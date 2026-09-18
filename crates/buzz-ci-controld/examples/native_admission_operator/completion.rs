//! Explicit receipt import. Root collects immutable evidence; UID 1201 signs
//! through the existing keyholder. This module never executes candidate code.
use super::*;
use buzz_ci_controld::production::{
    AcceptedRequestBinding, ArtifactCompletion, AttemptCompletion, AttemptExecutor, CiSigner,
    ControlStore, EvidenceReader, JobCompletion, JobMetadata, OutputDescriptor, ProductionHandler,
    RelayControl, StoredPublication,
};
use buzz_ci_controld::runner_v2::AdmissionSigner;
use buzz_ci_controld::source::{AuthenticatedRelay, ReqwestTransport};
use buzz_ci_controld::store::DurableControlStore;
use buzz_core::ci::{
    CiJobState, CiSkipPolicy, CiTeardownAttestationEnvelope, CiTeardownLease, CI_SCHEMA_VERSION,
};
use nostr::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema_version: u32,
    relay_base_url: String,
    /// Exact immutable installed profile, independently compared by root.
    profile_sha256: String,
    /// Root's receipt. Mac uses the exact SSH broker receipt; Linux uses supervisor.json.
    receipt_sha256: String,
    result_sha256: String,
    registration_sha256: String,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("native completion evidence mismatch".into())
    }
}

fn number(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .ok_or_else(|| "missing measured integer".into())
}

fn text_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .ok_or_else(|| "missing measured string".into())
}

fn protected_read(path: &Path, limit: usize, protected: bool) -> Result<Vec<u8>> {
    if protected {
        require(path.is_absolute() && fs::canonicalize(path)? == path)?;
        let m = fs::symlink_metadata(path)?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o777 == 0o444
                && m.nlink() == 1,
        )?;
        for parent in path.ancestors().skip(1) {
            let m = fs::symlink_metadata(parent)?;
            require(m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)?;
        }
    }
    let file = fs::File::open(path)?;
    require(file.metadata()?.is_file())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    require(bytes.len() <= limit)?;
    Ok(bytes)
}

struct ExistingSignature([u8; 64]);
impl AdmissionSigner for ExistingSignature {
    type Error = ();
    fn sign_admission(
        &mut self,
        value: &mut v2::AdmitAttemptRequest,
    ) -> std::result::Result<(), ()> {
        value.admission_signature = self.0;
        Ok(())
    }
}

fn verified_registration(
    authority: &Authority,
    accepted: &AcceptedRequest,
    frame: &[u8],
) -> Result<Value> {
    let (_, v2::Request::RegisterJobIntent(registration)) =
        v2::decode_request(frame).map_err(|_| "invalid registration")?
    else {
        return Err("job registration required".into());
    };
    let bindings = authority.bindings()?;
    let admission = prepare_signed_admission(
        accepted,
        &bindings,
        &mut ExistingSignature(registration.admission.admission_signature),
    )?;
    let (header, expected) = prepare_job_intent_registration(admission, accepted, &bindings)?;
    require(
        frame
            == v2::encode_request(header.request_id, v2::Request::RegisterJobIntent(expected))
                .as_bytes(),
    )?;
    let message: [u8; 32] = Sha256::digest(v2::admission_signature_message(&admission)).into();
    Secp256k1::verification_only().verify_schnorr(
        &Signature::from_slice(&admission.admission_signature)?,
        &Message::from_digest(message),
        &XOnlyPublicKey::from_slice(&hash(
            &authority.keyholder.keyholder_selectors.manifest.public_key,
        )?)?,
    )?;
    let policy = authority.policy()?;
    let mut expected = json!({
        "schema_version":2, "admission_message_digest":hex::encode(message),
        "workflow_id":authority.workflow_id,"job_id":authority.job_id,"artifacts":policy["artifacts"],
        "signed_request_digest":accepted.event_id,"source_pin_event_id":authority.source_pin_event_id,
        "candidate_sha":authority.candidate_oid,"base_sha":authority.trusted_base_oid,
        "workflow_digest":authority.workflow_digest,"workflow_file_sha256":authority.workflow_digest,
        "workflow_path":policy["workflow_path"],"job_intent_digest":hex::encode(admission.job_intent_digest),
        "isolation_profile_digest":authority.lane.isolation_profile_digest,
        "lane_manifest_digest":hex::encode(admission.lane_manifest_digest),"lane_epoch":authority.lane.lane_epoch,
        "run_id":hex::encode(admission.run_id),"attempt":admission.attempt,
        "expires_at":admission.expires_at,"wall_timeout_seconds":admission.wall_timeout_seconds
    });
    if let Some(driver) = &authority.driver_file_sha256 {
        expected["driver_file_sha256"] = json!(driver);
    }
    Ok(expected)
}

#[derive(Clone)]
struct RetainedEvidence(BTreeMap<String, Vec<u8>>);
impl EvidenceReader for RetainedEvidence {
    type Error = ();
    fn read(&self, descriptor: &OutputDescriptor) -> std::result::Result<Vec<u8>, ()> {
        self.0.get(&descriptor.relative_path).cloned().ok_or(())
    }
}
impl RetainedEvidence {
    fn add(&mut self, name: &str, bytes: Vec<u8>) -> OutputDescriptor {
        let descriptor = OutputDescriptor {
            relative_path: name.into(),
            sha256: digest(&bytes),
            byte_length: bytes.len() as u64,
        };
        self.0.insert(name.into(), bytes);
        descriptor
    }
}

struct CompletedAttempt {
    request: AcceptedRequestBinding,
    completion: AttemptCompletion,
}
impl AttemptExecutor for CompletedAttempt {
    type Error = ();
    fn execute(
        &mut self,
        accepted: &AcceptedRequest,
    ) -> std::result::Result<AttemptCompletion, ()> {
        if accepted.channel_id != self.request.channel_id
            || accepted.event_id != self.request.event_id
            || accepted.envelope != self.request.envelope
        {
            return Err(());
        }
        Ok(self.completion.clone())
    }
}

fn prepare(
    authority: &Authority,
    accepted: &AcceptedRequest,
    bundle: &Bundle,
    directory: &Path,
    protected: bool,
) -> Result<(AttemptCompletion, RetainedEvidence)> {
    require(bundle.schema_version == 1)?;
    hash(&bundle.profile_sha256)?;
    let frame = protected_read(&directory.join("registration.bin"), 992, protected)?;
    require(digest(&frame) == bundle.registration_sha256)?;
    let expected = verified_registration(authority, accepted, &frame)?;
    let raw = protected_read(&directory.join("receipt.json"), 65536, protected)?;
    require(digest(&raw) == bundle.receipt_sha256)?;
    let proof: Value = serde_json::from_slice(&raw)?;
    let result_bytes = protected_read(&directory.join("result.json"), 32768, protected)?;
    require(digest(&result_bytes) == bundle.result_sha256)?;
    let result: Value = serde_json::from_slice(&result_bytes)?;
    let mut evidence = RetainedEvidence(BTreeMap::new());
    let (started, finished, conclusion, code, log_bytes, cap, truncated, lease) = if authority
        .workflow_id
        == "CI"
    {
        require(
            proof["schema_version"] == "buzz-ci-native-linux-supervisor/v2"
                && proof["native_result"] == result,
        )?;
        require(
            result["schema_version"] == "buzz-ci-native-linux-receipt/v1"
                && result["admission"] == expected
                && result["job_id"] == authority.job_id
                && result["profile_sha256"] == bundle.profile_sha256,
        )?;
        require(proof["registration_sha256"] == bundle.registration_sha256)?;
        for name in [
            "container_absent",
            "recursive_cgroup_empty",
            "unit_inactive",
            "slice_inactive",
        ] {
            require(proof[name] == true)?;
        }
        for name in ["cleanup_proven", "source_cleanup_proven"] {
            require(result[name] == true)?;
        }
        let invocation = digest(&serde_json::to_vec(
            &json!({"admission_message_digest": expected["admission_message_digest"], "profile_sha256":bundle.profile_sha256}),
        )?);
        require(
            result["invocation_digest"] == invocation
                && proof["unit"] == format!("buzz-ci-linux-{invocation}.service"),
        )?;
        let slice_name = format!("buzzcilinux{invocation}.slice");
        let slice_invocation_id = text_field(&proof, "slice_invocation_id")?;
        require(
            proof["slice"] == slice_name
                && proof["cgroup_path"] == format!("/sys/fs/cgroup/{slice_name}")
                && proof["cgroup_observation"] == "retained-slice-populated-zero"
                && slice_invocation_id.len() == 32
                && slice_invocation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
        )?;
        let invocation_id = text_field(&proof, "invocation_id")?;
        require(
            invocation_id.len() == 32
                && invocation_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        require(number(&proof, "exec_main_code")? == 1)?;
        require(
            result["materialization"]["candidate_sha"] == authority.candidate_oid
                && result["materialization"]["base_sha"] == authority.trusted_base_oid
                && result["materialization"]["workflow_file_sha256"] == authority.workflow_digest,
        )?;
        hash(text_field(&result["materialization"], "checkout_sha256")?)?;
        let tree = text_field(&result["materialization"], "tree_sha")?;
        require(
            tree.len() == 40
                && tree
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        let execution = &result["workflow_execution"];
        require(
            execution["schema_version"] == "buzz-ci-native-shell-projection/v1"
                && execution["job_id"] == authority.job_id
                && execution["trusted_base_sha"] == authority.trusted_base_oid
                && execution["workflow_file_sha256"] == authority.workflow_digest
                && execution["executed_step_indices"] == json!([1])
                && execution["native_step_indices"] == json!([0, 2, 3]),
        )?;
        hash(text_field(execution, "script_sha256")?)?;
        let container = &result["container"];
        require(
            container["cleanup_proven"] == true
                && container["container_name"] == format!("buzzci-{invocation}"),
        )?;
        let conclusion = text_field(&result, "conclusion")?;
        require(
            number(&proof, "exec_main_status")? == if conclusion == "success" { 0 } else { 1 },
        )?;
        let reason = match conclusion {
            "success" => "success",
            "failure" => "job_failed",
            "cancelled" => "cancelled",
            "timed_out" => "deadline",
            _ => return Err("unsupported native outcome".into()),
        };
        require(container["reason"] == reason)?;
        let mut combined = Vec::new();
        let mut truncated = false;
        for channel in ["stdout", "stderr"] {
            let bytes =
                protected_read(&directory.join(format!("{channel}.log")), 32768, protected)?;
            require(
                container[format!("{channel}_sha256")] == digest(&bytes)
                    && container[format!("{channel}_relative_path")] == format!("{channel}.log"),
            )?;
            let observed = number(container, &format!("{channel}_bytes"))?;
            require(
                bytes.len() as u64 == observed.min(32768)
                    && container[format!("{channel}_truncated")] == (observed > bytes.len() as u64),
            )?;
            truncated |= observed > bytes.len() as u64;
            combined.extend_from_slice(
                format!("=== {channel}, retained bytes; channels are not time-merged ===\n")
                    .as_bytes(),
            );
            combined.extend_from_slice(&bytes);
            combined.push(b'\n');
        }
        let started = number(&result, "started_at")?;
        let finished = number(&proof, "finished_at")?;
        require(
            number(&result, "finished_at")? >= started
                && number(&result, "finished_at")? <= finished,
        )?;
        let lease = format!(
            "native-linux:{invocation}:{invocation_id}:{}:{}",
            number(&proof, "cgroup_device")?,
            number(&proof, "cgroup_inode")?
        );
        (
            started,
            finished,
            conclusion.to_owned(),
            container["exit_code"].as_i64(),
            combined,
            66048,
            truncated,
            lease,
        )
    } else {
        require(bundle.profile_sha256 == authority.lane.host_profile_digest)?;
        require(proof == result)?;
        for (name, value) in expected.as_object().ok_or("expected admission record")? {
            require(&result[name] == value)?;
        }
        require(result["cleanup_complete"] == true)?;
        let log = protected_read(&directory.join("job.log"), 1024 * 1024, protected)?;
        let meta = &result["log"];
        require(
            meta["sha256"] == digest(&log)
                && number(meta, "byte_length")? == log.len() as u64
                && number(meta, "cap_bytes")? == 1024 * 1024,
        )?;
        let observed = number(meta, "observed_bytes")?;
        require(
            log.len() as u64 == observed.min(1024 * 1024)
                && meta["truncated"] == (observed > log.len() as u64),
        )?;
        let lease = format!(
            "native-macos:uid590:{}",
            text_field(&expected, "admission_message_digest")?
        );
        (
            number(&result, "started_at")?,
            number(&result, "completed_at")?,
            text_field(&result, "conclusion")?.to_owned(),
            result["exit_code"].as_i64(),
            log,
            1024 * 1024,
            observed > number(meta, "byte_length")?,
            lease,
        )
    };
    require(
        started >= accepted.envelope.issued_at
            && started < accepted.envelope.expires_at
            && finished >= started
            && finished <= SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    // The current CI protocol refuses truncated logs as durable evidence.
    require(!truncated)?;
    let state = match conclusion.as_str() {
        "success" => {
            require(code == Some(0))?;
            CiJobState::Success
        }
        "failure" => {
            require(code.is_some_and(|code| code != 0))?;
            CiJobState::Failure
        }
        "cancelled" => CiJobState::Cancelled,
        "timed_out" => CiJobState::TimedOut,
        _ => return Err("unproven cleanup or terminal outcome".into()),
    };
    let job = JobCompletion {
        metadata: JobMetadata {
            job_id: authority.job_id.clone(),
            name: authority.job_id.clone(),
            required: true,
            skip_policy: CiSkipPolicy::Forbid,
            selected_job_instance: authority.job_id.clone(),
            also_reruns: vec![],
        },
        attempt: accepted.envelope.attempt,
        state,
        reason: None,
        started_at: started,
        finished_at: finished,
        log: evidence.add("job.log", log_bytes),
        log_cap_bytes: cap,
        artifacts: vec![ArtifactCompletion {
            descriptor: evidence.add("result.json", result_bytes),
            artifact_id: "result".into(),
            name: "result.json".into(),
            media_type: "application/json".into(),
        }],
    };
    let request = &accepted.envelope;
    let teardown = CiTeardownAttestationEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_event_id: accepted.event_id.clone(),
        run_id: request.run_id.clone(),
        workflow_id: request.workflow_id.clone(),
        target_repo_a: request.target_repo_a.clone(),
        tip_oid: request.tip_oid.clone(),
        base_oid: request.base_oid.clone(),
        workflow_digest: request.workflow_digest.clone(),
        attempt: request.attempt,
        leases: vec![CiTeardownLease {
            job_id: authority.job_id.clone(),
            attempt: request.attempt,
            lease_id: lease,
        }],
        lease_empty: true,
        teardown_at: finished,
        relay_signer: authority
            .keyholder
            .keyholder_selectors
            .ci_event
            .public_key
            .clone(),
    };
    teardown.validate()?;
    Ok((
        AttemptCompletion {
            jobs: vec![job],
            teardown,
            finished_at: finished,
        },
        evidence,
    ))
}

struct UnavailableAttempt;
impl AttemptExecutor for UnavailableAttempt {
    type Error = ();
    fn execute(&mut self, _: &AcceptedRequest) -> std::result::Result<AttemptCompletion, ()> {
        Err(())
    }
}

type NativeRelay = AuthenticatedRelay<ReqwestTransport, UnixKeyholderClient>;

fn connect_relay(authority: &Authority, url: &str) -> Result<NativeRelay> {
    let transport = ReqwestTransport::new(
        Duration::from_secs(10),
        Duration::from_secs(60),
        4 * 1024 * 1024,
    )?;
    Ok(AuthenticatedRelay::new(
        url.parse()?,
        transport,
        UnixKeyholderClient::connect_native(authority.keyholder.clone())?,
    )?)
}

fn find_request(relay: &mut NativeRelay, expected: &AcceptedRequest) -> Result<AcceptedRequest> {
    let mut cursor = 0;
    for _ in 0..10000 {
        let Some(next) = relay.next_accepted(&expected.channel_id, cursor)? else {
            break;
        };
        cursor = next.watch_cursor;
        if next.event_id == expected.event_id {
            require(next.envelope == expected.envelope)?;
            return Ok(next);
        }
    }
    Err("request absent from authenticated accepted intake".into())
}

fn operator_store(accepted: &AcceptedRequest) -> Result<DurableControlStore> {
    let store_path = PathBuf::from(format!(
        "/var/lib/buzzci/native-publication/{}",
        accepted.event_id
    ));
    let mut store = DurableControlStore::open(store_path, 1201)?;
    let prior = store.cursor(&accepted.channel_id)?;
    if prior == 0 && accepted.watch_cursor > 1 {
        require(store.advance_cursor(&accepted.channel_id, 0, accepted.watch_cursor - 1)?)?;
    }
    require(store.cursor(&accepted.channel_id)? <= accepted.watch_cursor)?;
    Ok(store)
}

fn begin(args: &[String]) -> Result<()> {
    require(
        args.len() == 7
            && nix::unistd::geteuid().as_raw() == 1201
            && nix::unistd::getegid().as_raw() == 1201,
    )?;
    let authority = load_authority(Path::new(&args[2]), &args[3], true)?;
    let event: Event =
        serde_json::from_slice(&protected_read(Path::new(&args[4]), 1024 * 1024, true)?)?;
    let source: Event =
        serde_json::from_slice(&protected_read(Path::new(&args[5]), 1024 * 1024, true)?)?;
    let accepted = validate_inputs(
        &authority,
        &event,
        &source,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let mut relay = connect_relay(&authority, &args[6])?;
    let accepted = find_request(&mut relay, &accepted)?;
    let store = operator_store(&accepted)?;
    let binding = AcceptedRequestBinding {
        channel_id: accepted.channel_id.clone(),
        event_id: accepted.event_id.clone(),
        envelope: accepted.envelope.clone(),
    };
    let mut handler = ProductionHandler::new(
        relay,
        UnixKeyholderClient::connect_native(authority.keyholder.clone())?,
        UnavailableAttempt,
        store.clone(),
        RetainedEvidence(BTreeMap::new()),
    );
    let event_id = handler.acknowledge_once_bound(&binding)?;
    let Some(StoredPublication::Accepted { signed, .. }) =
        store.load_publication(&format!("{}:run:queued", accepted.event_id))?
    else {
        return Err("queued acknowledgement not accepted".into());
    };
    require(connect_relay(&authority, &args[6])?.publication_exists(&signed)?)?;
    println!(
        "{}",
        json!({"request_event_id":accepted.event_id,"queued_event_id":event_id,"execution_started":false})
    );
    Ok(())
}

fn select_fresh_request(
    authority: &Authority,
    source: &Event,
    event: Event,
    started: u64,
    now: u64,
    selected: &mut Option<Event>,
) -> Result<()> {
    if event.created_at.as_secs() >= started
        && validate_inputs(authority, &event, source, now).is_ok()
    {
        require(selected.is_none())?;
        *selected = Some(event);
    }
    Ok(())
}

fn await_request(args: &[String]) -> Result<()> {
    require(
        args.len() == 7
            && nix::unistd::geteuid().as_raw() == 1201
            && nix::unistd::getegid().as_raw() == 1201,
    )?;
    let authority = load_authority(Path::new(&args[2]), &args[3], true)?;
    let source: Event =
        serde_json::from_slice(&protected_read(Path::new(&args[4]), 1024 * 1024, true)?)?;
    source.verify()?;
    require(source.id.to_hex() == authority.source_pin_event_id)?;
    let seconds: u64 = args[6].parse()?;
    require((1..=60).contains(&seconds))?;
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    eprintln!("native request capture ready; waiting for one fresh accepted request");
    let mut cursor = 0;
    let mut selected: Option<Event> = None;
    for _ in 0..10000 {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or("request capture timed out")?;
        let transport = ReqwestTransport::new(
            (remaining / 3).min(Duration::from_secs(3)),
            remaining / 3,
            4 * 1024 * 1024,
        )?;
        let mut keyholder = authority.keyholder.clone();
        keyholder.keyholder_timeout_millis = keyholder
            .keyholder_timeout_millis
            .min(u64::try_from((remaining / 3).as_millis())?);
        let mut relay = AuthenticatedRelay::new(
            args[5].parse()?,
            transport,
            UnixKeyholderClient::connect_native(keyholder)?,
        )?;
        let next = relay.next_accepted_event(&authority.channel_id, cursor)?;
        require(std::time::Instant::now() < deadline)?;
        match next {
            Some((next_cursor, event)) => {
                cursor = next_cursor;
                select_fresh_request(
                    &authority,
                    &source,
                    event,
                    started,
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    &mut selected,
                )?;
            }
            None => {
                if let Some(event) = selected {
                    println!("{}", serde_json::to_string(&event)?);
                    return Ok(());
                }
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or("request capture timed out")?;
                std::thread::sleep(remaining.min(Duration::from_millis(100)));
            }
        }
    }
    Err("accepted intake exceeded capture bound".into())
}

// Derive read authority from the same descriptors publication uses. No caller
// supplied URL or digest bypasses prepare's complete receipt verification.
fn evidence_read_plan(
    authority: &Authority,
    accepted: &AcceptedRequest,
    completion: &AttemptCompletion,
    bundle: &Bundle,
    authority_sha256: &str,
    bundle_sha256: &str,
    now: u64,
) -> Result<Value> {
    let [job] = completion.jobs.as_slice() else {
        return Err("one completed job required".into());
    };
    let policy = buzz_ci_keyholder::NativeEvidencePolicy {
        not_before: now,
        expires_at: now.checked_add(300).ok_or("read window overflow")?,
        request_event_id: accepted.event_id.clone(),
        run_id: accepted.envelope.run_id.clone(),
        job_id: job.metadata.job_id.clone(),
        attempt: job.attempt,
        authority_sha256: authority_sha256.into(),
        bundle_sha256: bundle_sha256.into(),
        log_sha256: job.log.sha256.clone(),
        artifacts: job
            .artifacts
            .iter()
            .map(|a| buzz_ci_keyholder::NativeEvidenceArtifact {
                artifact_id: a.artifact_id.clone(),
                sha256: a.descriptor.sha256.clone(),
            })
            .collect(),
    };
    policy.validate()?;
    Ok(
        json!({"schema_version":1,"validated":true,"request_event_id":accepted.event_id,
        "state":job.state,"relay_origin":bundle.relay_base_url,
        "keyholder_selectors":authority.keyholder.keyholder_selectors,
        "native_evidence":policy}),
    )
}

pub(super) fn run(args: &[String]) -> Result<()> {
    if args[1] == "await-request" {
        return await_request(args);
    }
    if args[1] == "begin" {
        return begin(args);
    }
    require(args.len() == 8)?;
    let publishing = args[1] == "publish";
    let protected = publishing || nix::unistd::geteuid().as_raw() == 0;
    let authority = load_authority(Path::new(&args[2]), &args[3], protected)?;
    let event: Event = serde_json::from_slice(&protected_read(
        Path::new(&args[4]),
        1024 * 1024,
        protected,
    )?)?;
    let source: Event = serde_json::from_slice(&protected_read(
        Path::new(&args[5]),
        1024 * 1024,
        protected,
    )?)?;
    // Retained completion may be published after admission expiry. Verify the
    // request at its own issue time, then require measured execution in-window.
    let accepted = validate_inputs(&authority, &event, &source, event.created_at.as_secs())?;
    let bundle_path = Path::new(&args[6]);
    let bundle_bytes = protected_read(bundle_path, 16384, protected)?;
    require(digest(&bundle_bytes) == args[7])?;
    let bundle: Bundle = serde_json::from_slice(&bundle_bytes)?;
    let (completion, evidence) = prepare(
        &authority,
        &accepted,
        &bundle,
        bundle_path.parent().ok_or("bundle directory")?,
        protected,
    )?;
    if !publishing {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let plan = evidence_read_plan(
            &authority,
            &accepted,
            &completion,
            &bundle,
            &args[3],
            &args[7],
            now,
        )?;
        println!("{}", plan);
        return Ok(());
    }
    require(nix::unistd::geteuid().as_raw() == 1201 && nix::unistd::getegid().as_raw() == 1201)?;
    let mut relay = connect_relay(&authority, &bundle.relay_base_url)?;
    // Authenticated acceptance, not a caller-supplied watch cursor. Scan only;
    // this per-request operator store never advances the daemon's cursor.
    let stored_request = find_request(&mut relay, &accepted)?;
    let binding = AcceptedRequestBinding {
        channel_id: accepted.channel_id.clone(),
        event_id: accepted.event_id.clone(),
        envelope: accepted.envelope.clone(),
    };
    let store = operator_store(&stored_request)?;
    require(matches!(
        store.load_publication(&format!("{}:run:queued", accepted.event_id))?,
        Some(StoredPublication::Accepted { .. })
    ))?;
    let signer = UnixKeyholderClient::connect_native(authority.keyholder.clone())?;
    let signer_key = signer.pubkey().to_owned();
    let mut handler = ProductionHandler::new(
        relay,
        signer,
        CompletedAttempt {
            request: binding.clone(),
            completion,
        },
        store.clone(),
        evidence,
    );
    if store.cursor(&authority.channel_id)? < stored_request.watch_cursor {
        handler.poll_once_bound(&authority.channel_id, &binding)?;
    }
    // Every terminal outcome needs exact signed check readback. A successful
    // outcome additionally uses the existing authenticated full evidence export.
    let Some(StoredPublication::Accepted { signed, .. }) =
        store.load_publication(&format!("{}:run:check", accepted.event_id))?
    else {
        return Err("terminal check not accepted".into());
    };
    let mut readback = connect_relay(&authority, &bundle.relay_base_url)?;
    require(readback.publication_exists(&signed)?)?;
    let content: Value = serde_json::from_str(&signed.content)?;
    let export = if content["conclusion"] == "success" {
        Some(handler.export_first_evidence(
            &binding,
            &authority.job_id,
            accepted.envelope.attempt,
        )?)
    } else {
        None
    };
    println!(
        "{}",
        json!({"request_event_id":accepted.event_id,"check_event_id":signed.event_id,"signer":signer_key,"terminal_check":content,"authenticated_evidence":export.map(|value| json!({"authorization_digest":value.authorization_digest,"objects":value.objects.iter().map(|object| json!({"name":object.name,"sha256":object.sha256,"byte_length":object.bytes.len()})).collect::<Vec<_>>()}))})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::secp256k1::{Keypair, SecretKey};

    #[test]
    fn read_plan_uses_exact_completion_descriptors_for_both_native_profiles() {
        for mac in [false, true] {
            let f = fixture(mac);
            let (completion, evidence) = f.prepare().unwrap();
            let plan = evidence_read_plan(
                &f.authority,
                &f.accepted,
                &completion,
                &f.bundle,
                &"11".repeat(32),
                &"22".repeat(32),
                500,
            )
            .unwrap();
            let policy: buzz_ci_keyholder::NativeEvidencePolicy =
                serde_json::from_value(plan["native_evidence"].clone()).unwrap();
            assert_eq!(policy.request_event_id, f.accepted.event_id);
            assert_eq!(policy.run_id, f.accepted.envelope.run_id);
            assert_eq!(policy.job_id, f.authority.job_id);
            assert_eq!(policy.attempt, f.accepted.envelope.attempt);
            assert_eq!(policy.not_before, 500);
            assert_eq!(policy.expires_at, 800);
            assert_eq!(policy.log_sha256, digest(&evidence.0["job.log"]));
            assert_eq!(
                policy.artifacts[0].sha256,
                digest(&evidence.0["result.json"])
            );
            assert_eq!(policy.paths().len(), 2);
            assert!(policy
                .paths()
                .iter()
                .all(|p| p.contains(&f.accepted.event_id)));
        }
    }

    #[test]
    fn capture_excludes_old_or_other_requests_and_refuses_ambiguous_fresh_requests() {
        let (authority, keys, source, mut request) = super::super::tests::fixture();
        let event = super::super::tests::sign(&keys, &request);
        let mut selected = None;
        select_fresh_request(&authority, &source, event.clone(), 101, 101, &mut selected).unwrap();
        assert!(selected.is_none());
        select_fresh_request(&authority, &source, event.clone(), 100, 101, &mut selected).unwrap();
        assert_eq!(selected.as_ref().unwrap().id, event.id);
        request.run_id = "12345678-1234-4234-8234-123456789abe".into();
        assert!(select_fresh_request(
            &authority,
            &source,
            super::super::tests::sign(&keys, &request),
            100,
            101,
            &mut selected
        )
        .is_err());
        request.tip_oid = "99".repeat(20);
        let mut selected = None;
        select_fresh_request(
            &authority,
            &source,
            super::super::tests::sign(&keys, &request),
            100,
            101,
            &mut selected,
        )
        .unwrap();
        assert!(selected.is_none());
    }

    struct FixtureSigner;
    impl AdmissionSigner for FixtureSigner {
        type Error = ();
        fn sign_admission(
            &mut self,
            value: &mut v2::AdmitAttemptRequest,
        ) -> std::result::Result<(), ()> {
            let secp = Secp256k1::new();
            let pair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[4; 32]).unwrap());
            let digest: [u8; 32] = Sha256::digest(v2::admission_signature_message(value)).into();
            value.admission_signature = *secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &pair)
                .as_ref();
            Ok(())
        }
    }

    struct Fixture {
        authority: Authority,
        accepted: AcceptedRequest,
        bundle: Bundle,
        directory: tempfile::TempDir,
    }
    impl Fixture {
        fn write_result(&mut self, result: Value, mut proof: Value) {
            if self.authority.workflow_id == "CI" {
                proof["native_result"] = result.clone();
            } else {
                proof = result.clone();
            }
            let result = serde_json::to_vec(&result).unwrap();
            let proof = serde_json::to_vec(&proof).unwrap();
            self.bundle.result_sha256 = digest(&result);
            self.bundle.receipt_sha256 = digest(&proof);
            fs::write(self.directory.path().join("result.json"), result).unwrap();
            fs::write(self.directory.path().join("receipt.json"), proof).unwrap();
        }
        fn result(&self) -> Value {
            serde_json::from_slice(&fs::read(self.directory.path().join("result.json")).unwrap())
                .unwrap()
        }
        fn proof(&self) -> Value {
            serde_json::from_slice(&fs::read(self.directory.path().join("receipt.json")).unwrap())
                .unwrap()
        }
        fn prepare(&self) -> Result<(AttemptCompletion, RetainedEvidence)> {
            prepare(
                &self.authority,
                &self.accepted,
                &self.bundle,
                self.directory.path(),
                false,
            )
        }
    }

    fn fixture(mac: bool) -> Fixture {
        let (mut authority, keys, source, mut request) = super::super::tests::fixture();
        if mac {
            authority.workflow_id = "native-macos".into();
            authority.job_id = "desktop-build-macos-unsigned".into();
            authority.driver_file_sha256 = Some("55".repeat(32));
            authority.lane.max_wall_timeout_seconds = 2700;
            request.workflow_id = authority.workflow_id.clone();
            request.job_ids = vec![authority.job_id.clone()];
        }
        let event = super::super::tests::sign(&keys, &request);
        let accepted = validate_inputs(&authority, &event, &source, 101).unwrap();
        let bindings = authority.bindings().unwrap();
        let admission = prepare_signed_admission(&accepted, &bindings, &mut FixtureSigner).unwrap();
        let (header, registration) =
            prepare_job_intent_registration(admission, &accepted, &bindings).unwrap();
        let frame = v2::encode_request(
            header.request_id,
            v2::Request::RegisterJobIntent(registration),
        );
        let expected = verified_registration(&authority, &accepted, frame.as_bytes()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("registration.bin"), frame.as_bytes()).unwrap();
        let bundle = Bundle {
            schema_version: 1,
            relay_base_url: "https://relay.example".into(),
            profile_sha256: authority.lane.host_profile_digest.clone(),
            receipt_sha256: String::new(),
            result_sha256: String::new(),
            registration_sha256: digest(frame.as_bytes()),
        };
        let mut fixture = Fixture {
            authority,
            accepted,
            bundle,
            directory,
        };
        if mac {
            let mut result = expected;
            let fields = json!({"cleanup_complete":true,"started_at":101,"completed_at":103,"exit_code":0,"conclusion":"success","log":{"sha256":digest(b"build\n"),"byte_length":6,"cap_bytes":1048576,"observed_bytes":6,"truncated":false}});
            result
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            fs::write(fixture.directory.path().join("job.log"), b"build\n").unwrap();
            fixture.write_result(result, Value::Null);
        } else {
            let invocation = digest(&serde_json::to_vec(&json!({"admission_message_digest":expected["admission_message_digest"],"profile_sha256":fixture.bundle.profile_sha256})).unwrap());
            let result = json!({"schema_version":"buzz-ci-native-linux-receipt/v1","admission":expected,"profile_sha256":fixture.bundle.profile_sha256,"job_id":"dead-token-guard","invocation_digest":invocation,"cleanup_proven":true,"source_cleanup_proven":true,"conclusion":"success","started_at":101,"finished_at":103,
                "materialization":{"candidate_sha":fixture.authority.candidate_oid,"base_sha":fixture.authority.trusted_base_oid,"workflow_file_sha256":fixture.authority.workflow_digest,"tree_sha":"88".repeat(20),"checkout_sha256":"77".repeat(32)},
                "workflow_execution":{"schema_version":"buzz-ci-native-shell-projection/v1","job_id":"dead-token-guard","trusted_base_sha":fixture.authority.trusted_base_oid,"workflow_file_sha256":fixture.authority.workflow_digest,"script_sha256":"66".repeat(32),"executed_step_indices":[1],"native_step_indices":[0,2,3]},
                "container":{"exit_code":0,"reason":"success","container_name":format!("buzzci-{invocation}"),"cleanup_proven":true,"stdout_sha256":digest(b"pass\n"),"stderr_sha256":digest(b""),"stdout_relative_path":"stdout.log","stderr_relative_path":"stderr.log","stdout_bytes":5,"stderr_bytes":0,"stdout_truncated":false,"stderr_truncated":false}});
            let proof = json!({"schema_version":"buzz-ci-native-linux-supervisor/v2","registration_sha256":fixture.bundle.registration_sha256,"container_absent":true,"recursive_cgroup_empty":true,"unit_inactive":true,"slice_inactive":true,"slice":format!("buzzcilinux{invocation}.slice"),"slice_invocation_id":"bb".repeat(16),"cgroup_path":format!("/sys/fs/cgroup/buzzcilinux{invocation}.slice"),"cgroup_observation":"retained-slice-populated-zero","unit":format!("buzz-ci-linux-{invocation}.service"),"invocation_id":"aa".repeat(16),"exec_main_code":1,"exec_main_status":0,"cgroup_device":12,"cgroup_inode":34,"finished_at":104});
            fs::write(fixture.directory.path().join("stdout.log"), b"pass\n").unwrap();
            fs::write(fixture.directory.path().join("stderr.log"), b"").unwrap();
            fixture.write_result(result, proof);
        }
        fixture
    }

    #[test]
    fn both_profiles_bind_exact_bytes_and_measured_native_cleanup() {
        for mac in [false, true] {
            let fixture = fixture(mac);
            let (completion, evidence) = fixture.prepare().unwrap();
            assert_eq!(completion.jobs[0].state, CiJobState::Success);
            assert_eq!(completion.jobs[0].started_at, 101);
            assert!(completion.teardown.leases[0].lease_id.starts_with(if mac {
                "native-macos:"
            } else {
                "native-linux:"
            }));
            assert_eq!(
                evidence
                    .read(&completion.jobs[0].artifacts[0].descriptor)
                    .unwrap(),
                fs::read(fixture.directory.path().join("result.json")).unwrap()
            );
        }
    }

    #[test]
    fn refuses_missing_or_rebound_linux_slice_cleanup() {
        for field in [
            "slice",
            "slice_invocation_id",
            "cgroup_path",
            "cgroup_observation",
            "slice_inactive",
        ] {
            let mut fixture = fixture(false);
            let result = fixture.result();
            let mut proof = fixture.proof();
            proof[field] = Value::Null;
            fixture.write_result(result, proof);
            assert!(fixture.prepare().is_err());
        }
    }

    #[test]
    fn refuses_missing_logs_modified_registration_cleanup_and_rebound_source() {
        for mac in [false, true] {
            for mutation in 0..7 {
                let mut fixture = fixture(mac);
                let mut result = fixture.result();
                let mut proof = fixture.proof();
                match mutation {
                    0 => {
                        if mac {
                            result["cleanup_complete"] = json!(false);
                        } else {
                            proof["recursive_cgroup_empty"] = json!(false);
                        }
                    }
                    1 => {
                        if mac {
                            result["candidate_sha"] = json!("99".repeat(20));
                        } else {
                            result["admission"]["candidate_sha"] = json!("99".repeat(20));
                        }
                    }
                    2 => {
                        result["started_at"] = json!(99);
                    }
                    3 => {
                        result["exit_code"] = json!(1);
                        if !mac {
                            result["container"]["exit_code"] = json!(1);
                        }
                    }
                    4 => {
                        fs::remove_file(fixture.directory.path().join(if mac {
                            "job.log"
                        } else {
                            "stdout.log"
                        }))
                        .unwrap();
                    }
                    5 => {
                        let mut bytes =
                            fs::read(fixture.directory.path().join("registration.bin")).unwrap();
                        bytes[200] ^= 1;
                        fixture.bundle.registration_sha256 = digest(&bytes);
                        fs::write(fixture.directory.path().join("registration.bin"), bytes)
                            .unwrap();
                    }
                    _ => {
                        if mac {
                            result["log"]["truncated"] = json!(true);
                        } else {
                            result["container"]["stdout_truncated"] = json!(true);
                        }
                    }
                }
                fixture.write_result(result, proof);
                assert!(
                    fixture.prepare().is_err(),
                    "accepted {mac} mutation {mutation}"
                );
            }
        }
    }

    #[test]
    fn retained_completion_accepts_admission_expiry_but_not_execution_before_admission() {
        let fixture = fixture(false);
        assert!(fixture.prepare().is_ok());
        assert!(validate_inputs(
            &fixture.authority,
            &super::super::tests::sign(
                &nostr::Keys::parse(&"01".repeat(32)).unwrap(),
                &fixture.accepted.envelope
            ),
            &super::super::tests::fixture().2,
            500
        )
        .is_err());
    }
}
