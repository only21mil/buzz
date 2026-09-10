use buzz_ci_keyholder::*;
use std::cell::Cell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Backend {
    selectors: SelectorSet,
    calls: Rc<Cell<usize>>,
}
impl SigningBackend for Backend {
    fn public_key(&self, selector: KeySelector) -> Result<[u8; 32], BackendError> {
        Ok(self.selectors.identity(selector).public_key)
    }
    fn sign_digest(&self, _: KeySelector, _: [u8; 32]) -> Result<[u8; 64], BackendError> {
        self.calls.set(self.calls.get() + 1);
        Ok([1; 64])
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn config() -> serde_json::Value {
    let keys = [
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    ];
    serde_json::json!({"schema_version":2,"peer":{"uid":1201,"gid":1201,"allowed_operations":["describe","sign_ci_event","nip98_authorize","sign_manifest"]},"selectors":{"ci_event":{"public_key":keys[0],"generation":1},"nip98":{"public_key":keys[1],"generation":1},"manifest":{"public_key":keys[2],"generation":1}},"nip98_origin":"https://framework-desktop.tail69757d.ts.net:38443","native_evidence":{"not_before":now()-1,"expires_at":now()+300,"request_event_id":"b7e08814f989e2b12893a27b201de58a5f080d50af88d2f928fd6adfc16b49ef","run_id":"01a08d0d-3782-7ab1-b0df-bb009c72a43a","job_id":"dead-token-guard","attempt":1,"authority_sha256":"11".repeat(32),"bundle_sha256":"22".repeat(32),"log_sha256":"5ffafe15da0896cd39f687565523b03cccb3a1017879bf0cb02f6b72fd9b6838","artifacts":[{"artifact_id":"result","sha256":"d2231779d46639d9777c12bf1533ffafc1525e2a863d994028e6644568ffdbf6"}]}})
}

#[test]
fn standalone_native_config_accepts_explicit_evidence_policy() {
    let value = config();
    let parsed = KeyholderConfig::from_slice(&serde_json::to_vec(&value).unwrap())
        .expect("standalone native evidence policy must parse independently of acceptance");
    assert!(parsed.acceptance.is_none());
}

fn service(value: serde_json::Value) -> (ProductionKeyholder<Backend>, Rc<Cell<usize>>) {
    let config = KeyholderConfig::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
    let policy = match config.native_evidence {
        Some(evidence) => SigningPolicy::new_with_native_evidence(
            config.peer_policy,
            config.selectors,
            config.nip98_origin,
            evidence,
        ),
        None => SigningPolicy::new(config.peer_policy, config.selectors, config.nip98_origin),
    }
    .unwrap();
    let calls = Rc::new(Cell::new(0));
    let backend = Backend {
        selectors: config.selectors,
        calls: calls.clone(),
    };
    (ProductionKeyholder::new(policy, backend).unwrap(), calls)
}
fn request(path: &str) -> Nip98AuthorizeRequest {
    Nip98AuthorizeRequest {
        expected_generation: 1,
        signer: Nip98Signer::Nip98,
        method: HttpMethod::Get,
        url: Url::new(format!(
            "https://framework-desktop.tail69757d.ts.net:38443{path}"
        ))
        .unwrap(),
        payload_digest: None,
        created_at: now(),
        nonce: [5; 16],
        query_filter: None,
    }
}
fn peer() -> PeerIdentity {
    PeerIdentity {
        uid: 1201,
        gid: 1201,
    }
}

#[test]
fn native_exact_get_signs_and_unrelated_or_malformed_get_never_reaches_backend() {
    let value = config();
    let (service, calls) = service(value.clone());
    let policy: NativeEvidencePolicy =
        serde_json::from_value(value["native_evidence"].clone()).unwrap();
    for path in policy.paths() {
        assert!(matches!(
            service.handle(peer(), Request::Nip98Authorize(request(&path))),
            Response::Nip98Authorize(_)
        ));
    }
    assert_eq!(calls.get(), 2);
    let path = policy
        .paths()
        .into_iter()
        .find(|p| p.starts_with("/ci/logs/"))
        .unwrap();
    for bad in [
        path.replace(&policy.request_event_id, &"99".repeat(32)),
        path.replace(&policy.run_id, "123e4567-e89b-12d3-a456-426614174000"),
        path.replace("dead-token-guard", "other-job"),
        path.replace("/1/", "/2/"),
        path.replace(&policy.log_sha256, &"99".repeat(32)),
        format!("{path}?query=1"),
        format!("{path}/"),
        path.replace("/logs/", "/logs//"),
        path.replace("dead-token", "dead%2dtoken"),
        format!("{path}#fragment"),
    ] {
        assert!(
            matches!(
                service.handle(peer(), Request::Nip98Authorize(request(&bad))),
                Response::Error { .. }
            ),
            "{bad}"
        );
    }
    let valid = request(&path);
    let mut malformed = vec![];
    let mut r = valid.clone();
    r.payload_digest = Some([7; 32]);
    malformed.push(r);
    let mut r = valid.clone();
    r.query_filter = Some(QueryFilter::new(b"[]".to_vec()).unwrap());
    malformed.push(r);
    let mut r = valid.clone();
    r.signer = Nip98Signer::CiEvent;
    malformed.push(r);
    let mut r = valid.clone();
    r.expected_generation = 2;
    malformed.push(r);
    let mut r = valid.clone();
    r.url = Url::new(
        valid
            .url
            .as_str()
            .replace("framework-desktop", "other-host"),
    )
    .unwrap();
    malformed.push(r);
    for r in malformed {
        assert!(matches!(
            service.handle(peer(), Request::Nip98Authorize(r)),
            Response::Error { .. }
        ));
    }
    let mut wrong_peer = peer();
    wrong_peer.uid = 1200;
    assert!(matches!(
        service.handle(wrong_peer, Request::Nip98Authorize(valid)),
        Response::Error { .. }
    ));
    assert_eq!(calls.get(), 2);
}

#[test]
fn default_expired_future_and_operation_denied_policies_do_not_sign() {
    let value = config();
    let policy: NativeEvidencePolicy =
        serde_json::from_value(value["native_evidence"].clone()).unwrap();
    let path = policy.paths().into_iter().next().unwrap();
    for case in 0..4 {
        let mut v = value.clone();
        match case {
            0 => {
                v.as_object_mut().unwrap().remove("native_evidence");
            }
            1 => {
                v["native_evidence"]["not_before"] = serde_json::json!(now() - 300);
                v["native_evidence"]["expires_at"] = serde_json::json!(now() - 1);
            }
            2 => {
                v["native_evidence"]["not_before"] = serde_json::json!(now() + 60);
                v["native_evidence"]["expires_at"] = serde_json::json!(now() + 300);
            }
            _ => v["peer"]["allowed_operations"] = serde_json::json!(["describe"]),
        }
        let (service, calls) = service(v);
        assert!(matches!(
            service.handle(peer(), Request::Nip98Authorize(request(&path))),
            Response::Error { .. }
        ));
        assert_eq!(calls.get(), 0);
    }
}
