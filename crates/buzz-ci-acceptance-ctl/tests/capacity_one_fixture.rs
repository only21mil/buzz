use std::{fs, path::PathBuf, process::Command};

use buzz_ci_acceptance_ctl::acceptance::{parse_scenario, Stage};
use sha2::{Digest, Sha256};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[test]
fn checked_in_scenario_and_fixture_bytes_match() {
    let root = repo_root();
    let acceptance = root.join("deploy/native-ci/acceptance");
    let scenario_bytes = fs::read(acceptance.join("scenario.template.json")).unwrap();
    let scenario = parse_scenario(&scenario_bytes).unwrap();
    let manifest = fs::read(acceptance.join("fixtures/fixture-manifest.json")).unwrap();
    assert_eq!(sha256(&manifest), scenario.fixture.manifest_digest);

    for schema in ["scenario.schema.json", "receipt.schema.json"] {
        let bytes = fs::read(acceptance.join(schema)).unwrap();
        let _: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    }
    let receipt_schema: serde_json::Value =
        serde_json::from_slice(&fs::read(acceptance.join("receipt.schema.json")).unwrap()).unwrap();
    let schema_stages = receipt_schema["$defs"]["stage"]["enum"].as_array().unwrap();
    let rust_stages = [
        Stage::CapacityZeroClosed,
        Stage::CapacityOneOpen,
        Stage::ManifestIdentity,
        Stage::ApprovalGrant,
        Stage::GrantResume,
        Stage::FirstAttemptTerminal,
        Stage::AuthenticatedExport,
        Stage::RerunSeparation,
        Stage::CancellationTerminal,
        Stage::TombstoneFolding,
        Stage::ControllerRestartRecovery,
        Stage::RunnerRestartRecovery,
        Stage::ReturnCapacityZero,
    ]
    .map(|stage| serde_json::to_value(stage).unwrap());
    assert_eq!(schema_stages.as_slice(), rust_stages.as_slice());
    let expected_stages: serde_json::Value =
        serde_json::from_slice(&fs::read(acceptance.join("expected-stages.json")).unwrap())
            .unwrap();
    assert_eq!(expected_stages.as_array().unwrap(), schema_stages);
    let prefix_items = receipt_schema["properties"]["checks"]["prefixItems"]
        .as_array()
        .unwrap();
    assert_eq!(prefix_items.len(), 13);
    for (index, (item, stage)) in prefix_items.iter().zip(schema_stages).enumerate() {
        let definition = item["$ref"]
            .as_str()
            .unwrap()
            .trim_start_matches("#/$defs/");
        let check = &receipt_schema["$defs"][definition]["allOf"][1]["properties"];
        assert_eq!(check["sequence"]["const"], index + 1);
        assert_eq!(&check["stage"]["const"], stage);
    }

    let output_dir = root
        .join("target")
        .join(format!("capacity-one-fixture-test-{}", std::process::id()));
    if output_dir.exists() {
        fs::remove_dir_all(&output_dir).unwrap();
    }
    fs::create_dir_all(&output_dir).unwrap();
    let output = Command::new(acceptance.join("fixtures/run-fixture.sh"))
        .arg(&output_dir)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.len() as u64,
        scenario.fixture.expected_log.bytes
    );
    assert_eq!(sha256(&output.stdout), scenario.fixture.expected_log.sha256);

    let artifact = fs::read(output_dir.join("result.json")).unwrap();
    let expected = &scenario.fixture.expected_artifacts[0];
    assert_eq!(artifact.len() as u64, expected.bytes);
    assert_eq!(sha256(&artifact), expected.sha256);
    fs::remove_dir_all(output_dir).unwrap();
}
