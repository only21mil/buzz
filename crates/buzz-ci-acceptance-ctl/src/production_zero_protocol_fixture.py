"""Local filesystem and FakeSystemd boundary for the Rust production driver test."""
from pathlib import Path
import json
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "deploy/native-ci/tests/support"))
from activation_scaffold import ActivationFixture, CONTROLLER


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


with tempfile.TemporaryDirectory() as temporary:
    fixture = ActivationFixture(Path(temporary))
    manifest, payloads, driver = fixture.load()
    CONTROLLER.stage(manifest, payloads, fixture.root, driver, fixture.binding)
    CONTROLLER.activate(manifest, payloads, fixture.root, driver)
    binding = fixture.binding
    base = {
        "schema_version": CONTROLLER.CAPACITY_ONE_REQUEST_SCHEMA,
        "action": CONTROLLER.CAPACITY_ONE_WIRE_ACTION,
        "activation_id": binding["activation_id"],
        "activation_package_digest": binding["activation_package_digest"],
        "scenario_sha256": binding["scenario_sha256"],
        "initial_controller_generation": binding["fixture"]["controller_generation"],
        "initial_runner_generation": binding["fixture"]["runner_generation"],
        "operation_id": "b" * 64,
    }
    request, digest = CONTROLLER._parse_capacity_one_request(
        CONTROLLER._wire_json(base), CONTROLLER._read_receipt(fixture.root),
    )
    CONTROLLER._set_capacity_one(manifest, payloads, fixture.root, driver, request, digest)
    if sys.argv[1] == "prepared":
        base.update(schema_version=CONTROLLER.ZERO_REQUEST_SCHEMA,
                    action="prepare_qualification_zero", operation_id="c" * 64)
        request, digest = CONTROLLER._parse_zero_request(
            CONTROLLER._wire_json(base), "prepare-qualification-zero", CONTROLLER._read_receipt(fixture.root),
        )
        CONTROLLER._prepare_qualification_zero(manifest, payloads, fixture.root, driver, request, digest)
    initial = CONTROLLER._read_receipt(fixture.root)["qualification_zero"]
    emit({"scenario": fixture.scenario, "scenario_sha256": binding["scenario_sha256"], "initial": initial})
    for line in sys.stdin:
        envelope = json.loads(line)
        raw = envelope["wire"].encode()
        try:
            request, digest = CONTROLLER._parse_zero_request(
                raw, envelope["action"], CONTROLLER._read_receipt(fixture.root),
            )
            if envelope["action"] == "finalize-qualification-zero":
                # Match the production host's capacity close before invoking
                # the controller. Controld stays available for prepare.
                for unit in envelope["close_units"]:
                    driver.stop(unit)
                response = CONTROLLER._finalize_qualification_zero(
                    manifest, payloads, fixture.root, driver, request, digest,
                )
            else:
                assert envelope["action"] == "prove-qualification-zero"
                response = CONTROLLER._prove_qualification_zero(manifest, fixture.root, driver, request)
            readback = CONTROLLER._finalized_zero_readback(manifest, fixture.root, driver)
            state = CONTROLLER._read_receipt(fixture.root)["qualification_zero"]
            assert state["phase"] == "finalized"
            assert readback["controld_acceptance_path"] == "absent"
            if initial is not None:
                assert state["prepare"] == initial["prepare"]
            proof = {
                "schema_version": "buzz-ci-capacity-one-zero-proof/v1",
                "scenario_sha256": binding["scenario_sha256"],
                "activation_id": binding["activation_id"],
                "activation_package_digest": binding["activation_package_digest"],
                "integrated_candidate_sha": binding["fixture"]["integrated_candidate_sha"],
                "capacity": 0,
                "admission": "closed",
                "controller_generation": binding["fixture"]["controller_generation"],
                "runner_generation": binding["fixture"]["runner_generation"],
                "controld_service_active": readback["units"]["buzz-ci-controld.service"]["ActiveState"] == "active",
                "controld_acceptance_socket_active": readback["units"]["buzz-ci-controld-acceptance.socket"]["ActiveState"] == "active",
                "controld_acceptance_socket_present": fixture.root.joinpath("run/buzzci/controld-acceptance.sock").exists(),
            }
            emit({"response": response, "proof": proof, "state": state})
        except ValueError as error:
            emit({"error": str(error)})
