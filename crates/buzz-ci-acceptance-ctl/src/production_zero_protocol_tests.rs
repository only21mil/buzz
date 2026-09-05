mod zero_protocol_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdin, ChildStdout, Stdio};

    struct ControllerTransport {
        child: Child,
        input: Option<ChildStdin>,
        output: BufReader<ChildStdout>,
        config: AcceptanceControlConfig,
        lose_finalize: bool,
        frames: Vec<Vec<u8>>,
        states: Vec<serde_json::Value>,
    }

    impl Drop for ControllerTransport {
        fn drop(&mut self) {
            drop(self.input.take());
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().unwrap().is_none() {
                if std::time::Instant::now() >= deadline {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl ControllerTransport {
        fn receive(&mut self) -> serde_json::Value {
            let mut line = String::new();
            assert!(self.output.read_line(&mut line).unwrap() > 0);
            serde_json::from_str(&line).unwrap()
        }
    }

    impl AdapterTransport for ControllerTransport {
        type Error = String;

        fn exchange(
            &mut self,
            endpoint: AdapterEndpoint,
            raw: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>, Self::Error> {
            assert_eq!(endpoint, AdapterEndpoint::Control);
            let request: ControlRequest = serde_json::from_slice(raw).unwrap();
            assert!(self.config.binds(&request));
            assert_eq!(
                control_operation_id(&request).unwrap(),
                request.operation_id
            );
            let action = match request.operation {
                ControlOperation::FinalizeCapacityZero => QualificationZeroAction::Finalize,
                ControlOperation::ProveCapacityZero => QualificationZeroAction::Prove,
                _ => panic!("unexpected production operation"),
            };
            // These are the same encoder and response validator used by
            // SystemdHostControl. Python parses the exact compact wire bytes.
            let mut wire = qualification_zero_input(&self.config, action, &request).unwrap();
            // process_input_writer terminates each controller request with LF.
            wire.push(b'\n');
            self.frames.push(wire.clone());
            let envelope = serde_json::json!({
                "action": action.argument(),
                "wire": String::from_utf8(wire).unwrap(),
                "close_units": CAPACITY_ONE_STOP_ORDER,
            });
            writeln!(self.input.as_mut().unwrap(), "{envelope}").unwrap();
            self.input.as_mut().unwrap().flush().unwrap();
            let result = self.receive();
            if let Some(error) = result["error"].as_str() {
                panic!("real controller rejected production wire: {error}");
            }
            let receipt = qualification_zero_response(
                action,
                &request,
                &serde_json::to_vec(&result["response"]).unwrap(),
            )
            .unwrap();
            let proof: ZeroProof = serde_json::from_value(result["proof"].clone()).unwrap();
            self.states.push(result["state"].clone());
            if action == QualificationZeroAction::Finalize && self.lose_finalize {
                self.lose_finalize = false;
                return Err("injected response loss after real durable finalize".into());
            }
            serde_json::to_vec(&self.config.response(
                &request,
                proof_readback(&proof),
                Some(proof),
                Some(receipt),
            ))
            .map_err(|error| error.to_string())
        }
    }

    #[test]
    fn production_zero_driver_joins_real_controller_for_early_failure_and_prepared_retries() {
        for mode in ["null", "prepared"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/production_zero_protocol_fixture.py");
            let mut child = Command::new("python3")
                .arg(path)
                .arg(mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let mut transport = ControllerTransport {
                input: child.stdin.take(),
                output: BufReader::new(child.stdout.take().unwrap()),
                child,
                config: control_config(),
                lose_finalize: true,
                frames: Vec::new(),
                states: Vec::new(),
            };
            let initial = transport.receive();
            assert_eq!(initial["initial"].is_null(), mode == "null");
            let fixture: FixtureSpec =
                serde_json::from_value(initial["scenario"]["fixture"].clone()).unwrap();
            let mut driver_value = serde_json::to_value(config()).unwrap();
            let mut control_value = serde_json::to_value(control_config()).unwrap();
            for value in [&mut driver_value, &mut control_value] {
                for (key, field) in initial["scenario"]["fixture"].as_object().unwrap() {
                    if value.get(key).is_some() {
                        value[key] = field.clone();
                    }
                }
                value["scenario_sha256"] = initial["scenario_sha256"].clone();
            }
            transport.config = serde_json::from_value(control_value).unwrap();
            let config: ProductionDriverConfig = serde_json::from_value(driver_value).unwrap();
            let request = ZeroRequest {
                schema_version: ZERO_REQUEST_VERSION.into(),
                scenario_sha256: config.scenario_sha256.clone(),
                activation_id: fixture.activation_id,
                activation_package_digest: fixture.activation_package_digest,
                integrated_candidate_sha: fixture.integrated_candidate_sha,
                run_id: fixture.run_id,
                failed_stage: if mode == "null" {
                    Stage::AuthenticatedExport
                } else {
                    Stage::PrepareCapacityZero
                },
                final_response_sha256: (mode == "prepared").then(|| hex('e', 64)),
                expected_controller_generation: Some(fixture.controller_generation),
                expected_runner_generation: Some(fixture.runner_generation),
            };
            let mut driver = ProductionDriver::new(config, transport).unwrap();
            let transition = driver.return_to_zero(&request).unwrap();
            assert_eq!(transition.outcome, Outcome::Pass);
            assert_eq!(transition.phases[0].attempts, 2);
            assert_eq!(transition.zero_proof.capacity, 0);
            let repeated = driver.return_to_zero(&request).unwrap();
            assert_eq!(repeated.zero_proof, transition.zero_proof);
            let transport = driver.into_transport();
            assert_eq!(transport.frames[0], transport.frames[1]);
            assert_eq!(transport.frames[0], transport.frames[3]);
            assert_eq!(transport.states.len(), 5);
            assert!(
                transport
                    .states
                    .iter()
                    .all(|state| state == &transport.states[0])
            );
            assert_eq!(transport.states[0]["phase"], "finalized");
            assert!(transport.states[0]["prepare"].is_object());
            assert!(transport.states[0]["finalize"].is_object());
        }
    }
}
