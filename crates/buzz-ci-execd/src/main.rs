use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    match (args.next().as_deref(), args.next()) {
        (Some(arg), None) if arg == "--version" => {
            println!("buzz-ci-execd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        (Some(arg), None) if arg == "--self-check" => match buzz_ci_execd::self_check() {
            Ok(()) => {
                println!(r#"{{"status":"not_provisioned","capacity":0}}"#);
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!(r#"{{"error":"self_check_failed","reason":"{reason}"}}"#);
                ExitCode::from(4)
            }
        },
        (None, None) => {
            let forbidden = buzz_ci_execd::FORBIDDEN_ENVIRONMENT_KEYS
                .iter()
                .copied()
                .find(|key| std::env::var_os(key).is_some());
            if let Some(key) = forbidden {
                eprintln!(r#"{{"error":"forbidden_environment","key":"{key}"}}"#);
                return ExitCode::from(4);
            }
            eprintln!(r#"{{"error":"not_provisioned","capacity":0}}"#);
            ExitCode::from(4)
        }
        _ => {
            eprintln!(r#"{{"error":"usage","expected":"--version|--self-check"}}"#);
            ExitCode::from(1)
        }
    }
}
