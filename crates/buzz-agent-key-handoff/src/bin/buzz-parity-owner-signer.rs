#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use buzz_agent_key_handoff::{harden_process, parity_signature, require_anonymous_pipe};
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::path::PathBuf;

fn main() -> Result<()> {
    harden_process()?;
    let mut arguments = std::env::args().skip(1);
    let mut secrets_file = None;
    let mut owner_pubkey = None;
    let mut signed_at = None;
    while let Some(argument) = arguments.next() {
        let value = arguments.next().context("missing option value")?;
        match argument.as_str() {
            "--secrets-file" if secrets_file.is_none() => secrets_file = Some(PathBuf::from(value)),
            "--owner-pubkey" if owner_pubkey.is_none() => owner_pubkey = Some(value),
            "--signed-at" if signed_at.is_none() => signed_at = Some(value),
            _ => bail!("unsupported option"),
        }
    }
    let secrets_file = secrets_file.context("--secrets-file is required")?;
    if !secrets_file.is_absolute() {
        bail!("--secrets-file must be absolute");
    }
    let owner_pubkey = owner_pubkey.context("--owner-pubkey is required")?;
    let signed_at = signed_at.context("--signed-at is required")?;
    require_anonymous_pipe(io::stdin().as_fd())?;
    let mut payload = String::new();
    io::stdin().take(66).read_to_string(&mut payload)?;
    let payload = payload
        .strip_suffix('\n')
        .context("payload must end with newline")?;
    if payload.contains('\n') {
        bail!("payload must contain exactly one line");
    }
    let secret = parity_signature::owner_secret_from_file(&secrets_file)?;
    let signature = parity_signature::sign_payload(&secret, &owner_pubkey, payload, &signed_at)?;
    println!("{}", serde_json::to_string(&signature)?);
    Ok(())
}
