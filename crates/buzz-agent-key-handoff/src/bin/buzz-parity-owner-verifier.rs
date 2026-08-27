#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use buzz_agent_key_handoff::{harden_process, parity_signature, require_anonymous_pipe};
use std::io::{self, Read};
use std::os::fd::AsFd;

fn main() -> Result<()> {
    harden_process()?;
    let mut arguments = std::env::args().skip(1);
    if arguments.next().as_deref() != Some("--owner-pubkey") {
        bail!("--owner-pubkey is required");
    }
    let owner_pubkey = arguments.next().context("missing owner public key")?;
    if arguments.next().is_some() {
        bail!("unexpected argument");
    }
    require_anonymous_pipe(io::stdin().as_fd())?;
    let mut envelope = Vec::new();
    io::stdin().take(512 * 1024 + 1).read_to_end(&mut envelope)?;
    parity_signature::verify_envelope(&envelope, &owner_pubkey)
}
