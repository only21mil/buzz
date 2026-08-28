use anyhow::{bail, Context, Result};
use nostr::secp256k1::{
    schnorr::Signature, Keypair, Message, Secp256k1, SecretKey as SecpSecretKey, XOnlyPublicKey,
};
use rustix::fs::{open, Mode, OFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use zeroize::Zeroizing;

use crate::{parse_public_key_hex, secret_hex_and_public_key};

pub const SIGNATURE_SCHEMA: &str = "buzz-agent-capability-parity-signature-v1";
pub const SEALED_RECEIPT_SCHEMA: &str = "buzz-agent-capability-parity-sealed-receipt-v1";
pub const CANONICAL_JSON_CONTRACT: &str = "buzz-canonical-json-ascii-v1";
pub const OWNER_SECRET_FIELD: &str = "BUZZ_OWNER_PRIVATE_KEY";
pub const SIGNING_DOMAIN: &[u8] = b"buzz-agent-capability-parity/signature/v1\0";
const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENVELOPE_BYTES: usize = 512 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSignature {
    pub schema: String,
    pub algorithm: String,
    pub signer_pubkey: String,
    pub payload_sha256: String,
    pub signature: String,
    pub signed_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationEnvelope {
    schema: String,
    receipt: Value,
    signature: PublicSignature,
    signer: Value,
    verifier: Value,
    verified: bool,
    #[serde(default)]
    sealed_sha256: Option<String>,
}

fn lowercase_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn printable_ascii(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .all(|byte| (0x20..=0x7e).contains(byte))
}

fn append_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .context("canonical JSON numbers must be signed 64-bit integers")?;
            output.extend_from_slice(integer.to_string().as_bytes());
        }
        Value::String(text) => {
            if !printable_ascii(text) {
                bail!("canonical JSON strings must contain printable ASCII only");
            }
            output.extend_from_slice(
                serde_json::to_string(text)
                    .context("serialize canonical JSON string")?
                    .as_bytes(),
            );
        }
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                append_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            output.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if !printable_ascii(key) {
                    bail!("canonical JSON object keys must contain printable ASCII only");
                }
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .context("serialize canonical JSON object key")?
                        .as_bytes(),
                );
                output.push(b':');
                append_canonical_json(&map[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub fn canonical_json_ascii(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    append_canonical_json(value, &mut output)?;
    output.push(b'\n');
    Ok(output)
}

pub fn domain_separated_digest(payload_sha256: &str) -> Result<[u8; 32]> {
    if !lowercase_hex_64(payload_sha256) {
        bail!("payload digest must be 64 lowercase hexadecimal characters");
    }
    let payload = hex::decode(payload_sha256).context("decode payload digest")?;
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_DOMAIN);
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

fn strict_private_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let parent = path.parent().context("private input has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent).context("stat private input parent")?;
    let uid = rustix::process::getuid().as_raw();
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.mode() & 0o7777 != 0o700
    {
        bail!("private input parent must be an owner-controlled 0700 directory");
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .context("open private input")?;
    let mut file = fs::File::from(descriptor);
    let metadata = file.metadata().context("stat private input")?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_SECRET_FILE_BYTES
    {
        bail!("private input must be a single-link owner-controlled 0600 regular file");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.read_to_end(&mut bytes).context("read private input")?;
    Ok(bytes)
}

pub fn owner_secret_from_file(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = strict_private_file(path)?;
    let text = std::str::from_utf8(&bytes).context("private input is not UTF-8")?;
    let mut result: Option<Zeroizing<String>> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        if name == OWNER_SECRET_FIELD {
            if result.is_some() {
                bail!("owner secret field is duplicated");
            }
            result = Some(Zeroizing::new(value.trim_matches(['\'', '"']).to_owned()));
        }
    }
    result.context("owner secret field is absent")
}

pub fn sign_payload(
    secret_value: &str,
    expected_owner: &str,
    payload_sha256: &str,
    signed_at: &str,
) -> Result<PublicSignature> {
    let expected_owner = parse_public_key_hex(expected_owner)?;
    let signing_digest = domain_separated_digest(payload_sha256)?;
    let timestamp = signed_at.as_bytes();
    if timestamp.len() != 20
        || timestamp[4] != b'-'
        || timestamp[7] != b'-'
        || timestamp[10] != b'T'
        || timestamp[13] != b':'
        || timestamp[16] != b':'
        || timestamp[19] != b'Z'
        || timestamp.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        bail!("signed-at must be a UTC second timestamp");
    }
    let (secret_hex, actual_owner) = secret_hex_and_public_key(secret_value)?;
    if actual_owner != expected_owner {
        bail!("owner secret does not match reviewed owner public key");
    }
    let secret_bytes =
        Zeroizing::new(hex::decode(secret_hex.as_str()).context("decode owner secret")?);
    let secret = SecpSecretKey::from_slice(&secret_bytes).context("parse owner secret")?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let message = Message::from_digest_slice(&signing_digest).context("parse signing digest")?;
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    Ok(PublicSignature {
        schema: SIGNATURE_SCHEMA.to_owned(),
        algorithm: "schnorr-secp256k1".to_owned(),
        signer_pubkey: expected_owner,
        payload_sha256: payload_sha256.to_owned(),
        signature: signature.to_string(),
        signed_at: signed_at.to_owned(),
    })
}

pub fn verify_envelope(input: &[u8], expected_owner: &str) -> Result<()> {
    if input.len() > MAX_ENVELOPE_BYTES {
        bail!("verification envelope is too large");
    }
    let expected_owner = parse_public_key_hex(expected_owner)?;
    let envelope: VerificationEnvelope =
        serde_json::from_slice(input).context("parse verification envelope")?;
    if envelope.schema != SEALED_RECEIPT_SCHEMA {
        bail!("verification envelope state is invalid");
    }
    match (envelope.verified, envelope.sealed_sha256.as_deref()) {
        (false, None) => {}
        (true, Some(recorded)) if lowercase_hex_64(recorded) => {
            let mut persisted: Value =
                serde_json::from_slice(input).context("parse persisted verification envelope")?;
            persisted
                .as_object_mut()
                .context("persisted envelope must be an object")?
                .remove("sealed_sha256");
            let canonical = canonical_json_ascii(&persisted)
                .context("canonicalize persisted verification envelope")?;
            if hex::encode(Sha256::digest(canonical)) != recorded {
                bail!("sealed envelope digest mismatch");
            }
        }
        _ => bail!("verification envelope state is invalid"),
    }
    if !envelope.signer.is_object() || !envelope.verifier.is_object() {
        bail!("verification command provenance is invalid");
    }
    let receipt = envelope
        .receipt
        .as_object()
        .context("receipt must be an object")?;
    if receipt
        .get("canonical_json_contract")
        .and_then(Value::as_str)
        != Some(CANONICAL_JSON_CONTRACT)
    {
        bail!("receipt canonical JSON contract mismatch");
    }
    let recorded_payload = receipt
        .get("payload_sha256")
        .and_then(Value::as_str)
        .context("receipt payload digest is absent")?;
    if !lowercase_hex_64(recorded_payload) {
        bail!("receipt payload digest is invalid");
    }
    let mut unsigned_receipt = receipt.clone();
    unsigned_receipt.remove("payload_sha256");
    let canonical = canonical_json_ascii(&Value::Object(unsigned_receipt))
        .context("canonicalize receipt payload")?;
    let recomputed = hex::encode(Sha256::digest(canonical));
    if recomputed != recorded_payload {
        bail!("receipt payload digest mismatch");
    }
    let signature = envelope.signature;
    if signature.schema != SIGNATURE_SCHEMA
        || signature.algorithm != "schnorr-secp256k1"
        || signature.signer_pubkey != expected_owner
        || signature.payload_sha256 != recorded_payload
    {
        bail!("signature binding is invalid");
    }
    let public_key = XOnlyPublicKey::from_slice(&hex::decode(&expected_owner)?)
        .context("parse owner public key")?;
    let parsed_signature: Signature = signature.signature.parse().context("parse signature")?;
    let signing_digest = domain_separated_digest(recorded_payload)?;
    let message = Message::from_digest_slice(&signing_digest).context("parse signing digest")?;
    Secp256k1::verification_only()
        .verify_schnorr(&parsed_signature, &message, &public_key)
        .context("verify owner signature")
}
