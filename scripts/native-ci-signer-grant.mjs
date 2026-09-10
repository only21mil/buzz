#!/usr/bin/env node
// One reviewed repository/channel grant, using the existing owner key.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const fields = ['schema', 'operation', 'relay', 'channel_id', 'repository', 'issuer_public_key', 'signer_public_key', 'valid_until'];
export function validatePlan(plan) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan) ||
      Object.keys(plan).sort().join() !== [...fields].sort().join() ||
      plan.schema !== 'buzz-ci-signer-grant-operation-v1' ||
      !['grant', 'revoke'].includes(plan.operation)) throw Error('Invalid operation plan');
  if (typeof plan.relay !== 'string') throw Error('Invalid relay');
  const relay = new URL(plan.relay);
  if (relay.protocol !== 'wss:' || relay.username || relay.password || relay.search || relay.hash) throw Error('Relay must use credential-free wss');
  for (const field of ['issuer_public_key', 'signer_public_key']) {
    if (typeof plan[field] !== 'string' || !/^[0-9a-f]{64}$/.test(plan[field])) throw Error('Invalid public key');
  }
  if (typeof plan.channel_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(plan.channel_id)) throw Error('Invalid channel');
  const prefix = `30617:${plan.issuer_public_key}:`;
  if (typeof plan.repository !== 'string' || !plan.repository.startsWith(prefix) || plan.repository.length <= prefix.length) throw Error('Repository must belong to the pinned issuer');
  if (plan.valid_until !== null && (!Number.isSafeInteger(plan.valid_until) || plan.valid_until <= 0)) throw Error('Invalid expiry');
  if (plan.operation === 'revoke' && plan.valid_until !== null) throw Error('Revocation expiry is generated at execution');
  return plan;
}

export function unsignedGrant(plan, now) {
  validatePlan(plan);
  if (!Number.isSafeInteger(now) || now < 60) throw Error('Invalid clock');
  if (plan.operation === 'grant' && plan.valid_until !== null && plan.valid_until <= now) throw Error('Grant expiry has passed');
  return { kind: 46107, created_at: now, tags: [['h', plan.channel_id]], content: JSON.stringify({
    schema_version: 1, target_repo_a: plan.repository, signer_pubkey: plan.signer_public_key,
    valid_from: plan.operation === 'revoke' ? now - 60 : now,
    valid_until: plan.operation === 'revoke' ? now : plan.valid_until,
  }) };
}

// Injectable transport/signing keeps the tests offline and unsigned.
export function publishAndReadBack({ socket, event, relay, signAuth, verifyEvent, timeoutMs = 30000 }) {
  return new Promise((resolve, reject) => {
    let authId, sent = false, accepted = false, readback = false, done = false;
    const subscription = 'grant-readback';
    const finish = (error) => {
      if (done) return;
      done = true; clearTimeout(timer); socket.close();
      if (error) reject(error); else resolve({ accepted: true, read_back: true, event_id: event.id });
    };
    const timer = setTimeout(() => finish(Error('Timed out; event acceptance may be unknown. Query saved event ID before retrying.')), timeoutMs);
    socket.onerror = () => finish(Error('Transport failed; query saved event ID before retrying.'));
    socket.onclose = () => { if (!done) finish(Error('Connection closed before verified readback; query saved event ID.')); };
    socket.onmessage = ({ data }) => {
      try {
        const frame = JSON.parse(String(data));
        if (!Array.isArray(frame)) throw Error('Invalid relay frame');
        if (frame[0] === 'AUTH') {
          if (authId || typeof frame[1] !== 'string' || !frame[1]) throw Error('Unexpected authentication challenge');
          const auth = signAuth({ kind: 22242, created_at: Math.floor(Date.now() / 1000), content: '', tags: [['relay', relay], ['challenge', frame[1]]] });
          authId = auth.id; socket.send(JSON.stringify(['AUTH', auth]));
        } else if (frame[0] === 'OK' && authId && frame[1] === authId) {
          if (frame[2] !== true) throw Error('Relay authentication rejected');
          if (!sent) { sent = true; socket.send(JSON.stringify(['EVENT', event])); }
        } else if (frame[0] === 'OK' && frame[1] === event.id) {
          if (!sent || frame[2] !== true) throw Error('Grant publication rejected');
          if (!accepted) { accepted = true; socket.send(JSON.stringify(['REQ', subscription, { ids: [event.id] }])); }
        } else if (frame[0] === 'EVENT' && frame[1] === subscription) {
          const received = frame[2];
          if (!accepted || !verifyEvent(received) ||
              ['id', 'pubkey', 'created_at', 'kind', 'content', 'sig'].some(k => received[k] !== event[k]) ||
              JSON.stringify(received.tags) !== JSON.stringify(event.tags)) throw Error('Grant readback differs');
          readback = true;
        } else if (frame[0] === 'EOSE' && frame[1] === subscription) {
          if (!accepted || !readback) throw Error('Grant missing from relay readback');
          finish();
        } else if (frame[0] === 'CLOSED' && frame[1] === subscription) throw Error('Grant readback rejected');
      } catch (error) { finish(error); }
    };
  });
}

function readPrivateJson(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1 || stat.size > 65536) throw Error('Plan must be caller-owned, singly linked, regular mode 0600, at most 64KiB');
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
}
function outputPath(filename) {
  if (!path.isAbsolute(filename) || path.normalize(filename) !== filename) throw Error('Output must be canonical and absolute');
  const parent = path.dirname(filename), stat = fs.lstatSync(parent);
  if (fs.realpathSync(parent) !== parent || !stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) throw Error('Output parent must be canonical caller-owned mode 0700');
  if (fs.existsSync(filename)) throw Error('Output already exists');
}
export function save(filename, value) {
  const tool = fileURLToPath(new URL('./protected-ci-receipt.py', import.meta.url));
  const code = `import importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('receipt',sys.argv[1])
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)
p=pathlib.Path(sys.argv[2])
module.validate_evidence_root(p.parent,checkout=pathlib.Path(sys.argv[1]).parent.parent)
module.safe_publish(p,json.load(sys.stdin))`;
  const result = spawnSync('/usr/bin/python3', ['-I', '-c', code, tool, filename], {
    input: JSON.stringify(value), encoding: 'utf8', env: {}, timeout: 10000,
  });
  if (result.status !== 0) throw Error('Evidence publication failed');
}
async function main() {
  const [mode, planPath, prefix, ...extra] = process.argv.slice(2);
  if (!['--dry-run', '--publish'].includes(mode) || !planPath || extra.length || (mode === '--publish' && !prefix) || (mode === '--dry-run' && prefix)) throw Error('Usage: native-ci-signer-grant.mjs --dry-run PLAN | --publish PLAN ABSOLUTE_EVIDENCE_PREFIX');
  const plan = validatePlan(readPrivateJson(planPath));
  const template = unsignedGrant(plan, Math.floor(Date.now() / 1000));
  if (mode === '--dry-run') { console.log(JSON.stringify({ plan, unsigned_event: template }, null, 2)); return; }
  const eventPath = `${prefix}.event.json`, receiptPath = `${prefix}.receipt.json`;
  outputPath(eventPath); outputPath(receiptPath);
  const dependencyRoot = process.env.BUZZ_NOSTR_TOOLS_ROOT;
  if (!dependencyRoot || !path.isAbsolute(dependencyRoot)) throw Error('BUZZ_NOSTR_TOOLS_ROOT must name the reviewed installed dependency root');
  const require = createRequire(path.join(dependencyRoot, 'package.json'));
  const { finalizeEvent, getPublicKey, nip19, verifyEvent } = require('nostr-tools');
  const encoded = process.env.BUZZ_PRIVATE_KEY;
  if (!encoded) throw Error('BUZZ_PRIVATE_KEY is required in the inherited environment');
  let key;
  if (/^[0-9a-f]{64}$/.test(encoded)) key = Uint8Array.from(Buffer.from(encoded, 'hex'));
  else { const decoded = nip19.decode(encoded); if (decoded.type !== 'nsec') throw Error('Expected an nsec private key'); key = decoded.data; }
  try {
    if (getPublicKey(key) !== plan.issuer_public_key) throw Error('Private key does not match the pinned issuer');
    const event = finalizeEvent(template, key);
    // Save exact signed bytes before any connection; uncertain outcomes can be queried by ID.
    save(eventPath, event);
    const result = await publishAndReadBack({ socket: new WebSocket(plan.relay), event, relay: plan.relay, signAuth: value => finalizeEvent(value, key), verifyEvent });
    save(receiptPath, { schema: 'buzz-ci-signer-grant-publication-v1', timestamp: new Date().toISOString(), plan, ...result });
    console.log(JSON.stringify({ ...result, event_path: eventPath, receipt_path: receiptPath }));
  } finally { key.fill(0); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(() => {
  // Dependency/key-parser/transport errors may contain input data; never echo them.
  console.error('Grant operation failed. If an event file exists, query its ID and the scoped grant row before retrying.');
  process.exitCode = 1;
});
