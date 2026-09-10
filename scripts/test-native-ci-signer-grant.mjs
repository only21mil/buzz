import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { validatePlan, unsignedGrant, publishAndReadBack, save } from './native-ci-signer-grant.mjs';
const issuer = 'a'.repeat(64);
const plan = { schema: 'buzz-ci-signer-grant-operation-v1', operation: 'grant', relay: 'wss://relay.example', channel_id: '12345678-1234-1234-1234-123456789abc', repository: `30617:${issuer}:repo`, issuer_public_key: issuer, signer_public_key: 'b'.repeat(64), valid_until: null };
test('grant and revocation scope and expiry are exact', () => {
  const grant = unsignedGrant(plan, 2000), revoke = unsignedGrant({...plan, operation: 'revoke'}, 2000);
  assert.equal(grant.kind, 46107); assert.deepEqual(grant.tags, [['h', plan.channel_id]]);
  assert.deepEqual(JSON.parse(grant.content), { schema_version: 1, target_repo_a: plan.repository, signer_pubkey: plan.signer_public_key, valid_from: 2000, valid_until: null });
  assert.equal(revoke.created_at, 2000); assert.equal(JSON.parse(revoke.content).valid_from, 1940); assert.equal(JSON.parse(revoke.content).valid_until, 2000);
});
test('refuse additional fields, wrong issuer, credential URL, expired and invalid windows', () => {
  for (const delta of [{key: 'no'}, {repository: `30617:${'c'.repeat(64)}:repo`}, {relay:'wss://user:password@relay.example'}, {relay:'ws://relay.example'}, {valid_until: 1.5}, {operation:'revoke',valid_until:3000}]) assert.throws(() => validatePlan({...plan,...delta}));
  assert.throws(() => unsignedGrant({...plan,valid_until:2000},2000));
});
function session() {
  const sent=[];
  const socket={send: data=>sent.push(JSON.parse(data)),close(){}};
  const event={...unsignedGrant(plan,2000),id:'event-id',pubkey:issuer,sig:'fake-signature'};
  const promise=publishAndReadBack({socket,event,relay:plan.relay,signAuth: template=>({...template,id:'auth-id'}),verifyEvent: received=>received.sig==='fake-signature',timeoutMs:100});
  return {event,promise,sent,emit: frame=>socket.onmessage({data:JSON.stringify(frame)}),socket};
}
test('publish only after auth, only once, require matching signed readback',async()=>{
  const s=session(); assert.equal(s.sent.length,0);
  s.emit(['AUTH','challenge']); assert.equal(s.sent[0][0],'AUTH');
  s.emit(['OK','auth-id',true]);s.emit(['OK','auth-id',true]); assert.equal(s.sent.filter(f=>f[0]==='EVENT').length,1);
  s.emit(['OK','event-id',true]); assert.equal(s.sent.at(-1)[0],'REQ');
  s.emit(['EVENT','grant-readback',s.event]);s.emit(['EOSE','grant-readback']);
  assert.equal((await s.promise).read_back,true);
});
for(const [name,frames] of [
  ['auth rejection',[['AUTH','challenge'],['OK','auth-id',false]]],
  ['publish rejection',[['AUTH','challenge'],['OK','auth-id',true],['OK','event-id',false]]],
  ['empty readback',[['AUTH','challenge'],['OK','auth-id',true],['OK','event-id',true],['EOSE','grant-readback']]],
  ['duplicate challenge',[['AUTH','challenge'],['AUTH','another']]],
])test(name,async()=>{const s=session();for(const frame of frames)s.emit(frame);await assert.rejects(s.promise);});
test('changed readback fails',async()=>{const s=session();s.emit(['AUTH','challenge']);s.emit(['OK','auth-id',true]);s.emit(['OK','event-id',true]);s.emit(['EVENT','grant-readback',{...s.event,content:'changed'}]);await assert.rejects(s.promise);});
test('timeout reports uncertain outcome',async()=>{const s=session();await assert.rejects(s.promise,/unknown/);});
test('shared publisher creates private evidence once and rejects symlinks',()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'buzz-grant-test-'));fs.chmodSync(root,0o700);
  try { const out=path.join(root,'event.json');save(out,{public:'event'});assert.equal(fs.statSync(out).mode&0o777,0o600);assert.equal(fs.statSync(out).nlink,1);assert.throws(()=>save(out,{}));const link=path.join(root,'link.json');fs.symlinkSync(out,link);assert.throws(()=>save(link,{}));assert.deepEqual(JSON.parse(fs.readFileSync(out)),{public:'event'}); }finally{fs.rmSync(root,{recursive:true});}
});
