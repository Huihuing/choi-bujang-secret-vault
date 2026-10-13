import test from 'node:test';
import assert from 'node:assert/strict';
import {
 RESTORE_ROUTE,POLICY_ROUTE,exactStage10Path,isVerifiedJudgeB,
 recoveryNoteId,recoveryNoteOperation,recoveryPolicyHash,confirmedRestoreResponse,
} from '../src/stage10-restore-contract.mjs';
import {restoreFromVerifiedSnapshot} from '../src/restore-core.mjs';

const id='11111111-1111-4111-8111-111111111111';
const login={kind:'judge',identity:'b',userId:id,
 runId:'22222222-2222-4222-8222-222222222222'};
test('B must have engine-verified judge identity and run ID',()=>{
 assert.equal(isVerifiedJudgeB(login),true);
 for(const change of [
  {identity:'a'},{kind:'student'},{userId:'fake'},{runId:''},
 ])assert.equal(isVerifiedJudgeB({...login,...change}),false);
 assert.equal(isVerifiedJudgeB(null),false);
});
test('only exact restoration/policy paths, no query, fragment or other routes',()=>{
 assert.equal(exactStage10Path('/api/restore',RESTORE_ROUTE),true);
 assert.equal(exactStage10Path('/api/recovery-policy',POLICY_ROUTE),true);
 for(const value of ['/api/restore/','/api/restore/'+id,
   '/api/restore?role=b','/api/restore#tag','/api/restore/export']) {
  assert.equal(exactStage10Path(value,RESTORE_ROUTE),false,value);
 }
});
test('POST recovery identifies exactly one UUID, never trusts owner/body privileges',()=>{
 assert.equal(recoveryNoteId({id}),id);
 assert.equal(recoveryNoteId(JSON.stringify({id})),id);
 for(const input of [null,{},[],{id:'not-uuid'},{id,owner_id:id},{id,role:'instructor'},
  '{"id":',{'noteId':id},{id:'../../note'},'{'+ 'x'.repeat(2500)+'}']) {
  assert.equal(recoveryNoteId(input),null,JSON.stringify(input));
 }
});
test('policy restore requires exact valid 64-digit reviewed baseline hash',()=>{
 const hash='a'.repeat(64);
 assert.equal(recoveryPolicyHash({expectedSha256:hash}),hash);
 for(const value of [null,{}, {expectedSha256:hash,approve:true},
  {expectedSha256:'abc'},{expectedSha256:hash.toUpperCase()}]){
  assert.equal(recoveryPolicyHash(value),null);
 }
});
test('restore response is constrained to verified id, version, hash',()=>{
 const v={restored:true,id,content_sha256:'b'.repeat(64),
  snapshot_version:'stage10_before_attack_v1',secret:'not-returned'};
 assert.deepEqual(confirmedRestoreResponse(v,id),{
  restored:true,id,content_sha256:'b'.repeat(64),snapshot_version:v.snapshot_version,
 });
 assert.equal(confirmedRestoreResponse({...v,id:'33333333-3333-4333-8333-333333333333'},id),null);
 assert.equal(confirmedRestoreResponse({...v,content_sha256:'invalid'},id),null);
 assert.equal(confirmedRestoreResponse({...v,restored:false},id),null);
});
test('RESTORE endpoint must only return 405 on unsupported verbs without touching data',async()=>{
 const {default:handler}=await import('../api/restore.js');
 let status,headers={},body;
 const response={
  status(code){status=code;return this},
  setHeader(key,value){headers[key]=value;return this},
  json(value){body=value;return value},
 };
 await handler({method:'GET',url:'/api/restore',headers:{}},response);
 assert.equal(status,405);
 assert.equal(headers.Allow,'POST');
 assert.deepEqual(body,{error:'method_not_allowed'});
});



const snapshot={
  backup_verified:true,id,snapshot_version:'stage10_before_attack_v1',
  record_sha256:'a'.repeat(64),content_sha256:'b'.repeat(64),
  policy_sha256:'c'.repeat(64),changed_fields:['content','title'],
};
const restored={
  restored:true,id,backup_verified:true,snapshot_version:snapshot.snapshot_version,
  record_sha256:snapshot.record_sha256,content_sha256:snapshot.content_sha256,
  policy_sha256:snapshot.policy_sha256,changed_fields:snapshot.changed_fields,
};
function fakeClient(read={data:snapshot,error:null},write={data:restored,error:null}) {
 const calls=[];
 return {calls,supabase:{async rpc(name,args){
  calls.push({name,args});
  if(name==='stage10_note_preview')return read;
  if(name==='stage10_restore_verified')return write;
  throw new Error('unexpected RPC');
 }}};
}
test('existing POST id remains valid, only true dryRun adds preflight',()=>{
 assert.deepEqual(recoveryNoteOperation({id}),{id,dryRun:false});
 assert.deepEqual(recoveryNoteOperation({id,dryRun:true}),{id,dryRun:true});
 assert.deepEqual(recoveryNoteOperation(JSON.stringify({id,dryRun:true})),{id,dryRun:true});
 for(const body of [{id,dryRun:false},{id,dryRun:'true'}, {id,dryRun:true,owner_id:id},
   {noteId:id,dryRun:true},{id,role:'judge'},{id,owner_id:id},{}]){
  assert.equal(recoveryNoteOperation(body),null);
 }
 assert.equal(recoveryNoteId({id}),id);
});
test('dryRun reads and validates backup only and returns version and changed fields',async()=>{
 const mock=fakeClient();
 const out=await restoreFromVerifiedSnapshot({supabase:mock.supabase,id,ownerId:'verified_owner',dryRun:true});
 assert.equal(out.status,200);
 assert.equal(out.body.preview,true);
 assert.equal(out.body.backup_verified,true);
 assert.equal(out.body.snapshot_version,'stage10_before_attack_v1');
 assert.deepEqual(out.body.changed_fields,['content','title']);
 assert.deepEqual(mock.calls.map(x=>x.name),['stage10_note_preview']);
 assert.equal(mock.calls[0].args.p_verified_owner,'verified_owner');
 assert.equal(JSON.stringify(out).includes('verified_owner'),false);
});
test('normal restore rechecks hashes and version, then returns proof',async()=>{
 const mock=fakeClient();
 const out=await restoreFromVerifiedSnapshot({supabase:mock.supabase,id,ownerId:'verified_owner'});
 assert.equal(out.status,200);
 assert.equal(out.body.restored,true);
 assert.equal(out.body.backup_verified,true);
 assert.deepEqual(mock.calls.map(x=>x.name),['stage10_note_preview','stage10_restore_verified']);
 const args=mock.calls[1].args;
 assert.equal(args.p_expected_record_sha256,snapshot.record_sha256);
 assert.equal(args.p_expected_version,snapshot.snapshot_version);
 assert.equal(args.p_expected_policy_sha256,snapshot.policy_sha256);
 assert.deepEqual(out.body.changed_fields,['content','title']);
});
test('missing and corrupt backups stop before write for previews AND restores',async()=>{
 const readCases=[
  [{data:null,error:{code:'P0002'}},404,'verified_backup_missing'],
  [{data:null,error:{code:'22000'}},409,'backup_verification_failed'],
  [{data:{...snapshot,backup_verified:false},error:null},409,'backup_verification_failed'],
  [{data:{...snapshot,record_sha256:'untrusted'},error:null},409,'backup_verification_failed'],
  [{data:{...snapshot,id:'33333333-3333-4333-8333-333333333333'},error:null},409,'backup_verification_failed'],
  [{data:{...snapshot,changed_fields:['owner_id']},error:null},409,'backup_verification_failed'],
 ];
 for(const [read,status,reason] of readCases){
  for(const dryRun of [false,true]){
   const mock=fakeClient(read);
   const out=await restoreFromVerifiedSnapshot({supabase:mock.supabase,id,ownerId:'verified_owner',dryRun});
   assert.equal(out.status,status);
   assert.equal(out.body.error,reason);
   assert.deepEqual(mock.calls.map(x=>x.name),['stage10_note_preview']);
  }
 }
});
test('failed restoration or mismatched post-write proof never reports success',async()=>{
 for(const write of [
  {data:null,error:{code:'22000'}},
  {data:{...restored,record_sha256:'f'.repeat(64)},error:null},
  {data:{...restored,backup_verified:false},error:null},
 ]){
  const mock=fakeClient(undefined,write);
  const out=await restoreFromVerifiedSnapshot({supabase:mock.supabase,id,ownerId:'verified_owner'});
  assert.ok(out.status>=400);
  assert.deepEqual(mock.calls.map(x=>x.name),['stage10_note_preview','stage10_restore_verified']);
 }
});
