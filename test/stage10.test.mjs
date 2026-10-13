import test from 'node:test';
import assert from 'node:assert/strict';
import {
 RESTORE_ROUTE,POLICY_ROUTE,exactStage10Path,isVerifiedJudgeB,
 recoveryNoteId,recoveryPolicyHash,confirmedRestoreResponse,
} from '../src/stage10-restore-contract.mjs';

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
