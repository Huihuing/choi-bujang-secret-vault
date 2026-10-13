import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {publicOperationsResponse} from '../api/war-room-summary.js';

const observed={
 observed_at:'2026-10-13T06:25:58.000+00:00',
 device_pending:0,device_approved:0,device_revoked:0,
 restore_events:0,probe_events:0,probe_matches:0,
 backup_version:'stage10_before_attack_v1',backup_changed_fields:0,
};
test('public operational dashboard preserves actual zero values from DB',()=>{
 const output=publicOperationsResponse(observed,'a'.repeat(40));
 assert.equal(output.schema,'byteback.public-operations.v1');
 assert.equal(output.source,'server_database_aggregate');
 assert.deepEqual(output.deviceState,{pending:0,approved:0,revoked:0});
 assert.deepEqual(output.recovery,{
  version:'stage10_before_attack_v1',changedPolicyEntries:0,verifiedRestoreEvents:0,
 });
 assert.deepEqual(output.safeHttpChecks,{recorded:0,expectedStatusMatched:0});
 assert.equal(output.policyRules.declaredInSource,4);
 assert.equal(output.policyRules.engineDecisions,null);
 assert.equal(output.detector.eventCount,null);
 assert.equal(output.revocation.engineRevokedCount,null);
 assert.deepEqual(output.judgeCases,{target:41,verified:null,
  source:'judge_case_records_not_connected'});
 assert.equal(output.observedAt,observed.observed_at);
 assert.ok(!JSON.stringify(output).includes('owner_id'));
 assert.ok(!JSON.stringify(output).includes('notes'));
});
test('server refuses unverified or missing operational counts instead of inventing them',()=>{
 for(const field of ['device_pending','device_approved','device_revoked',
  'restore_events','probe_events','probe_matches','backup_changed_fields']){
  for(const invalid of [null,undefined,'',-1,2.3,'none',{},NaN]){
   assert.equal(publicOperationsResponse({...observed,[field]:invalid},null),null,field);
  }
 }
 assert.equal(publicOperationsResponse({...observed,probe_matches:1},null),null);
 assert.equal(publicOperationsResponse({...observed,backup_version:null},null),null);
 assert.equal(publicOperationsResponse({...observed,observed_at:'invalid'},null),null);
});
test('PWA shows actual aggregate dashboard before sign in with correct stage',async()=>{
 const page=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const shell=await readFile(new URL('../public/war-summary.js',import.meta.url),'utf8');
 const sw=await readFile(new URL('../public/sw.js',import.meta.url),'utf8');
 assert.ok(page.includes('STEP 12'));
 assert.ok(!page.includes('STEP 11'));
 assert.ok(page.includes('id="war-public" class="card wide" aria-labelledby'));
 assert.ok(page.includes('src="/war-summary.js"'));
 assert.ok(page.includes('id="war-room" class="card wide" hidden'));
 assert.ok(page.includes('결과 미연동 (출처 설명 펼치기)'));
 assert.ok(shell.includes("perform('/api/war-room-summary'"));
 assert.ok(shell.includes("cache:'no-store'"));
 assert.ok(shell.includes('미확인'));
 assert.ok(sw.includes("url.pathname.startsWith('/api/')"));
 assert.ok(!sw.includes("'/api/war-room-summary'"));
});
test('public aggregate RPC is service-role-only and does not select private note rows',async()=>{
 const sql=await readFile(new URL('../db/stage12-public-operational-snapshot.sql',import.meta.url),'utf8');
 assert.match(sql,/REVOKE ALL ON FUNCTION public.stage12_public_operational_snapshot\(\) FROM PUBLIC,anon,authenticated/);
 assert.match(sql,/GRANT EXECUTE ON FUNCTION public.stage12_public_operational_snapshot\(\) TO service_role/);
 assert.ok(!sql.includes('FROM public.notes'));
 assert.ok(sql.includes('public.stage10_policy_preview()'));
 const api=await readFile(new URL('../api/war-room-summary.js',import.meta.url),'utf8');
 assert.ok(api.includes("req.method!=='GET'"));
 assert.ok(api.includes("Cache-Control','no-store'"));
 assert.ok(api.includes("stage12_public_operational_snapshot"));
});
