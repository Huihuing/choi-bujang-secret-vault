import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decide} from '../xdr/persistence/decide.mjs';
import {readAlerts,parseAlerts} from '../xdr/persistence/read-alerts.mjs';
import {makeRule,rulesFromDecisions,createIsolationGuard} from '../xdr/persistence/respond.mjs';

const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json',import.meta.url),'utf8'));

test('read Wazuh alerts without leaking secret-looking values',async()=>{
 assert.equal(fixture.source.includes('synthetic'),true);
 assert.equal((await readAlerts()).length,fixture.alerts.length);
 const a=structuredClone(fixture.alerts[0]);
 a.rule.description='service installed token=NEVER_PRINT password=HIDDEN';
 const extracted=parseAlerts({alerts:[a]});
 assert.equal(extracted.length,1);
 assert.ok(!JSON.stringify(extracted).includes('NEVER_PRINT'));
 assert.ok(!JSON.stringify(extracted).includes('HIDDEN'));
 assert.deepEqual(Object.keys(extracted[0]),['time','sourceIp','account','ruleLevel','description']);
 const patterns=JSON.parse(await readFile(new URL('../xdr/persistence/patterns.json',import.meta.url),'utf8'));
 assert.ok(patterns.length>=3&&patterns.every(x=>x.name&&x.condition&&x.basis));
});
test('standalone offline decide classifies clear 6 / ambiguous 6 / normal 6',async()=>{
 const code=await readFile(new URL('../xdr/persistence/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/^\s*import\s/mu);
 assert.doesNotMatch(code,/\b(?:readFile|writeFile|fetch|require)\s*\(/u);
 const isolated=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const counts={block:0,alert:0,record:0};
 for(const alert of fixture.alerts){
  const actual=isolated.decide(alert);
  assert.deepEqual(actual,decide(alert));
  assert.ok(actual.confidence>=0&&actual.confidence<=1);
  assert.equal(actual.action,actual.confidence>=.85?'block':actual.confidence>=.5?'alert':'record');
  assert.equal(actual.action,alert.fixture.classification==='normal'?'record':alert.fixture.classification,alert.id);
  counts[actual.action]++;
 }
 assert.deepEqual(counts,{block:6,alert:6,record:6});
});
test('severe corroborated unsigned service and unfamiliar task trigger block',()=>{
 const service=structuredClone(fixture.alerts[0]);
 assert.equal(decide(service).action,'block');
 service.data.signatureValid=true;service.data.baselineKnown=true;
 service.rule.description='승인된 서비스가 정상 등록되었습니다';
 assert.notEqual(decide(service).action,'block');
 const task=structuredClone(fixture.alerts[2]);
 assert.equal(decide(task).action,'block');
 task.data.signed=true;task.data.baselineKnown=true;task.rule.description='정상 서명된 예약 작업 등록';
 assert.notEqual(decide(task).action,'block');
});
test('ambiguous service, task, startup changes only alert',()=>{
 for(const a of fixture.alerts.slice(6,12))assert.equal(decide(a).action,'alert');
 const truncated=structuredClone(fixture.alerts[0]);
 truncated.data.baselineKnown=undefined;
 truncated.rule.description='새 서비스 등록 감지, 서명 상태 불확실';
 delete truncated.data.signatureValid;
 assert.equal(decide(truncated).action,'alert');
});
test('benign authorized changes remain record regardless of name',()=>{
 for(const a of fixture.alerts.slice(12))assert.equal(decide(a).action,'record');
 const approved=structuredClone(fixture.alerts[12]);
 approved.rule.description='Signed approved Windows service installed';
 assert.equal(decide(approved).action,'record');
});
test('device-bound isolation expires, does not deny another device at same IP',async()=>{
 const rows=fixture.alerts.map(alert=>({alert,decision:decide(alert),
  fixtureNormal:alert.fixture.classification==='normal'}));
 const rules=rulesFromDecisions(rows);
 assert.equal(rules.length,6);
 for(const rule of rules){
  assert.match(rule.deviceId,/^[a-f0-9]{16}$/u);
  assert.ok(rule.alertId&&rule.id.startsWith('xdr.persistence.'));
  assert.equal(Date.parse(rule.expiresAt)-Date.parse(rule.startsAt),15*60000);
 }
 const normal=fixture.alerts[12];
 assert.equal(makeRule(normal,{action:'block',confidence:1,reason:'unsigned-new-service'},Date.parse(normal.timestamp)),null);
 const baseline={schema:'aleph.decision.v1',requestId:'r',decision:'allow',reasonCode:'approved',ruleIds:[]};
 const guard=createIsolationGuard(async()=>baseline,async()=>rules);
 const bad=fixture.alerts[0];
 const at=Date.parse(bad.timestamp);
 const deny=await guard({requestId:'r',deviceId:bad.data.deviceId},{now:at});
 assert.equal(deny.decision,'deny');
 assert.deepEqual(await guard({requestId:'r',deviceId:'00000000000000ff'},
  {now:at,sourceIp:bad.data.srcip}),baseline);
 assert.deepEqual(await guard({requestId:'r',deviceId:bad.data.deviceId},
  {now:at+16*60000}),baseline);
 const approved=fixture.alerts[12];
 assert.deepEqual(await guard({requestId:'r',deviceId:approved.data.deviceId},
  {now:Date.parse(approved.timestamp)}),baseline);
 const forged=structuredClone(bad);forged.data.deviceId='not-engine-verified';
 assert.equal(makeRule(forged,decide(forged),Date.parse(forged.timestamp)),null);
});
test('unexpected alert shapes are safe and do not automatically block',()=>{
 const cyclic={};cyclic.self=cyclic;
 for(const input of [null,0,[],{}, {data:{syscheck:cyclic}},
   {rule:{mitre:['T1053'],level:12},data:{signed:false}},
   {rule:{mitre:{id:['T1543.003']},level:12,description:'새 서비스 등록'}}]){
  const out=decide(input);
  assert.ok(out.action==='alert'||out.action==='record');
 }
});
