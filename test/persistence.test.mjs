import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {decide} from '../xdr/persistence/decide.mjs';
import {readAlerts,parseAlerts} from '../xdr/persistence/read-alerts.mjs';
import {makeRule,rulesFromDecisions,createIsolationGuard} from '../xdr/persistence/respond.mjs';

const SOURCE=new URL('../xdr/fixtures/persistence.json',import.meta.url);
const content=await readFile(SOURCE,'utf8');
const fixture=JSON.parse(content);
const alerts=fixture.alerts;
const bindings=JSON.parse(await readFile(new URL('../xdr/persistence/device-bindings.fixture.json',import.meta.url),'utf8'));
const resolveDevice=alert=>Object.hasOwn(bindings.agents,alert?.agent?.name)?bindings.agents[alert.agent.name]:null;
const isNormal=alert=>alert?.rule?.level<=3;

test('ALEPH published 24-event fixture exact Git blob, original fields and safe read projection',async()=>{
 const gitSha=createHash('sha1').update('blob '+Buffer.byteLength(content)+String.fromCharCode(0)).update(content).digest('hex');
 assert.equal(gitSha,'8dfb349b02cb0fd107a751c148be6165aa8c2725');
 assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
 assert.equal(fixture.moduleKey,'persistence');
 assert.equal(alerts.length,24);
 assert.equal((await readAlerts()).length,24);
 const sample=structuredClone(alerts[0]);
 sample.rule.description='service installed token=NEVER_PRINT password=HIDDEN';
 const rows=parseAlerts({alerts:[sample]});
 assert.deepEqual(Object.keys(rows[0]),['time','sourceIp','account','ruleLevel','description']);
 assert.ok(!JSON.stringify(rows).includes('NEVER_PRINT'));
 assert.ok(!JSON.stringify(rows).includes('HIDDEN'));
 const patterns=JSON.parse(await readFile(new URL('../xdr/persistence/patterns.json',import.meta.url),'utf8'));
 assert.ok(patterns.length>=3&&patterns.every(p=>p.name&&p.condition&&p.basis));
});

test('standalone decide: 8 block / 8 alert / 8 record, by evidence rather than alert IDs',async()=>{
 const code=await readFile(new URL('../xdr/persistence/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/^\s*import\s/mu);
 assert.doesNotMatch(code,/\b(?:readFile|writeFile|fetch|require)\s*\(/u);
 const isolated=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const totals={block:0,alert:0,record:0};
 for(let i=0;i<alerts.length;i++){
  const x=isolated.decide(alerts[i]);
  assert.deepEqual(x,decide(alerts[i]));
  assert.equal(x.action,i<8?'block':i<16?'alert':'record',alerts[i].id);
  assert.equal(x.action,x.confidence>=.85?'block':x.confidence>=.5?'alert':'record');
  totals[x.action]++;
 }
 assert.deepEqual(totals,{block:8,alert:8,record:8});
 for(const alert of alerts.slice(0,8)){
  const clone=structuredClone(alert);
  clone.id='mutated-independent-id';
  clone.data.srcuser='different-training-account';
  assert.equal(decide(clone).action,'block',alert.id);
 }
});

test('actual service, task, Startup and correlated persistence are block; missing evidence is not',()=>{
 for(const alert of alerts.slice(0,8))assert.equal(decide(alert).action,'block');
 const service=structuredClone(alerts[0]);
 service.rule.description='Signed approved service installed';
 service.data.approved=true;
 service.data.signed=true;
 assert.equal(decide(service).action,'record');
 const tempAlone=structuredClone(alerts[12]);
 assert.equal(decide(tempAlone).action,'alert');
 const modifiedDescriptionOnly=structuredClone(alerts[10]);
 assert.equal(decide(modifiedDescriptionOnly).action,'alert');
 const notRun=structuredClone(alerts[13]);
 assert.equal(decide(notRun).action,'alert');
 const incomplete={rule:{level:12,mitre:['T1543'],description:'새 서비스 등록'},data:{path:'C:\\lab\\approved.exe'}};
 assert.notEqual(decide(incomplete).action,'block');
});

test('all ambiguous examples alert only; normal signed and scheduled activity records',()=>{
 for(const alert of alerts.slice(8,16))assert.equal(decide(alert).action,'alert',alert.id);
 for(const alert of alerts.slice(16))assert.equal(decide(alert).action,'record',alert.id);
 assert.equal(decide({rule:{level:2,mitre:['T1053'],description:'운영체제 업데이트 예약이 평소 시각에 그대로입니다.'}}).action,'record');
 assert.equal(decide({rule:{level:3,mitre:['T1543'],description:'기존 정상 서명된 서비스 실행 중'}}).action,'record');
});

test('quarantine rules only through explicit fixture identity resolver, never from Wazuh agent data',async()=>{
 assert.equal(bindings.fixtureOnly,true);
 assert.equal(bindings.sourceFixtureBlobSha,'8dfb349b02cb0fd107a751c148be6165aa8c2725');
 const records=alerts.map(alert=>({alert,decision:decide(alert),fixtureNormal:isNormal(alert)}));
 assert.equal(rulesFromDecisions(records).length,0);
 const rules=rulesFromDecisions(records,resolveDevice);
 assert.equal(rules.length,8);
 for(const rule of rules){
  assert.match(rule.deviceId,/^[a-f0-9]{16}$/u);
  assert.equal(rule.deviceId,'000000000000a104');
  assert.ok(rule.id.startsWith('xdr.persistence.'));
  assert.ok(rule.alertId);
  assert.equal(Date.parse(rule.expiresAt)-Date.parse(rule.startsAt),900000);
 }
 const baseline={schema:'aleph.decision.v1',requestId:'r',decision:'allow',reasonCode:'approved',ruleIds:[]};
 const guard=createIsolationGuard(async()=>baseline,async()=>rules);
 const start=Date.parse(alerts[0].timestamp);
 assert.equal((await guard({requestId:'r',deviceId:'000000000000a104'},{now:start})).decision,'deny');
 assert.deepEqual(await guard({requestId:'r',deviceId:'000000000000ffff'},{now:start,sourceIp:alerts[0].data.srcip}),baseline);
 assert.deepEqual(await guard({requestId:'r',deviceId:'000000000000a104'},{now:start+16*60000}),baseline);
 const denies={...baseline,decision:'deny',reasonCode:'preexisting-deny'};
 const stepUp={...baseline,decision:'step_up',reasonCode:'preexisting-step-up'};
 assert.deepEqual(await createIsolationGuard(async()=>denies,async()=>rules)({requestId:'r',deviceId:'000000000000a104'},{now:start}),denies);
 assert.deepEqual(await createIsolationGuard(async()=>stepUp,async()=>rules)({requestId:'r',deviceId:'000000000000a104'},{now:start}),stepUp);
 assert.equal(makeRule(alerts[0],decide(alerts[0]),start,()=>null),null);
 assert.equal(makeRule(alerts[0],decide(alerts[0]),start+16*60000,resolveDevice),null);
 assert.equal(makeRule(alerts[8],{action:'block',confidence:1,reason:'unfamiliar-scheduled-task'},Date.parse(alerts[8].timestamp),resolveDevice),null);
 assert.equal(makeRule(alerts[16],{action:'block',confidence:1,reason:'unsigned-temporary-service'},Date.parse(alerts[16].timestamp),resolveDevice),null);
});

test('malformed, cyclical, high-level but uncorroborated alerts do not automatically block',()=>{
 const c={};c.self=c;
 for(const a of [null,0,{},[],{data:{syscheck:c}},
  {rule:{level:12,mitre:['T1053']}},{rule:{level:15,mitre:['T1543'],description:'Signed approved service installed'}},
  {rule:{level:14,mitre:['T1543'],description:'서명 없음'},data:{path:'C:\\Windows\\System32\\test.exe'}}]){
  const x=decide(a);
  assert.ok(['alert','record'].includes(x.action));
 }
});
