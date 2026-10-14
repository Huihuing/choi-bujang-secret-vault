import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decide} from '../xdr/privilege/decide.mjs';
import {readAlerts,parseAlerts} from '../xdr/privilege/read-alerts.mjs';
import {makeRule,rulesFromDecisions,createSessionGuard} from '../xdr/privilege/respond.mjs';

const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json',import.meta.url),'utf8'));
const bindings=JSON.parse(await readFile(new URL('../xdr/privilege/subject-bindings.fixture.json',import.meta.url),'utf8'));
const resolver=account=>Object.hasOwn(bindings.subjects,account)?bindings.subjects[account]:null;

test('read alert count and redact secret-looking Wazuh values',async()=>{
 assert.equal(fixture.source.includes('AI-created'),true);
 assert.equal((await readAlerts()).length,18);
 const sample=structuredClone(fixture.alerts[0]);
 sample.rule.description='administrator token=DO_NOT_LOG password=SECRET';
 const parsed=parseAlerts({alerts:[sample]});
 assert.deepEqual(Object.keys(parsed[0]),['time','sourceIp','account','ruleLevel','description']);
 assert.ok(!JSON.stringify(parsed).includes('DO_NOT_LOG'));
 assert.ok(!JSON.stringify(parsed).includes('SECRET'));
 const patterns=JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json',import.meta.url),'utf8'));
 assert.ok(patterns.length>=3&&patterns.every(p=>p.name&&p.condition&&p.basis));
});
test('self-contained offline decision outputs 6 block, 6 alert, 6 record',async()=>{
 const code=await readFile(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/^\s*import\s/mu);
 assert.doesNotMatch(code,/\b(?:readFile|writeFile|fetch|require)\s*\(/u);
 const isolated=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const counts={block:0,alert:0,record:0};
 for(const sample of fixture.alerts){
  const actual=isolated.decide(sample);
  assert.deepEqual(actual,decide(sample));
  assert.equal(actual.action,sample.fixture.classification==='normal'?'record':sample.fixture.classification,sample.id);
  assert.equal(actual.action,actual.confidence>=.85?'block':actual.confidence>=.5?'alert':'record');
  assert.ok(actual.reason.length>3);
  counts[actual.action]++;
 }
 assert.deepEqual(counts,{block:6,alert:6,record:6});
});
test('unapproved admin membership change and unexpected elevated command are clear',()=>{
 for(const a of fixture.alerts.slice(0,6)){
  const out=decide(a);
  assert.equal(out.action,'block',a.id);
  assert.ok(out.reason.startsWith('unapproved-')||out.reason.startsWith('unexpected-')||out.reason==='off-hours-elevation');
 }
 const event=structuredClone(fixture.alerts[0]);
 event.rule.mitre={id:['T1078.004']};
 assert.equal(decide(event).action,'block');
});
test('incomplete group change, admin command, and off-hours use stay alert',()=>{
 for(const a of fixture.alerts.slice(6,12))assert.equal(decide(a).action,'alert',a.id);
 const group=structuredClone(fixture.alerts[0]);
 delete group.data.approved;delete group.data.baselineKnown;
 group.rule.description='Administrator added to group, approval unknown';
 assert.equal(decide(group).action,'alert');
 const command=structuredClone(fixture.alerts[3]);
 command.data.firstSeen=false;
 assert.equal(decide(command).action,'alert');
});
test('approved maintenance and ordinary events are never blocked',()=>{
 for(const a of fixture.alerts.slice(12))assert.equal(decide(a).action,'record',a.id);
 const approved=structuredClone(fixture.alerts[0]);
 approved.rule.level=2;approved.rule.mitre=[];
 approved.data.approved=true;approved.data.baselineKnown=true;
 approved.rule.description='Approved administrator added to Administrators group';
 assert.equal(decide(approved).action,'record');
});
test('session restriction requires trusted account to pseudonymous subject mapping',async()=>{
 const rows=fixture.alerts.map(alert=>({alert,decision:decide(alert),
  fixtureNormal:alert.fixture.classification==='normal'}));
 assert.equal(rulesFromDecisions(rows).length,0,'no map must create zero deny rules');
 const rules=rulesFromDecisions(rows,resolver);
 assert.equal(rules.length,6);
 assert.ok(rules.every(x=>x.subjectId.startsWith('test-sdp-subject-')));
 for(const rule of rules){
  assert.match(rule.id,/^xdr\.privilege\.pr-/u);
  assert.ok(rule.alertId);
  assert.equal(Date.parse(rule.expiresAt)-Date.parse(rule.startsAt),900000);
 }
 const baseline={schema:'aleph.decision.v1',requestId:'r',decision:'allow',reasonCode:'approved',ruleIds:[]};
 const guard=createSessionGuard(async()=>baseline,async()=>rules);
 const bad=fixture.alerts[0],at=Date.parse(bad.timestamp);
 assert.equal((await guard({requestId:'r',subjectId:resolver(bad.data.srcuser)},{now:at})).decision,'deny');
 assert.deepEqual(await guard({requestId:'r',subjectId:'test-sdp-subject-ff'},{now:at}),baseline);
 assert.deepEqual(await guard({requestId:'r',subjectId:resolver(bad.data.srcuser)},{now:at+16*60000}),baseline);
 const normal=fixture.alerts[12];
 assert.equal(makeRule(normal,{action:'block',confidence:1,reason:'unapproved-admin-group-add'},Date.parse(normal.timestamp),resolver),null);
});
test('cannot turn an alert into a forced deny with an injected decision',()=>{
 const ambiguous=fixture.alerts[6],at=Date.parse(ambiguous.timestamp);
 assert.equal(makeRule(ambiguous,{action:'block',confidence:1,reason:'unapproved-admin-group-add'},at,resolver),null);
 const untrusted=fixture.alerts[0];
 assert.equal(makeRule(untrusted,decide(untrusted),Date.parse(untrusted.timestamp),()=>null),null);
 assert.equal(makeRule(untrusted,decide(untrusted),Date.parse(untrusted.timestamp)+16*60000,resolver),null);
});
test('invalid and unexpected Wazuh shapes remain safe',()=>{
 const cyclic={};cyclic.self=cyclic;
 for(const a of [null,undefined,0,{},[],{data:{eventID:'4732'}},
  {rule:{level:12,mitre:['T1078']},data:{groupName:'Administrators'}},
  {rule:{level:2},data:{win:cyclic}},
 ]){
  const result=decide(a);
  assert.ok(['alert','record'].includes(result.action));
  assert.ok(result.confidence>=0&&result.confidence<=1);
 }
});
