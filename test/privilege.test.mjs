import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decide} from '../xdr/privilege/decide.mjs';
import {readAlerts,parseAlerts} from '../xdr/privilege/read-alerts.mjs';
import {makeRule,rulesFromDecisions,createSessionGuard} from '../xdr/privilege/respond.mjs';

const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json',import.meta.url),'utf8'));
const bindings=JSON.parse(await readFile(new URL('../xdr/privilege/subject-bindings.fixture.json',import.meta.url),'utf8'));
const resolver=account=>Object.hasOwn(bindings.subjects,account)?bindings.subjects[account]:null;
const alerts=fixture.alerts;
const normal=a=>a.rule.level<=3;

test('26 unmodified course Wazuh alerts, minimal sanitized projection',async()=>{
 assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
 assert.equal(fixture.moduleKey,'privilege');
 assert.equal(alerts.length,26);
 assert.equal((await readAlerts()).length,alerts.length);
 const changed=structuredClone(alerts[0]);
 changed.rule.description='administrator token=DO_NOT_LOG password=SECRET';
 const parsed=parseAlerts({alerts:[changed]});
 assert.deepEqual(Object.keys(parsed[0]),['time','sourceIp','account','ruleLevel','description']);
 assert.ok(!JSON.stringify(parsed).includes('DO_NOT_LOG'));
 assert.ok(!JSON.stringify(parsed).includes('SECRET'));
 const patterns=JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json',import.meta.url),'utf8'));
 assert.ok(patterns.length>=3&&patterns.every(x=>x.name&&x.condition&&x.basis));
});
test('standalone import-free decision, block 9 alert 8 record 9',async()=>{
 const code=await readFile(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/^\s*import\s/mu);
 assert.doesNotMatch(code,/\b(?:readFile|writeFile|fetch|require)\s*\(/u);
 const isolated=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const counts={block:0,alert:0,record:0};
 for(let i=0;i<alerts.length;i++){
  const x=isolated.decide(alerts[i]);
  assert.deepEqual(x,decide(alerts[i]));
  const expected=i<9?'block':i<17?'alert':'record';
  assert.equal(x.action,expected,alerts[i].id);
  assert.equal(x.action,x.confidence>=.85?'block':x.confidence>=.5?'alert':'record');
  assert.ok(x.reason.length>3);
  counts[x.action]++;
 }
 assert.deepEqual(counts,{block:9,alert:8,record:9});
});
test('clear admin group, unusual command and session escalation stay block',()=>{
 for(const x of alerts.slice(0,9)){
  assert.equal(decide(x).action,'block',x.id);
  const changed=structuredClone(x);
  changed.id='pv-unrelated';
  changed.data.srcuser='unit-test-user';
  assert.equal(decide(changed).action,'block',x.id+' must not depend on account or alert ID');
 }
 const unknown=structuredClone(alerts[0]);
 unknown.rule.mitre={id:['T1078.004']};
 assert.equal(decide(unknown).action,'block');
});
test('incomplete, canceled or unsuccessful attempts remain alert only',()=>{
 for(const x of alerts.slice(9,17))assert.equal(decide(x).action,'alert',x.id);
 const canceled=structuredClone(alerts[3]);
 canceled.rule.description='관리자 그룹 추가와 명령 실행이 취소됐습니다.';
 assert.equal(decide(canceled).action,'alert');
 const group=structuredClone(alerts[4]);
 group.data.group='project-week3';
 group.rule.description='계정 네 개를 과제 그룹에 추가했습니다. 관리자 그룹은 아닙니다.';
 assert.equal(decide(group).action,'alert');
 const weak={rule:{level:13,mitre:['T1078'],description:'보통 계정이 일반 그룹에 추가됐습니다.'},
  data:{srcuser:'example',group:'class-notes'}};
 assert.notEqual(decide(weak).action,'block');
});
test('normal events, approved administrator maintenance and id-only signals record',()=>{
 for(const x of alerts.slice(17))assert.equal(decide(x).action,'record',x.id);
 const approved=structuredClone(alerts[0]);
 approved.data.approved=true;
 assert.equal(decide(approved).action,'record');
 assert.equal(decide({rule:{level:12,mitre:['T1078'],description:'Account sign-in verified'}}).action,'record');
 assert.notEqual(decide({rule:{level:10,description:'관리자 명령이 실패했습니다.'}}).action,'block');
});
test('verified offline-only subject binding, 15-minute denial and other principals unaffected',async()=>{
 const rows=alerts.map(alert=>({alert,decision:decide(alert),fixtureNormal:normal(alert)}));
 assert.equal(bindings.schema,'aleph.xdr.synthetic-bindings.v1');
 assert.equal(bindings.fixtureOnly,true);
 assert.equal(bindings.sourceFixtureBlobSha,'442fc3297bcc73969fa61b1368d08e0038b9c135');
 assert.equal(rulesFromDecisions(rows).length,0,'without trusted subject mapping, no revoke rule');
 const rules=rulesFromDecisions(rows,resolver);
 assert.equal(rules.length,9);
 assert.ok(rules.every(x=>x.alertId&&x.subjectId.startsWith('test-sdp-subject-')));
 for(const rule of rules)assert.equal(Date.parse(rule.expiresAt)-Date.parse(rule.startsAt),900000);
 const base={schema:'aleph.decision.v1',requestId:'r',decision:'allow',reasonCode:'allowed',ruleIds:[]};
 const guard=createSessionGuard(async()=>base,async()=>rules);
 const start=Date.parse(alerts[0].timestamp);
 assert.equal((await guard({requestId:'r',subjectId:resolver('user01')},{now:start})).decision,'deny');
 assert.deepEqual(await guard({requestId:'r',subjectId:'test-sdp-subject-unrelated'},{now:start}),base);
 assert.deepEqual(await guard({requestId:'r',subjectId:resolver('user01')},{now:start+16*60000}),base);
 assert.deepEqual(await guard({requestId:'r',subjectId:'test-sdp-subject-admin01'},{now:start}),base);
 const priorDeny={...base,decision:'deny',reasonCode:'existing-policy'};
 const priorStepUp={...base,decision:'step_up',reasonCode:'step-up-policy'};
 assert.deepEqual(await createSessionGuard(async()=>priorDeny,async()=>rules)({requestId:'r',subjectId:resolver('user01')},{now:start}),priorDeny);
 assert.deepEqual(await createSessionGuard(async()=>priorStepUp,async()=>rules)({requestId:'r',subjectId:resolver('user01')},{now:start}),priorStepUp);
});
test('cannot forge a block decision or identity mapping',()=>{
 const ambiguous=alerts[9],at=Date.parse(ambiguous.timestamp);
 assert.equal(makeRule(ambiguous,{action:'block',confidence:1,reason:'unexpected-admin-group-change'},at,resolver),null);
 const clear=alerts[0],start=Date.parse(clear.timestamp),actual=decide(clear);
 assert.equal(makeRule(clear,actual,start,()=>null),null);
 assert.equal(makeRule(clear,actual,start+16*60000,resolver),null);
 assert.equal(makeRule(alerts[17],{action:'block',confidence:1,reason:actual.reason},Date.parse(alerts[17].timestamp),resolver),null);
});
test('incomplete Wazuh input never blocks',()=>{
 const cyclic={};cyclic.self=cyclic;
 for(const a of [null,undefined,0,{},[],{rule:{level:12,mitre:['T1078']}},{data:{group:'administrators'}},{rule:{level:2},data:{win:cyclic}}]){
  const result=decide(a);
  assert.ok(['alert','record'].includes(result.action));
 }
});
