import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decide} from '../xdr/known-cve/decide.mjs';
import {readAlerts,parseAlerts} from '../xdr/known-cve/read-alerts.mjs';
import {makeRule,rulesFromDecisions} from '../xdr/known-cve/respond.mjs';
import {createGuard} from '../xdr/web-injection/connect.mjs';

const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json',import.meta.url),'utf8'));
test('fixture count equals redacted extracted lines, and every pattern has a source',async()=>{
 const raw=fixture.alerts;
 assert.equal(raw.length,18);
 assert.equal((await readAlerts()).length,raw.length);
 const example=structuredClone(raw[0]);
 example.rule.description='test token=should_not_be_in_logs password=not-for-display';
 const output=parseAlerts({alerts:[example]});
 assert.equal(output.length,1);
 assert.ok(!JSON.stringify(output).includes('should_not_be_in_logs'));
 assert.ok(!JSON.stringify(output).includes('not-for-display'));
 const patterns=JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json',import.meta.url),'utf8'));
 assert.ok(patterns.length>=3);
 assert.ok(patterns.every(x=>x.name&&x.condition&&x.basis));
});
test('standalone offline decide classifies 6 clear, 6 suspicious, and 6 normal',async()=>{
 const code=await readFile(new URL('../xdr/known-cve/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/^\s*import\s/mu);
 assert.doesNotMatch(code,/\b(?:readFile|writeFile|fetch|require)\s*\(/u);
 const isolated=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const counts={block:0,alert:0,record:0};
 for(const [index,alert] of fixture.alerts.entries()){
  const a=isolated.decide(alert);
  assert.deepEqual(a,decide(alert));
  assert.ok(a.confidence>=0&&a.confidence<=1);
  assert.equal(a.action,index<6?'block':index<12?'alert':'record');
  assert.equal(a.action,a.confidence>=.85?'block':a.confidence>=.5?'alert':'record');
  assert.ok(typeof a.reason==='string'&&a.reason.length>3);
  counts[a.action]++;
 }
 assert.deepEqual(counts,{block:6,alert:6,record:6});
});
test('encoded and header JNDI syntax is clear, vague scanning remains alert',()=>{
 const alert=structuredClone(fixture.alerts[0]);
 alert.rule.mitre=[];
 alert.rule.level=5;
 assert.equal(decide(alert).action,'block');
 alert.data.url='/docs?topic=log4j';
 alert.rule.description='log4shell vulnerability probe';
 assert.equal(decide(alert).action,'alert');
 alert.rule.description='정상 문서 조회';alert.rule.level=2;
 assert.equal(decide(alert).action,'record');
 const sample=structuredClone(fixture.alerts[1]);
 sample.data.headers={'User-Agent':'ordinary browser'};
 sample.rule.description='로그 취약점 탐색 경보';
 assert.equal(decide(sample).action,'alert');
});
test('only high confidence CVE exploitation creates expiring evidence-linked deny rules',async()=>{
 const rows=fixture.alerts.map(alert=>({alert,decision:decide(alert),
   fixtureNormal:alert.fixture.classification==='normal'}));
 const rules=rulesFromDecisions(rows);
 assert.equal(rules.length,6);
 assert.equal(new Set(rules.map(x=>x.sourceIp)).size,6);
 for(let i=0;i<rules.length;i++){
  assert.equal(rules[i].alertId,fixture.alerts[i].id);
  assert.ok(rules[i].id.startsWith('xdr.known-cve.'));
  assert.equal(Date.parse(rules[i].expiresAt)-Date.parse(rules[i].startsAt),900000);
  assert.ok(rules[i].pattern.startsWith('log4shell-'));
 }
 assert.equal(makeRule(fixture.alerts[12],{action:'block',confidence:1,reason:'log4shell-jndi-lookup'},
  Date.parse(fixture.alerts[12].timestamp)),null);
 assert.equal(makeRule(fixture.alerts[0],decide(fixture.alerts[0]),
  Date.parse(fixture.alerts[0].timestamp)+16*60000),null);
 // A normal sample from the same IP cancels address-wide deny candidates.
 const clone=structuredClone(fixture.alerts[12]);clone.data.srcip=fixture.alerts[0].data.srcip;
 const safeRules=rulesFromDecisions([...rows,{alert:clone,decision:decide(clone),fixtureNormal:true}]);
 assert.equal(safeRules.length,5);
 const baseline={schema:'aleph.decision.v1',requestId:'synthetic',decision:'allow',
  reasonCode:'approved',ruleIds:[]};
 const guard=createGuard(async()=>baseline,async()=>rules);
 for(const sample of fixture.alerts){
  const now=Date.parse(sample.timestamp);
  const result=await guard({requestId:'synthetic'},{sourceIp:sample.data.srcip,now});
  assert.equal(result.decision,decide(sample).action==='block'?'deny':'allow');
 }
 const first=fixture.alerts[0];
 assert.deepEqual(await guard({requestId:'synthetic'},
  {sourceIp:first.data.srcip,now:Date.parse(first.timestamp)+16*60000}),baseline);
});
