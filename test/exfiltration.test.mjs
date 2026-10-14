import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decide} from '../xdr/exfiltration/decide.mjs';
import {readAlerts,parseAlerts} from '../xdr/exfiltration/read-alerts.mjs';
import {makeRule,rulesFromDecisions,createDestinationGuard} from '../xdr/exfiltration/respond.mjs';
const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json',import.meta.url),'utf8'));
const events=fixture.alerts;
test('read all sanitized Wazuh alerts and evidence based patterns',async()=>{
 assert.equal((await readAlerts()).length,events.length);
 const sample=structuredClone(events[0]);
 sample.rule.description='Outbound token=SECRET password=HIDDEN upload';
 const rows=parseAlerts({alerts:[sample]});
 assert.deepEqual(Object.keys(rows[0]),['time','sourceIp','account','ruleLevel','description']);
 assert.ok(!JSON.stringify(rows).includes('SECRET'));
 assert.ok(!JSON.stringify(rows).includes('HIDDEN'));
 const patterns=JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json',import.meta.url),'utf8'));
 assert.ok(patterns.length>=3&&patterns.every(p=>p.name&&p.condition&&p.basis));
});
test('standalone offline detector yields 10 block / 10 alert / 10 record',async()=>{
 const code=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/^\s*import\s/mu);
 assert.doesNotMatch(code,/\b(?:readFile|writeFile|fetch|require)\s*\(/u);
 const isolated=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const counts={block:0,alert:0,record:0};
 for(const alert of events){
  const actual=isolated.decide(alert);
  assert.deepEqual(actual,decide(alert));
  const expected=events.indexOf(alert)<10?'block':events.indexOf(alert)<20?'alert':'record';
  assert.equal(actual.action,expected,alert.id);
  assert.equal(actual.action,actual.confidence>=.85?'block':actual.confidence>=.5?'alert':'record');
  counts[actual.action]++;
 }
 assert.deepEqual(counts,{block:10,alert:10,record:10});
});
test('destination block limited to trusted gateway IP, clear evidence and expiry',async()=>{
 const rows=events.map(alert=>({alert,decision:decide(alert),fixtureNormal:Number(alert.id.slice(3))>=21}));
 const rules=rulesFromDecisions(rows);
 assert.equal(rules.length,10);
 assert.ok(rules.every(x=>x.alertId&&x.destinationIp&&Date.parse(x.expiresAt)-Date.parse(x.startsAt)===900000));
 const baseline={schema:'aleph.decision.v1',requestId:'r',decision:'allow',reasonCode:'approved',ruleIds:[]};
 const guard=createDestinationGuard(async()=>baseline,async()=>rules);
 const sample=events[0],at=Date.parse(sample.timestamp);
 assert.equal((await guard({requestId:'r'},{destinationIp:sample.data.dstip,now:at})).decision,'deny');
 assert.deepEqual(await guard({requestId:'r'},{destinationIp:events[12].data.dstip,now:at}),baseline);
 assert.deepEqual(await guard({requestId:'r'},{destinationIp:sample.data.dstip,now:at+16*60000}),baseline);
 assert.deepEqual(await guard({requestId:'r',destinationIp:sample.data.dstip},{now:at}),baseline);
 assert.equal(makeRule(events[12],{action:'block',confidence:1,reason:'new-destination-bulk-exfiltration'},Date.parse(events[12].timestamp)),null);
 assert.equal(makeRule(events[6],{action:'block',confidence:1,reason:'new-destination-bulk-exfiltration'},Date.parse(events[6].timestamp)),null);
});
test('incomplete Wazuh records cannot block',()=>{
 for(const a of [null,undefined,{},[],{data:{dstip:'8.8.8.8'}},
 {rule:{level:15,mitre:['T1041']}},{rule:{level:15,mitre:['T1041']},data:{dstip:'192.168.1.2',bytes_sent:999999999,newDestination:true}}]){
  assert.notEqual(decide(a).action,'block');
 }
});



test('real 30-alert Wazuh fixture, all three behavior groups and expiry',()=>{
 assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
 assert.equal(events.length,30);
 assert.equal(events[0].data.bytes,'240000000');
 assert.equal(events[19].rule.description.includes('압축 파일'),true);
 const results=events.map(x=>decide(x).action);
 assert.deepEqual({block:results.filter(x=>x==='block').length,
  alert:results.filter(x=>x==='alert').length,record:results.filter(x=>x==='record').length},
  {block:10,alert:10,record:10});
});
test('evidence cannot be replaced by a high level or T1041 tag',()=>{
 const baseline={rule:{level:12,mitre:['T1041'],description:'Routine report'},
  data:{dstip:'203.0.113.12',bytes:'2000'}};
 const incomplete={rule:{level:12,mitre:['T1048'],description:'File transfer was attempted'},
  data:{dstip:'203.0.113.13',bytes:'0'}};
 assert.notEqual(decide(baseline).action,'block');
 assert.notEqual(decide(incomplete).action,'block');
});
test('large approved transfer, internal-only destination and inbound traffic stay non-blocking',()=>{
 const approved={rule:{level:12,mitre:['T1048'],description:'Approved outbound archive to a first-seen destination'},
  data:{dstip:'203.0.113.21',bytes:'500000000',files:'200',approved:true}};
 const internal={rule:{level:12,mitre:['T1048'],description:'10분 안에 자료 200건이 처음 보는 목적지로 나갔습니다.'},
  data:{dstip:'10.1.2.3',bytes:'500000000',files:'200'}};
 const inbound={rule:{level:12,description:'10분 안에 자료 200건이 처음 보는 목적지로 나갔습니다.'},
  data:{dstip:'203.0.113.21',bytes:'500000000',files:'200',direction:'inbound'}};
 assert.equal(decide(approved).action,'record');
 assert.notEqual(decide(internal).action,'block');
 assert.equal(decide(inbound).action,'record');
});
test('parsed transfer fields can independently support review',()=>{
 const near={rule:{level:6,description:'New destination transfer'},data:{dstip:'203.0.113.17',bytes:1500000}};
 assert.equal(decide(near).action,'alert');
 const normal={rule:{level:3,mitre:['T1048'],description:'Small class sync'},
 data:{dstip:'198.51.100.10',bytes:'20000',files:'3'}};
 assert.equal(decide(normal).action,'record');
});
