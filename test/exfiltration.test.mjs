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
test('standalone offline detector yields 6 block / 6 alert / 6 record',async()=>{
 const code=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/^\s*import\s/mu);
 assert.doesNotMatch(code,/\b(?:readFile|writeFile|fetch|require)\s*\(/u);
 const isolated=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
 const counts={block:0,alert:0,record:0};
 for(const alert of events){
  const actual=isolated.decide(alert);
  assert.deepEqual(actual,decide(alert));
  assert.equal(actual.action,alert.fixture.classification==='normal'?'record':alert.fixture.classification,alert.id);
  assert.equal(actual.action,actual.confidence>=.85?'block':actual.confidence>=.5?'alert':'record');
  counts[actual.action]++;
 }
 assert.deepEqual(counts,{block:6,alert:6,record:6});
});
test('destination block limited to trusted gateway IP, clear evidence and expiry',async()=>{
 const rows=events.map(alert=>({alert,decision:decide(alert),fixtureNormal:alert.fixture.classification==='normal'}));
 const rules=rulesFromDecisions(rows);
 assert.equal(rules.length,6);
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


test('Wazuh alias fields, localized descriptions and transfer-size units',()=>{
 const samples=[
  {rule:{level:7},data:{dest_ip:'203.0.113.41',direction:'outbound',transfer_size_mb:500,destination_first_seen:true}},
  {rule:{level:8,description:'처음 보는 외부 주소로 대용량 파일 전송'},data:{dst_ip:'203.0.113.42'}},
  {rule:{level:12,mitre:{id:['T1048']},description:'External outbound archive upload outside business hours'},
   data:{dest_ip:'203.0.113.43',bytes_sent:'750 MB',filename:'records.zip',approved:false}},
 ];
 for(const sample of samples)assert.equal(decide(sample).action,'block');
 const newDestination={rule:{level:7,description:'Outbound upload to a new external destination'},
  data:{dstip:'203.0.113.44',bytes_sent:1200}};
 assert.equal(decide(newDestination).action,'alert');
});
test('approved transfers and inbound traffic must not be blocked',()=>{
 const approved={rule:{level:12,mitre:['T1041'],description:'Approved scheduled backup to external destination'},
  data:{dstip:'203.0.113.52',bytes_sent:1e9,newDestination:true,approved:true}};
 const inbound={rule:{level:12,mitre:['T1041'],description:'New large transfer involving external address'},
  data:{dstip:'203.0.113.53',bytes_out:1e9,newDestination:true,direction:'inbound'}};
 assert.equal(decide(approved).action,'record');
 assert.equal(decide(inbound).action,'record');
});


test('baseline membership is not proof of explicit authorization',()=>{
 const caseFile={
  rule:{level:11,mitre:['T1048'],description:'Large outbound transfer to first-seen destination'},
  data:{dstip:'203.0.113.91',bytes_sent:250*1048576,newDestination:true,baselineKnown:true}
 };
 assert.equal(decide(caseFile).action,'block');
});
test('relative volume, nested destination aliases and Japanese/Korean-style time markers',()=>{
 const comparison={
  rule:{level:6},data:{dest_ip:'203.0.113.92',bytes_out:40*1048576,
   baselineBytes:3*1048576,firstSeen:true,direction:'outbound'}
 };
 assert.equal(decide(comparison).action,'block');
 const event={id:'ex-alias-01',timestamp:'2026-10-14T03:00:00Z',
  rule:{level:9,description:'처음 보는 외부 주소로 대용량 파일 전송'},
  data:{dest_ip:'203.0.113.93'}};
 const decision=decide(event);
 assert.equal(decision.action,'block');
 const rule=makeRule(event,decision,Date.parse(event.timestamp));
 assert.equal(rule.destinationIp,'203.0.113.93');
 assert.equal(rule.alertId,'ex-alias-01');
});
test('unknown or approved-only evidence never turns into a block',()=>{
 const tagOnly={rule:{level:2,mitre:['T1041'],description:'Routine outbound transfer'},
 data:{dstip:'203.0.113.95',bytes_sent:1024}};
 assert.equal(decide(tagOnly).action,'record');
 const confirmed={rule:{level:12,mitre:['T1048'],description:'Approved external archive transfer after hours'},
 data:{dstip:'203.0.113.96',newDestination:true,bytes_sent:250*1048576,approved:true}};
 assert.equal(decide(confirmed).action,'record');
});
