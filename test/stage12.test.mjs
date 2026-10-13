import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {evaluateSafeProbe,PROBES,listProbeSpecs} from '../api/war-room-check.js';
import {RULE_IDS} from '../src/decider.mjs';

test('only fixed safe probes, with normal and forbidden requests both represented',()=>{
 const specs=listProbeSpecs();
 assert.ok(specs.length>=10 && specs.length<=20);
 assert.equal(specs.length,Object.keys(PROBES).length);
 assert.ok(specs.some(x=>x.kind==='normal'&&x.expectedStatus===200));
 assert.ok(specs.some(x=>x.kind==='deny'&&x.expectedStatus===401));
 assert.ok(specs.some(x=>x.kind==='deny'&&x.expectedStatus===400));
 assert.ok(specs.every(x=>x.path.startsWith('/')&&!x.path.includes('?')));
 assert.ok(specs.every(x=>x.method==='GET'||x.method==='POST'));
});
test('real observed HTTP status is recorded with request ID and timestamp, not invented',async()=>{
 const calls=[],at='2026-10-13T06:00:00.000Z';
 const mock=async(url,options)=>{
  calls.push({url:String(url),options});
  return {status:401};
 };
 const result=await evaluateSafeProbe('anonymous_notes',mock,at);
 assert.match(result.requestId,/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
 assert.equal(result.expectedStatus,401);
 assert.equal(result.observedStatus,401);
 assert.equal(result.passed,true);
 assert.equal(result.observedAt,at);
 assert.equal(result.source,'safe_http_self_check');
 assert.equal(calls[0].url,'https://choi-bujang-secret-vault-jwnp.vercel.app/api/notes');
 assert.equal(calls[0].options.method,'GET');
 assert.equal(calls[0].options.headers['X-Request-Id'],result.requestId);
 assert.equal(calls[0].options.headers.Authorization,undefined);
});
test('an unexpected status is failure, a network error is unknown and not a pass',async()=>{
 const mismatch=await evaluateSafeProbe('public_home',async()=>({status:503}));
 assert.equal(mismatch.expectedStatus,200);
 assert.equal(mismatch.observedStatus,503);
 assert.equal(mismatch.passed,false);
 const network=await evaluateSafeProbe('anonymous_notes',async()=>{throw Error('unavailable');});
 assert.equal(network.observedStatus,null);
 assert.equal(network.passed,false);
});
test('custom URLs, unlisted cases, query injection and mutation targets cannot run',async()=>{
 for(const value of ['https://evil.example','/api/notes','../../notes',
  '__proto__','constructor','cross_owner_delete']){
  await assert.rejects(()=>evaluateSafeProbe(value,async()=>({status:200})),TypeError);
 }
 for(const spec of Object.values(PROBES)){
  assert.equal(new URL(spec.path,'https://choi-bujang-secret-vault-jwnp.vercel.app').origin,
   'https://choi-bujang-secret-vault-jwnp.vercel.app');
  assert.ok(spec.method==='GET'||spec.method==='POST');
  if(spec.method==='POST')assert.ok(spec.expected===401);
 }
});
test('operations screens do not claim live engine event count or official 41/41 PASS',async()=>{
 const root=new URL('../',import.meta.url);
 const ops=await readFile(new URL('api/war-room.js',root),'utf8');
 const view=await readFile(new URL('public/war-room.js',root),'utf8');
 assert.ok(ops.includes('observedEventCount:null'));
 assert.ok(ops.includes('engineRevocationCount:null'));
 assert.ok(ops.includes('official_41_case_results_not_connected'));
 assert.ok(view.includes('공식 41종 (과제 기준)'));
 assert.ok(!view.includes('0/41건 연동'));
 assert.ok(!ops.includes('importedJudgements:0'));
 assert.ok(ops.includes('importedJudgements:null'));
 assert.ok(ops.includes('countFromServer'));
 assert.ok(view.includes('미확인 · 서버 실측 자료 없음'));
 assert.ok(view.includes('현재 학생 계정 DB 실측'));
 assert.ok(view.includes('미확인'));
 assert.ok(!view.includes('41/41 통과'));
 assert.equal(RULE_IDS.length,4);
});
test('access controls keep dashboard login-only and app notes hidden before device approval',async()=>{
 const root=new URL('../',import.meta.url);
 const ops=await readFile(new URL('api/war-room.js',root),'utf8');
 const checks=await readFile(new URL('api/war-room-check.js',root),'utf8');
 const html=await readFile(new URL('public/index.html',root),'utf8');
 const js=await readFile(new URL('public/app.js',root),'utf8');
 assert.ok(ops.includes("if(!login)return send(res,401"));
 assert.ok(checks.includes("if(!login)return send(res,401"));
 assert.ok(checks.includes(".eq('owner_id',login.userId)"));
 assert.ok(html.includes('id="war-room"') && html.includes('hidden aria-labelledby="war-title"'));
 assert.ok(js.includes('const warRoom=mountWarRoom('));
 assert.ok(js.includes('persistSession:false'));
 assert.ok(js.includes('lockedNotes()'));
});
test('no API or protected memo content may be cached by PWA service worker',async()=>{
 const sw=await readFile(new URL('../public/sw.js',import.meta.url),'utf8');
 assert.ok(sw.includes("url.pathname.startsWith('/api/')"));
 assert.ok(!sw.includes("caches.open('notes'"));
});

test('isolated bundle records 3 judge-recognized GET/HEAD requests and marks all others not_run',async()=>{
 const {runAttackChecks}=await import('../src/attack-check.mjs');
 const {default:config}=await import('../aleph.config.json',{with:{type:'json'}});
 const previous=globalThis.fetch;
 const requests=[];
 globalThis.fetch=async(input,options={})=>{
  const url=new URL(input);
  const method=options.method??'GET';
  requests.push({path:url.pathname,method});
  assert.ok(['GET','HEAD'].includes(method),'isolated runner forbids any mutation method');
  if(url.pathname==='/api/notes')
    return new Response(JSON.stringify({error:'authentication_required'}),{
      status:401,headers:{'content-type':'application/json'},
    });
  if(url.pathname==='/aleph.json')
    return new Response(JSON.stringify({step:12,allowedRoutes:['/api/notes']}),{
      status:200,headers:{'content-type':'application/json'},
    });
  if(url.pathname==='/'&&method==='HEAD')
    return new Response(null,{
      status:200,headers:{'x-content-type-options':'nosniff'},
    });
  throw Error('unexpected uncatalogued request '+method+' '+url.pathname);
 };
 try {
  const entries=await runAttackChecks(config);
  assert.equal(config.step,12);
  assert.equal(entries.length,20);
  assert.deepEqual(requests,[
   {path:'/api/notes',method:'GET'},
   {path:'/aleph.json',method:'GET'},
   {path:'/',method:'HEAD'},
  ]);
  assert.equal(new Set(entries.map(x=>x.attackId)).size,entries.length);
  const verified=new Set(['anonymous_notes_denied','deployment_identity_step12',
   'first_page_security_header']);
  for(const entry of entries){
   if(verified.has(entry.attackId))assert.ok(entry.observed.includes('HTTP '));
   else assert.equal(entry.observed,'not_run',entry.attackId);
  }
  assert.equal(entries.filter(x=>x.observed==='not_run').length,17);
 }finally{globalThis.fetch=previous;}
});
test('failed actual GET cannot be represented as success in stage-12 bundle',async()=>{
 const {runAttackChecks}=await import('../src/attack-check.mjs');
 const {default:config}=await import('../aleph.config.json',{with:{type:'json'}});
 const previous=globalThis.fetch;
 globalThis.fetch=async(input,options={})=>{
  const u=new URL(input);
  if(u.pathname==='/')return new Response(null,{status:503});
  if(u.pathname==='/aleph.json')return new Response('{}',{status:503});
  if(u.pathname==='/api/notes')return new Response('{}',{status:200});
  throw Error('unexpected');
 };
 try{
  const checks=await runAttackChecks(config);
  for(const id of ['anonymous_notes_denied','deployment_identity_step12',
   'first_page_security_header']){
   const c=checks.find(x=>x.attackId===id);
   assert.ok(c.observed.includes('불일치')||c.observed.includes('실패'));
  }
 }finally{globalThis.fetch=previous;}
});
