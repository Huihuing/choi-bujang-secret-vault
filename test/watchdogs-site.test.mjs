import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,readdir,access,rm,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {basename,join,resolve,sep} from 'node:path';
import vm from 'node:vm';
import {buildWatchdogsAssets} from '../scripts/build-watchdogs.mjs';

const repository=new URL('../',import.meta.url);
async function fixture(t,{real=false}={}){
 const root=await mkdtemp(join(tmpdir(),'watchdogs-static-'));
 t.after(async()=>{
  assert.ok(resolve(root).startsWith(resolve(tmpdir())+sep)&&basename(root).startsWith('watchdogs-static-'));
  await rm(root,{recursive:true,force:true});
 });
 const source=join(root,'on-client','student','pc-monitor');
 await mkdir(source,{recursive:true});await mkdir(join(root,'public'));
 const html='<!doctype html><html lang="ko"><head><link href="/style.css" rel="stylesheet"><script src="/app.js" type="module"></script></head><body>WATCHDOGS</body></html>';
 const assets={};
 for(const name of ['index.html','app.js','style.css']){
  assets[name]=real?await readFile(new URL('on-client/student/pc-monitor/'+name,repository)):
   Buffer.from(name==='index.html'?html:name==='app.js'?'// static fixture':'body{color:inherit}');
  await writeFile(join(source,name),assets[name]);
 }
 return {root,source,assets,output:join(root,'public','watchdogs')};
}

test('hosted build reuses only the three student UI assets and leaves runtime data untouched',async t=>{
 const f=await fixture(t,{real:true});
 await writeFile(join(f.source,'collect.ps1'),'not a public UI asset');
 await writeFile(join(f.source,'start-watchdogs.ps1'),'not a public UI asset');
 const sentinel=Buffer.from('preserve-existing-static-data-bytes');
 await writeFile(join(f.root,'public','data.json'),sentinel);
 const result=await buildWatchdogsAssets({root:f.root});
 assert.deepEqual(result.files,['index.html','app.js','style.css']);
 assert.deepEqual((await readdir(f.output)).sort(),['app.js','index.html','style.css']);
 const html=await readFile(join(f.output,'index.html'),'utf8');
 assert.match(html,/<html\b[^>]*data-watchdogs-hosted="true"/);
 assert.match(html,/src="\/watchdogs\/app\.js"/);
 assert.match(html,/href="\/watchdogs\/style\.css"/);
 assert.doesNotMatch(html,/(?:src|href)="\/(?:app\.js|style\.css)"/);
 for(const name of ['app.js','style.css'])assert.deepEqual(await readFile(join(f.output,name)),f.assets[name]);
 assert.deepEqual(await readFile(join(f.root,'public','data.json')),sentinel);
});

test('missing or incompatible student sources fail before creating hosted output',async t=>{
 const missing=await fixture(t);
 await rm(join(missing.source,'style.css'));
 await assert.rejects(buildWatchdogsAssets({root:missing.root}),{code:'ENOENT'});
 await assert.rejects(access(missing.output),{code:'ENOENT'});
 const malformed=await fixture(t);
 await writeFile(join(malformed.source,'index.html'),'<html><body>no required asset paths</body></html>');
 await assert.rejects(buildWatchdogsAssets({root:malformed.root}),/WATCHDOGS_HTML_CONTRACT_MISMATCH/);
 await assert.rejects(access(malformed.output),{code:'ENOENT'});
 await assert.rejects(buildWatchdogsAssets({root:'.'}),/WATCHDOGS_ROOT_REQUIRED/);
});

test('hosted rebuild neither deletes unexpected output nor overwrites a linked source',async t=>{
 const f=await fixture(t);await mkdir(f.output);
 const marker=join(f.output,'keep.txt');await writeFile(marker,'keep');
 await assert.rejects(buildWatchdogsAssets({root:f.root}),/WATCHDOGS_UNEXPECTED_OUTPUT/);
 assert.equal(await readFile(marker,'utf8'),'keep');
 const linked=await fixture(t);
 const outside=join(linked.root,'private-fixture.txt');await writeFile(outside,'not a public asset');
 await rm(join(linked.source,'app.js'));await link(outside,join(linked.source,'app.js'));
 await assert.rejects(buildWatchdogsAssets({root:linked.root}),/WATCHDOGS_UNSAFE_PATH/);
 await assert.rejects(access(linked.output),{code:'ENOENT'});
});

test('hosted flag replacement is idempotent and preserves student source files',async t=>{
 const f=await fixture(t);
 const original=(await readFile(join(f.source,'index.html'),'utf8')).replace('<html lang="ko">','<html lang="ko" data-watchdogs-hosted="false">');
 await writeFile(join(f.source,'index.html'),original);
 await buildWatchdogsAssets({root:f.root});
 const first=await readFile(join(f.output,'index.html'),'utf8');
 await buildWatchdogsAssets({root:f.root});
 assert.equal(await readFile(join(f.output,'index.html'),'utf8'),first);
 assert.equal((first.match(/data-watchdogs-hosted=/g)||[]).length,1);
 assert.equal(await readFile(join(f.source,'index.html'),'utf8'),original);
});

function navigation(source,hash=''){
 const elements=new Map(),events=new Map();
 const document={activeElement:null,getElementById:id=>elements.get(id)};
 function element(id){
  const value={id,hidden:false,attributes:new Map(),children:[],
   contains(node){return this===node||this.children.includes(node);},
   setAttribute(name,text){this.attributes.set(name,text);},
   removeAttribute(name){this.attributes.delete(name);},focus(){document.activeElement=this;},
  };elements.set(id,value);return value;
 }
 for(const name of ['watchdogs','archive']){element(name+'-panel');element(name+'-tab');}
 const protectedPanel=element('create-panel');protectedPanel.hidden=true;
 const privateWar=element('war-room');privateWar.hidden=true;
 elements.get('archive-panel').children.push(protectedPanel,privateWar);
 const frame={src:'/watchdogs/',state:{selectedFilter:'network'}};
 elements.get('watchdogs-panel').children.push(frame);
 let requests=0;
 const location={hash};
 vm.runInNewContext(source,{document,location,window:{addEventListener:(name,fn)=>events.set(name,fn)},
  fetch(){requests++;throw Error('navigation must not request data');}});
 return {elements,frame,document,requests:()=>requests,navigate(hash){location.hash=hash;events.get('hashchange')();}};
}

test('menu changes only outer visibility and preserves iframe, authentication DOM and inner approval gates',async()=>{
 const source=await readFile(new URL('public/site-shell.js',repository),'utf8');
 const h=navigation(source);
 assert.equal(h.elements.get('watchdogs-panel').hidden,false);
 assert.equal(h.elements.get('archive-panel').hidden,true);
 assert.equal(h.elements.get('watchdogs-tab').attributes.get('aria-current'),'page');
 const frame=h.frame,gate=h.elements.get('create-panel');
 h.navigate('#archive');
 assert.equal(h.elements.get('archive-panel').hidden,false);
 assert.equal(h.elements.get('watchdogs-panel').hidden,true);
 assert.equal(h.elements.get('archive-tab').attributes.get('aria-current'),'page');
 assert.equal(gate.hidden,true);assert.equal(h.elements.get('war-room').hidden,true);
 h.document.activeElement=gate;h.navigate('#watchdogs');
 assert.equal(h.document.activeElement,h.elements.get('watchdogs-tab'));
 assert.equal(h.frame,frame);assert.equal(h.frame.src,'/watchdogs/');
 assert.equal(h.frame.state.selectedFilter,'network');
 assert.equal(h.elements.get('create-panel'),gate);assert.equal(gate.hidden,true);
 assert.equal(h.requests(),0);
 const deepLink=navigation(source,'#archive');
 assert.equal(deepLink.elements.get('archive-panel').hidden,false);
});

test('combined HTML retains all existing auth, notes and public evidence hooks exactly once',async()=>{
 const html=await readFile(new URL('public/index.html',repository),'utf8');
 for(const id of ['login-form','logout-button','device-panel','device-request','device-refresh',
  'notes','create-panel','create-form','war-public','war-public-evidence','war-room','war-probes']){
  assert.equal((html.match(new RegExp('id="'+id+'"','g'))||[]).length,1,id);
 }
 assert.match(html,/<section id="archive-panel" hidden/);
 assert.match(html,/<iframe[^>]*src="\/watchdogs\/"[^>]*title=/);
 assert.match(html,/\.watchdogs-frame\{[^}]*min-height:560px/);
 for(const path of ['/site-shell.js','/app.js','/war-summary.js'])assert.ok(html.includes('src="'+path+'"'));
 assert.ok(html.includes('hidden aria-labelledby="war-title"'));
 assert.ok(html.includes('id="create-panel" class="card wide" hidden'));
 assert.ok(html.includes('STEP 12'));assert.ok(!html.includes('STEP 11'));
});

test('service worker falls back only for static hosted shell and bypasses APIs, data and loopback',async()=>{
 const source=await readFile(new URL('public/sw.js',repository),'utf8');
 const events=new Map(),cached=[];
 vm.runInNewContext(source,{URL,self:{location:{origin:'https://site.test'},addEventListener:(name,fn)=>events.set(name,fn)},
  fetch:async()=>{throw Error('synthetic offline');},caches:{match:async request=>{cached.push(request.url);return {staticShell:true};}}});
 const dispatch=url=>{
  let pending;
  events.get('fetch')({request:{url},respondWith:value=>{pending=value;}});
  return pending;
 };
 for(const url of ['https://site.test/api/notes','https://site.test/api/pc',
  'https://site.test/aleph.json','https://site.test/data.json','http://127.0.0.1:5191/api/pc']){
  assert.equal(dispatch(url),undefined,url);
 }
 for(const path of ['/site-shell.js','/watchdogs/','/watchdogs/index.html','/watchdogs/app.js','/watchdogs/style.css']){
  assert.equal((await dispatch('https://site.test'+path)).staticShell,true,path);
 }
 assert.equal(cached.length,5);
});

test('combined PWA keeps its installed identity, start URL, scope and icon routes',async()=>{
 const manifest=JSON.parse(await readFile(new URL('public/manifest.webmanifest',repository),'utf8'));
 assert.equal(manifest.id,'/');assert.equal(manifest.start_url,'/');assert.equal(manifest.scope,'/');
 assert.equal(manifest.name,'WATCHDOGS + BYTE BACK');
 assert.deepEqual(manifest.icons.map(item=>item.src),['/icon-192.png','/icon-512.png','/icon.svg']);
 const build=await readFile(new URL('scripts/build-public.mjs',repository),'utf8');
 assert.ok(build.includes('await buildWatchdogsAssets({root})'));
 const ignored=await readFile(new URL('.gitignore',repository),'utf8');
 assert.ok(ignored.split(/\r?\n/).includes('/public/watchdogs/'));
});

test('watchdogs activity records scroll inside a bounded keyboard-focusable list',async()=>{
 const html=await readFile(new URL('on-client/student/pc-monitor/index.html',repository),'utf8');
 const css=await readFile(new URL('on-client/student/pc-monitor/style.css',repository),'utf8');
 assert.match(html,/<ol id="timeline-list" class="timeline-list" tabindex="0" aria-label="조회 완료 최신순 기록"><\/ol>/);
 assert.match(css,/\.timeline-list\{[^}]*max-height:min\(65vh,600px\)/);
 assert.match(css,/\.timeline-list\{[^}]*overflow-y:auto/);
 assert.match(css,/\.timeline-list\{[^}]*scrollbar-gutter:stable/);
 assert.match(css,/@media\(max-width:700px\)\{[^]*?\.timeline-list\{max-height:min\(58vh,480px\)\}/);
});
