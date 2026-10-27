// 합성 서버 검사: 고정 웹 Origin의 세 JSON GET만 읽을 수 있는지 검증합니다.
// 격리 자식의 HTTP upstream/PowerShell은 모의이며 실제 Windows·5189·5191에
// 요청하지 않습니다. 검사 서버는 자동 할당한 빈 루프백 포트에서만 실행합니다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const harness=String.raw`
import assert from 'node:assert/strict';
import http from 'node:http';
import childProcess from 'node:child_process';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {syncBuiltinESMExports} from 'node:module';

const productionOrigin='https://choi-bujang-secret-vault-jwnp.vercel.app';
const logicalPort=64001;
process.env.WATCHDOGS_MONITOR_PORT=String(logicalPort);
Object.defineProperty(process,'platform',{value:'win32'});
const calls={pc:0,network:0,sdp:0};
let readerFailure=false,upstreamFailure=false,server,ready;
const listening=new Promise(resolve=>{ready=resolve;});
const createServer=http.createServer;
http.createServer=(...args)=>{
  server=createServer(...args);
  const listen=server.listen;
  server.listen=(...values)=>listen.call(server,0,'127.0.0.1',
    typeof values.at(-1)==='function'?values.at(-1):undefined);
  server.once('listening',ready);
  return server;
};
http.get=(target,options,onResponse)=>{
  assert.equal(target,'http://127.0.0.1:5189/api/diagnostics');
  calls.sdp++;
  const req=new EventEmitter();req.destroy=()=>req;
  queueMicrotask(()=>{
    if(upstreamFailure){req.emit('error',new Error('MOCK_UPSTREAM_UNAVAILABLE'));return;}
    const res=new EventEmitter();res.statusCode=200;
    res.setEncoding=()=>res;res.resume=()=>res;
    onResponse(res);
    res.emit('data',JSON.stringify({ok:true,data:{engine:{mode:'disconnected',
      code:'ENGINE_NOT_CONNECTED'},checkedAt:'2026-10-27T01:02:03.000Z'}}));
    res.emit('end');
  });
  return req;
};
childProcess.spawn=(command,args,options)=>{
  assert.equal(command,'powershell.exe');assert.equal(options.windowsHide,true);
  const section=args[args.indexOf('-Section')+1];
  assert.ok(['pc','network'].includes(section));calls[section]++;
  const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();
  child.kill=()=>true;
  const field=(value,unit)=>({status:'ok',value,unit,source:'MOCK_SOURCE',
    measuredAt:'2026-10-27T01:02:03.000Z',reason:null,detail:'합성 자료'});
  const log=()=>({status:'ok',errorCount:0,warningCount:0,sampled:0,limit:1000,
    windowHours:24,source:'MOCK_SOURCE',measuredAt:'2026-10-27T01:02:03.000Z',reason:null});
  queueMicrotask(()=>{
    if(readerFailure){
      child.emit('error',new Error('MOCK_READER_UNAVAILABLE'));
      child.stdout.end();child.stderr.end();child.emit('close',1);return;
    }
    const fields=section==='pc'?{cpu:field(1,'%'),memory:field(2,'GiB'),disk:field(3,'GiB')}:
      {network:field(1,'개'),firewall:field('합성 프로필','프로필'),logs:{System:log(),Application:log()}};
    child.stdout.end(JSON.stringify({schema:'watchdogs.local-monitor.v1',section,
      sampleType:'measured',queriedAt:'2026-10-27T01:02:03.000Z',fields}));
    child.stderr.end();setImmediate(()=>child.emit('close',0));
  });
  return child;
};
syncBuiltinESMExports();
const originalWrite=process.stdout.write;
process.stdout.write=()=>true;
const results=[];
try{
  await import(process.env.WATCHDOGS_MOCK_SERVER_URL);
  await listening;
  process.stdout.write=originalWrite;
  const address=server.address();
  assert.equal(address.address,'127.0.0.1');
  assert.ok(![5189,5191,5192].includes(address.port));
  const request=(path,{method='GET',headers={}}={})=>new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port:address.port,path,method,
      headers:{Host:'127.0.0.1:'+logicalPort,...headers}},res=>{
      let body='';res.setEncoding('utf8');res.on('data',part=>{body+=part;});
      res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));
    });
    req.setTimeout(2000,()=>req.destroy(new Error('MOCK_LOCAL_REQUEST_TIMEOUT')));
    req.on('error',reject);req.end();
  });
  const webHeaders={Origin:productionOrigin,'Sec-Fetch-Site':'cross-site',Accept:'application/json'};
  function corsAllowed(res){
    assert.equal(res.headers['access-control-allow-origin'],productionOrigin);
    assert.equal(res.headers.vary,'Origin');
    assert.equal(res.headers['access-control-allow-credentials'],undefined);
    assert.equal(res.headers['access-control-allow-headers'],undefined);
    assert.equal(res.headers['access-control-allow-private-network'],undefined);
    assert.equal(res.headers['cache-control'],'no-store');
  }
  async function denied(path,options,status){
    const before=JSON.stringify(calls),res=await request(path,options);
    assert.equal(res.status,status);
    assert.equal(res.headers['access-control-allow-origin'],undefined);
    assert.equal(res.headers['access-control-allow-credentials'],undefined);
    assert.equal(JSON.stringify(calls),before,'거부 요청은 수집·upstream을 호출하지 않음');
  }
  async function check(name,run){await run();results.push(name);}
  await check('기존 로컬 화면과 CSP는 유지하고 CORS를 열지 않는다',async()=>{
    const before=JSON.stringify(calls),res=await request('/');
    assert.equal(res.status,200);assert.ok(res.body.startsWith('<!doctype html>'));
    assert.ok(res.headers['content-security-policy'].includes("connect-src 'self'"));
    assert.ok(res.headers['content-security-policy'].includes("frame-ancestors 'none'"));
    assert.equal(res.headers['access-control-allow-origin'],undefined);
    assert.equal(JSON.stringify(calls),before);
  });
  await check('기존 로컬 Origin의 GET 조회는 계속 동작한다',async()=>{
    const res=await request('/api/pc',{headers:{Origin:'http://127.0.0.1:'+logicalPort,
      'Sec-Fetch-Site':'same-origin'}});
    assert.equal(res.status,200);assert.equal(JSON.parse(res.body).ok,true);
    assert.equal(res.headers['access-control-allow-origin'],undefined);
  });
  for(const path of ['/api/pc','/api/network','/api/sdp']){
    await check('고정 웹 Origin '+path+' GET만 CORS JSON을 제공한다',async()=>{
      const before={...calls},res=await request(path,{headers:webHeaders});
      assert.equal(res.status,200);assert.equal(JSON.parse(res.body).ok,true);corsAllowed(res);
      const key=path.slice(5);
      assert.equal(calls[key],before[key]+1);
      for(const other of Object.keys(calls).filter(value=>value!==key))
        assert.equal(calls[other],before[other]);
    });
  }
  await check('다른 Origin·preview·가짜 접미사·null·대소문자 변형은 거부한다',async()=>{
    for(const origin of ['https://other.invalid','https://preview-example.vercel.app',
      productionOrigin+'.evil.invalid','null',productionOrigin+'/',productionOrigin.toUpperCase(),
      productionOrigin.replace('https:','http:')]){
      await denied('/api/pc',{headers:{...webHeaders,Origin:origin}},403);
    }
    await denied('/api/pc?query=1',{headers:{...webHeaders,Origin:'https://other.invalid'}},403);
  });
  await check('Origin 없는 cross-site 요청도 계속 거부한다',async()=>{
    await denied('/api/pc',{headers:{'Sec-Fetch-Site':'cross-site'}},403);
  });
  await check('신뢰 Origin에도 로컬 정적 파일은 제공하지 않는다',async()=>{
    for(const path of ['/','/app.js','/style.css'])await denied(path,{headers:webHeaders},403);
  });
  await check('쿼리·해시가 있는 웹 요청은 계측 전에 거부한다',async()=>{
    for(const path of ['/api/pc?query=1','/api/network?query=1','/api/sdp#fragment'])
      await denied(path,{headers:webHeaders},404);
  });
  await check('웹 요청의 잘못된 Host는 CORS 없이 거부한다',async()=>{
    for(const host of ['other.invalid:'+logicalPort,'127.0.0.1:5189'])
      await denied('/api/pc',{headers:{...webHeaders,Host:host}},403);
  });
  await check('쓰기·HEAD·OPTIONS는 세 API 모두 GET 경계에서 거부한다',async()=>{
    for(const path of ['/api/pc','/api/network','/api/sdp']){
      for(const method of ['POST','PUT','DELETE','PATCH','HEAD','OPTIONS'])
        await denied(path,{method,headers:webHeaders},405);
    }
  });
  await check('등록하지 않은 API 경로는 신뢰 Origin에도 거부한다',async()=>{
    await denied('/api/unknown',{headers:webHeaders},403);
  });
  await check('Authorization을 붙인 웹 조회는 수집 전에 거부한다',async()=>{
    await denied('/api/pc',{headers:{...webHeaders,Authorization:'synthetic-placeholder'}},403);
  });
  await check('Cookie를 붙인 웹 조회는 수집 전에 거부한다',async()=>{
    await denied('/api/pc',{headers:{...webHeaders,Cookie:'synthetic=placeholder'}},403);
  });
  for(const path of ['/api/pc','/api/network']){
    await check('모의 수집 실패 '+path+' 503도 고정 CORS로 읽을 수 있다',async()=>{
      readerFailure=true;
      try{
        const res=await request(path,{headers:webHeaders});
        assert.equal(res.status,503);assert.equal(JSON.parse(res.body).ok,false);corsAllowed(res);
      }finally{readerFailure=false;}
    });
  }
  await check('모의 SDP 원천 실패 503도 고정 CORS로 읽을 수 있다',async()=>{
    upstreamFailure=true;
    try{
      const res=await request('/api/sdp',{headers:webHeaders});
      assert.equal(res.status,503);assert.equal(JSON.parse(res.body).ok,false);corsAllowed(res);
    }finally{upstreamFailure=false;}
  });
  await check('거부와 모의 실패 뒤에도 기존 로컬 화면을 제공한다',async()=>{
    const before=JSON.stringify(calls),res=await request('/');
    assert.equal(res.status,200);assert.equal(res.headers['access-control-allow-origin'],undefined);
    assert.equal(JSON.stringify(calls),before);
  });
}finally{
  process.stdout.write=originalWrite;
  if(server?.listening)await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
}
process.stdout.write(JSON.stringify({mockOnly:true,results}));
`;

test('모의 웹 연결: 고정 Origin·세 GET·로컬 경계를 실제 HTTP 라우팅으로 검증한다',
  {timeout:15000},async t=>{
    const child=spawnSync(process.execPath,['--input-type=module','--eval',harness],{
      encoding:'utf8',timeout:12000,windowsHide:true,
      env:{SystemRoot:process.env.SystemRoot,TEMP:process.env.TEMP,TMP:process.env.TMP,
        WATCHDOGS_MOCK_SERVER_URL:new URL('./server.mjs',import.meta.url).href},
    });
    assert.equal(child.error,undefined,child.error?.message);
    assert.equal(child.status,0,child.stderr||'격리 웹 연결 모의 검사 종료 상태');
    const report=JSON.parse(child.stdout);assert.equal(report.mockOnly,true);
    assert.equal(report.results.length,18);
    for(const name of report.results)await t.test('모의 웹 연결: '+name,()=>assert.ok(name));
  });
