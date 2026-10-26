// 격리 자식 프로세스의 합성 HTTP/PowerShell 응답을 사용하는 서버 모의 검사입니다.
// 자동 할당된 빈 루프백 포트만 사용하며 실제 5189/5191/5192 서버, WMI,
// PowerShell 수집기와 운영 SDP에는 요청하거나 명령을 실행하지 않습니다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const isolatedHarness=String.raw`
import assert from 'node:assert/strict';
import http from 'node:http';
import childProcess from 'node:child_process';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {syncBuiltinESMExports} from 'node:module';

const logicalPort=64001;
process.env.WATCHDOGS_MONITOR_PORT=String(logicalPort);
// Windows 전용 분기를 검사하기 위한 자식 프로세스 내부의 모의 값입니다.
Object.defineProperty(process,'platform',{value:'win32'});
const originalCreateServer=http.createServer;
let server;
let markReady;
const ready=new Promise(resolve=>{markReady=resolve;});
http.createServer=(...args)=>{
  server=originalCreateServer(...args);
  const originalListen=server.listen;
  server.listen=(...listenArgs)=>{
    const last=listenArgs.at(-1);
    const callback=typeof last==='function'?last:undefined;
    return originalListen.call(server,0,'127.0.0.1',callback);
  };
  server.once('listening',()=>markReady());
  return server;
};

let scenario='disconnected';
let upstreamCalls=0;
let destroyCalls=0;
http.get=(target,options,onResponse)=>{
  assert.equal(target,'http://127.0.0.1:5189/api/diagnostics');
  assert.equal(options.timeout,2500);
  upstreamCalls++;
  const selected=scenario;
  const req=new EventEmitter();
  const res=new EventEmitter();
  res.statusCode=selected==='http-error'?503:200;
  res.resume=()=>res;
  res.setEncoding=encoding=>{assert.equal(encoding,'utf8');return res;};
  let destroyed=false;
  req.destroy=()=>{
    if(destroyed)return req;
    destroyed=true;destroyCalls++;
    queueMicrotask(()=>{
      res.emit('aborted');
      res.emit('error',Object.assign(new Error('MOCK_RESPONSE_ABORTED'),{code:'ECONNRESET'}));
      res.emit('close');
    });
    return req;
  };
  queueMicrotask(()=>{
    onResponse(res);
    if(selected==='response-error'){
      res.emit('error',new Error('MOCK_RESPONSE_ERROR'));
    }else if(selected==='aborted'){
      res.emit('aborted');
      res.emit('error',Object.assign(new Error('MOCK_RESPONSE_ABORTED'),{code:'ECONNRESET'}));
    }else if(selected==='oversize'){
      res.emit('data','x'.repeat(20001));
    }else if(selected==='timeout'){
      req.emit('timeout');
    }else if(selected==='invalid-json'){
      res.emit('data','MOCK_INVALID_JSON');res.emit('end');
    }else if(selected==='disconnected'){
      res.emit('data',JSON.stringify({ok:true,data:{
        engine:{mode:'disconnected',code:'ENGINE_NOT_CONNECTED'},checkedAt:'2026-10-26T01:02:03.000Z',
      }}));
      res.emit('end');
    }
  });
  return req;
};

let spawnCalls=0;
let outputEncoding;
childProcess.spawn=(command,args,options)=>{
  assert.equal(command,'powershell.exe');
  assert.ok(args.includes('-NonInteractive'));
  assert.equal(options.windowsHide,true);
  spawnCalls++;
  const child=new EventEmitter();
  child.stdout=new PassThrough();child.stderr=new PassThrough();
  child.kill=()=>{child.stdout.destroy();child.stderr.destroy();return true;};
  const section=args[args.indexOf('-Section')+1];
  const payload={schema:'watchdogs.local-monitor.v1',section,sampleType:'measured',
    queriedAt:'2026-10-26T01:02:03.000Z',fields:{cpu:{status:'ok',value:12.5,unit:'%',
      source:'MOCK_SOURCE',measuredAt:'2026-10-26T01:02:03.000Z',reason:null,detail:'모의 한글 연결 상태'}}};
  const bytes=Buffer.from(JSON.stringify(payload),'utf8');
  const split=bytes.indexOf(Buffer.from('모의','utf8'))+1;
  assert.ok(split>0);
  child.stdout.on('end',()=>{
    outputEncoding=child.stdout.readableEncoding;
    child.emit('close',0);
  });
  queueMicrotask(()=>{
    child.stdout.write(bytes.subarray(0,split));
    queueMicrotask(()=>{child.stdout.end(bytes.subarray(split));child.stderr.end();});
  });
  return child;
};
syncBuiltinESMExports();

// 제품 시작 안내는 감추고 합성 검사의 통과 여부만 부모에게 전달합니다.
const originalWrite=process.stdout.write;
process.stdout.write=()=>true;
const results=[];
try{
  await import(process.env.WATCHDOGS_MOCK_SERVER_URL);
  await ready;
  process.stdout.write=originalWrite;
  const address=server.address();
  assert.equal(address.address,'127.0.0.1');
  assert.ok(![5189,5191,5192].includes(address.port));
  const request=(path,overrides={})=>new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port:address.port,path,method:'GET',
      headers:{Host:'127.0.0.1:'+logicalPort},...overrides},res=>{
      let body='';res.setEncoding('utf8');res.on('data',part=>{body+=part;});
      res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,body,headers:res.headers}));
    });
    req.setTimeout(2000,()=>req.destroy(new Error('MOCK_LOCAL_REQUEST_TIMEOUT')));
    req.on('error',reject);req.end();
  });
  const remainsAlive=async()=>{
    const response=await request('/');assert.equal(response.status,200);
    assert.ok(response.body.startsWith('<!doctype html>'));
  };
  for(const [selected,expectedCode] of [
    ['response-error','SDP_NOT_AVAILABLE'],['aborted','SDP_NOT_AVAILABLE'],
    ['oversize','SDP_UNVERIFIABLE'],['timeout','SDP_NOT_AVAILABLE'],
    ['invalid-json','SDP_UNVERIFIABLE'],['http-error','SDP_NOT_AVAILABLE'],
  ]){
    scenario=selected;
    const response=await request('/api/sdp');
    assert.equal(response.status,503,selected);
    const payload=JSON.parse(response.body);
    assert.equal(payload.ok,false,selected);
    assert.equal(payload.error.code,expectedCode,selected);
    assert.equal(response.headers['cache-control'],'no-store');
    await remainsAlive();
    results.push({name:selected,passed:true});
  }
  assert.equal(destroyCalls,2);
  scenario='disconnected';
  const normal=await request('/api/sdp');
  assert.equal(normal.status,200);
  assert.equal(JSON.parse(normal.body).data.mode,'disconnected');
  results.push({name:'disconnected',passed:true});
  const measured=await request('/api/pc');
  assert.equal(measured.status,200);
  const payload=JSON.parse(measured.body);
  assert.equal(payload.data.fields.cpu.detail,'모의 한글 연결 상태');
  assert.equal(outputEncoding,'utf8');
  assert.equal(spawnCalls,1);
  results.push({name:'split-utf8',passed:true});
  assert.equal(upstreamCalls,7);
  await remainsAlive();
}finally{
  process.stdout.write=originalWrite;
  if(server?.listening)await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
}
process.stdout.write(JSON.stringify({mockOnly:true,results}));
`;

test('모의 서버: 격리된 합성 응답에서 오류 복구와 UTF-8 경계를 검사한다',{timeout:15000},async t=>{
  const child=spawnSync(process.execPath,['--input-type=module','--eval',isolatedHarness],{
    encoding:'utf8',timeout:12000,windowsHide:true,
    env:{...process.env,WATCHDOGS_MOCK_SERVER_URL:new URL('./server.mjs',import.meta.url).href},
  });
  assert.equal(child.error,undefined,child.error?.message);
  assert.equal(child.status,0,child.stderr||'격리 모의 검사 종료 상태');
  const report=JSON.parse(child.stdout);
  assert.equal(report.mockOnly,true);
  assert.equal(report.results.length,8);
  const labels={
    'response-error':'진단 응답 error 뒤 503과 후속 GET 200',
    aborted:'진단 응답 aborted/error 뒤 503과 후속 GET 200',
    oversize:'크기 초과와 destroy 뒤 503과 후속 GET 200',
    timeout:'모의 시간 초과와 destroy 뒤 503과 후속 GET 200',
    'invalid-json':'잘못된 JSON 뒤 503과 후속 GET 200',
    'http-error':'원천 HTTP 실패 뒤 503과 후속 GET 200',
    disconnected:'모의 SDP 미연결을 성공 연결과 구분',
    'split-utf8':'합성 수집 stdout의 분리된 한글 UTF-8 보존',
  };
  for(const result of report.results){
    await t.test('모의 서버: '+labels[result.name],()=>assert.equal(result.passed,true));
  }
});
