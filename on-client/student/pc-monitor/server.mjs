// 워치독스의 읽기 전용 Windows 측정 동반 서비스.
// 제공 보안 Agent 서버, 로그인, OS 보안 설정을 수정하지 않는다.
import http from 'node:http';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.WATCHDOGS_MONITOR_PORT ?? 5191);
if (!Number.isSafeInteger(port) || port < 1024 || port > 65535 || port === 5189) {
  throw new Error('WATCHDOGS_MONITOR_PORT_INVALID');
}
const allowedHost = new Set(['127.0.0.1:' + port, 'localhost:' + port]);
const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
]);
const sectionPaths = new Map([['/api/pc','pc'],['/api/network','network']]);
const safeHeader = {
  'Cache-Control':'no-store',
  'X-Content-Type-Options':'nosniff',
  'Referrer-Policy':'no-referrer',
  'X-Frame-Options':'DENY',
  'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};
const respond=(res,status,data)=> {
  res.writeHead(status,{...safeHeader,'Content-Type':'application/json; charset=utf-8'});
  res.end(JSON.stringify(data));
};
const failure=(code,message)=>({ok:false,error:{code,message}});
const active=new Set();

function collect(section){
  if (process.platform !== 'win32') return Promise.resolve(failure('WINDOWS_ONLY','Windows PC에서만 실측할 수 있습니다.'));
  if (active.has(section)) return Promise.resolve(failure('BUSY','이미 조회 중입니다. 완료 후 다시 조회하세요.'));
  active.add(section);
  return new Promise(resolve=>{
    let settled=false, out='', timedOut=false;
    let child;
    const finish=result=>{
      if(settled)return;
      settled=true;clearTimeout(timer);active.delete(section);resolve(result);
    };
    try {
      child=spawn('powershell.exe',[
        '-NoLogo','-NoProfile','-NonInteractive',
        '-ExecutionPolicy','Bypass',
        '-File',join(here,'collect.ps1'),'-Section',section,
      ],{windowsHide:true,cwd:here,stdio:['ignore','pipe','pipe']});
    } catch {
      active.delete(section);
      resolve(failure('READER_UNAVAILABLE','읽기 전용 PowerShell 측정 도구를 시작하지 못했습니다.'));
      return;
    }
    const timer=setTimeout(()=>{
      timedOut=true;
      child.kill();
      finish(failure('MEASURE_TIMEOUT','측정 시간이 초과됐습니다. 현재 값은 확인 불가입니다.'));
    },section==='network'?25000:15000);
    child.stdout.on('data',part=>{
      out+=part.toString('utf8');
      if(out.length>100000){
        child.kill();
        finish(failure('RESPONSE_LIMIT','측정 결과 크기 제한을 초과해 표시하지 않습니다.'));
      }
    });
    // stderr를 브라우저/문서로 전달하지 않아 사용자 계정·경로가 노출되지 않게 한다.
    child.stderr.on('data',()=>{});
    child.on('error',()=>finish(failure('READER_UNAVAILABLE','PowerShell 측정 기능을 호출하지 못했습니다.')));
    child.on('close',code=>{
      if(timedOut||settled)return;
      if(code!==0)return finish(failure('MEASURE_FAILED','일부 측정 도구를 실행할 수 없습니다. 관리자 권한으로 변경하지 마세요.'));
      let parsed;
      try {parsed=JSON.parse(out.trim());}catch{return finish(failure('INVALID_MEASUREMENT','측정 자료 형식이 올바르지 않습니다. 값을 표시하지 않습니다.'));}
      if(parsed?.schema!=='watchdogs.local-monitor.v1'||parsed?.section!==section
         ||parsed?.sampleType!=='measured'||!parsed?.fields||typeof parsed.fields!=='object'){
        return finish(failure('INVALID_MEASUREMENT','측정 자료 계약이 맞지 않아 확인 불가로 처리합니다.'));
      }
      finish({ok:true,data:parsed});
    });
  });
}
async function checkSdp(){
  return new Promise(resolve=>{
    const target='http://127.0.0.1:5189/api/diagnostics';
    let done=false,body='';
    const finish=data=>{if(!done){done=true;resolve(data);}};
    const req=http.get(target,{timeout:2500,headers:{Accept:'application/json'}},res=>{
      if(res.statusCode!==200){res.resume();return finish(failure('SDP_NOT_AVAILABLE','기존 보안 Agent의 진단 응답을 확인할 수 없습니다.'));}
      res.setEncoding('utf8');
      res.on('data',chunk=>{
        body+=chunk;
        if(body.length>20000){req.destroy();finish(failure('SDP_UNVERIFIABLE','진단 자료 크기가 예상 범위를 벗어납니다.'));}
      });
      res.on('end',()=>{
        if(done)return;
        let parsed;
        try{parsed=JSON.parse(body);}catch{return finish(failure('SDP_UNVERIFIABLE','진단 응답 형식을 확인할 수 없습니다.'));}
        const mode=parsed?.data?.engine?.mode;
        const code=parsed?.data?.engine?.code;
        const t=parsed?.data?.checkedAt;
        if(parsed?.ok!==true||!['connected','disconnected','demo'].includes(mode)||typeof t!=='string'||!Number.isFinite(Date.parse(t))){
          return finish(failure('SDP_UNVERIFIABLE','기존 보안 Agent 연결 상태를 검증할 수 없습니다.'));
        }
        const text=mode==='disconnected'&&code==='ENGINE_NOT_CONNECTED'?'SDP 미연결':
          mode==='demo'?'예제(demo) · 실제 SDP 연결 아님':
          mode==='connected'?'SDP 어댑터 구성됨 · 실제 사용자 인증 및 운영 동작은 별도 확인':
          '확인 불가';
        finish({ok:true,data:{mode,label:text,checkedAt:t,source:'on-client /api/diagnostics'}});
      });
    });
    req.on('timeout',()=>req.destroy());
    req.on('error',()=>finish(failure('SDP_NOT_AVAILABLE','기존 보안 Agent(5189)를 읽지 못했습니다. SDP 연결 성공으로 간주하지 않습니다.')));
  });
}

const server=http.createServer(async(req,res)=>{
  const host=(req.headers.host||'').toLowerCase();
  if(!allowedHost.has(host)){
    respond(res,403,failure('LOOPBACK_ONLY','허용되지 않은 접근입니다.'));return;
  }
  const origin=req.headers.origin;
  if(origin&&!allowedHost.has(origin.replace(/^https?:\/\//i,'').toLowerCase())){
    respond(res,403,failure('ORIGIN_REJECTED','교차 출처 접근을 허용하지 않습니다.'));return;
  }
  if(req.headers['sec-fetch-site']==='cross-site'){
    respond(res,403,failure('ORIGIN_REJECTED','다른 사이트의 조회 요청을 허용하지 않습니다.'));return;
  }
  if(req.method!=='GET'){
    respond(res,405,failure('METHOD_NOT_ALLOWED','읽기 전용 GET 조회만 지원합니다.'));return;
  }
  let path;
  try {const u=new URL(req.url,'http://127.0.0.1:'+port);if(u.search||u.hash)throw Error('QUERY');path=u.pathname;}
  catch{return respond(res,404,failure('NOT_FOUND','지원하지 않는 조회입니다.'));}
  if(files.has(path)){
    const [name,type]=files.get(path);
    try {
      const body=await readFile(join(here,name));
      res.writeHead(200,{...safeHeader,'Content-Type':type});res.end(body);
    }catch{respond(res,503,failure('UI_UNAVAILABLE','화면 파일을 읽지 못했습니다.'));}
    return;
  }
  if(sectionPaths.has(path)){
    const result=await collect(sectionPaths.get(path));
    return respond(res,result.ok?200:503,result);
  }
  if(path==='/api/sdp'){
    const result=await checkSdp();
    return respond(res,result.ok?200:503,result);
  }
  respond(res,404,failure('NOT_FOUND','지원하지 않는 주소입니다.'));
});
server.requestTimeout=10000;
server.headersTimeout=9000;
server.listen(port,'127.0.0.1',()=>{
  process.stdout.write('워치독스 PC 읽기 전용 측정 화면: http://127.0.0.1:'+port+'/\n');
  process.stdout.write('측정은 화면에서 「다시 조회」를 누를 때만 실행합니다. 종료: Ctrl+C\n');
});
