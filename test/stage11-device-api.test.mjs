// API 행동 모의 검사: 로그인·DB·자료 API만 격리된 합성 응답으로 대체합니다.
// WebAuthn 공개키 해석과 서명 검증은 제품 함수를 그대로 실행합니다.
// OpenSSL 합성 키는 자식 프로세스 메모리에만 있으며 저장하지 않습니다.
// 실제 계정·DB·Windows 인증기·네트워크·운영 승인 검증이 아닙니다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

async function runMockSuite(){
  const {registerHooks}=await import('node:module');
  const {constants,generateKeyPairSync,sign}=await import('node:crypto');
  const {sha256,digestBody}=await import('../src/app-webauthn.mjs');
  const {APP_APPROVED}=await import('../src/app-approval.mjs');
  const origin='https://stage11-api-mock.invalid';
  const rpID=new URL(origin).hostname;
  const owner='11111111-1111-4111-8111-111111111111';
  const challengeId='22222222-2222-4222-8222-222222222222';
  const target={method:'GET',path:'/api/notes',body:null};
  let state;
  let networkCalls=0;
  const denyNetwork=()=>{networkCalls++;throw Error('MOCK_NETWORK_FORBIDDEN');};
  globalThis.fetch=denyNetwork;
  for(const moduleName of ['node:http','node:https']){
    const module=(await import(moduleName)).default;
    module.request=denyNetwork;module.get=denyNetwork;
  }
  const net=(await import('node:net')).default;
  net.connect=denyNetwork;net.createConnection=denyNetwork;

  function reset(){
    state={login:{kind:'student',userId:owner},devices:[],queries:[],rpcs:[],
      challenges:new Map(),deviceInserts:[],delegations:[],beforeUpdate:null};
    globalThis.__stage11ApiMock={
      createClient:()=>client,
      verifyLogin:async()=>state.login,
      delegate:(req,res)=>{
        state.delegations.push({approved:req[APP_APPROVED]===true,
          method:req.method,path:req.url,body:req.body});
        return res.status(200).json({mockResource:true});
      },
    };
  }
  function project(row,columns){
    if(!columns||columns==='*')return {...row};
    return Object.fromEntries(columns.split(',').map(key=>[key,row[key]]));
  }
  function execute(query){
    state.queries.push(query);
    if(query.table==='app_device_challenges'&&query.operation==='insert'){
      state.challenges.set(challengeId,{...query.values});
      return{data:{id:challengeId},error:null};
    }
    if(query.table!=='app_devices')throw Error('MOCK_UNEXPECTED_TABLE');
    if(query.operation==='insert'){
      state.deviceInserts.push({...query.values});state.devices.push({...query.values});
      return{data:null,error:null};
    }
    if(query.operation==='update'&&state.beforeUpdate){
      const before=state.beforeUpdate;state.beforeUpdate=null;before();
    }
    const matches=state.devices.filter(row=>query.filters.every(([kind,key,value])=>
      kind==='eq'?row[key]===value:row[key]!==value));
    if(query.operation==='update')for(const row of matches)Object.assign(row,query.values);
    const selected=matches.map(row=>project(row,query.columns));
    return{data:query.single?selected[0]??null:selected,error:null};
  }
  const client={
    from(table){
      const query={table,operation:'select',columns:null,filters:[],single:false};
      const builder={
        select(columns){query.columns=columns;return this;},
        insert(values){query.operation='insert';query.values=values;return this;},
        update(values){query.operation='update';query.values=values;return this;},
        eq(key,value){query.filters.push(['eq',key,value]);return this;},
        neq(key,value){query.filters.push(['neq',key,value]);return this;},
        order(){return this;},
        single(){query.single=true;return Promise.resolve(execute(query));},
        maybeSingle(){query.single=true;return Promise.resolve(execute(query));},
        then(resolve,reject){return Promise.resolve().then(()=>execute(query)).then(resolve,reject);},
      };
      return builder;
    },
    async rpc(name,args){
      state.rpcs.push({name,args});assert.equal(name,'stage11_consume_challenge');
      const value=state.challenges.get(args.p_id);
      if(!value||value.owner_id!==args.p_owner_id||value.purpose!==args.p_purpose)
        return{data:null,error:null};
      state.challenges.delete(args.p_id);return{data:{...value},error:null};
    },
  };
  const deviceUrl=new URL('../api/device.js',import.meta.url).href;
  const requestUrl=new URL('../api/app-request.js',import.meta.url).href;
  const delegatedModules=new Set(['./notes.js','./notes/[id].js',
    './instructor-notices.js','./instructor-notices/[id].js']);
  registerHooks({
    resolve(specifier,context,nextResolve){
      if([deviceUrl,requestUrl].includes(context.parentURL)){
        let name;
        if(specifier==='@supabase/supabase-js')name='db';
        if(specifier==='../aleph.config.json')name='config';
        if(specifier==='../src/verify-login.mjs')name='login';
        if(context.parentURL===requestUrl&&delegatedModules.has(specifier))name='resource';
        if(name)return{url:'stage11-api-mock:'+name,shortCircuit:true};
      }
      return nextResolve(specifier,context);
    },
    load(url,context,nextLoad){
      if(url==='stage11-api-mock:config')return{format:'json',shortCircuit:true,
        source:JSON.stringify({publicAppUrl:origin+'/'} )};
      const sources={
        'stage11-api-mock:db':'export const createClient=(...args)=>globalThis.__stage11ApiMock.createClient(...args);',
        'stage11-api-mock:login':'export const createLoginVerifier=()=> (...args)=>globalThis.__stage11ApiMock.verifyLogin(...args);',
        'stage11-api-mock:resource':'export default (req,res)=>globalThis.__stage11ApiMock.delegate(req,res);',
      };
      if(sources[url])return{format:'module',source:sources[url],shortCircuit:true};
      return nextLoad(url,context);
    },
  });
  reset();
  const {default:device}=await import(deviceUrl);
  const {default:appRequest}=await import(requestUrl);
  function response(){
    return{statusCode:null,body:null,headers:{},
      status(value){this.statusCode=value;return this;},
      setHeader(name,value){this.headers[name]=value;return this;},
      json(value){this.body=value;return this;},
    };
  }
  async function invoke(handler,url,body,method='POST'){
    const res=response();await handler({method,url,body,headers:{}},res);return res;
  }
  const callDevice=(body,method)=>invoke(device,'/api/device',body,method);
  const callRequest=body=>invoke(appRequest,'/api/app-request',body);
  const b64=value=>Buffer.from(value).toString('base64url');
  function head(major,length){
    if(length<24)return Buffer.from([(major<<5)|length]);
    if(length<256)return Buffer.from([(major<<5)|24,length]);
    if(length<65536)return Buffer.from([(major<<5)|25,length>>8,length&255]);
    throw Error('MOCK_CBOR_LENGTH');
  }
  function cbor(value){
    if(Number.isInteger(value))return head(value<0?1:0,value<0?-1-value:value);
    if(Buffer.isBuffer(value))return Buffer.concat([head(2,value.length),value]);
    if(typeof value==='string'){
      const bytes=Buffer.from(value);return Buffer.concat([head(3,bytes.length),bytes]);
    }
    if(value instanceof Map)return Buffer.concat([head(5,value.size),
      ...[...value].flatMap(([key,item])=>[cbor(key),cbor(item)])]);
    throw Error('MOCK_CBOR_TYPE');
  }
  // 합성 키는 자식 프로세스 메모리 안에만 있으며 Windows 키 공급자는 호출하지 않습니다.
  const rsaPair=generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
  const ecPair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const rsa=rsaPair.publicKey.export({format:'jwk'});
  const ec=ecPair.publicKey.export({format:'jwk'});
  const credentialId=b64(Buffer.from('synthetic-stage11-credential'));
  function authData(flags=5,count=1){
    const bytes=Buffer.alloc(37);sha256(rpID).copy(bytes);bytes[32]=flags;
    bytes.writeUInt32BE(count,33);return bytes;
  }
  function clientData(type,challenge,site=origin){
    return Buffer.from(JSON.stringify({type,challenge,origin:site,crossOrigin:false}));
  }
  function registration(algorithm,challenge,{site=origin,flags=0x45}={}){
    const publicKey=algorithm===-257?new Map([
      [1,3],[3,-257],[-1,Buffer.from(rsa.n,'base64url')],[-2,Buffer.from(rsa.e,'base64url')],
    ]):new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(ec.x,'base64url')],[-3,Buffer.from(ec.y,'base64url')]]);
    const id=Buffer.from(credentialId,'base64url');
    const length=Buffer.alloc(2);length.writeUInt16BE(id.length);
    const data=Buffer.concat([authData(flags,0),Buffer.alloc(16),length,id,cbor(publicKey)]);
    return{id:credentialId,rawId:credentialId,type:'public-key',response:{
      clientDataJSON:b64(clientData('webauthn.create',challenge,site)),
      attestationObject:b64(cbor(new Map([['fmt','none'],['attStmt',new Map()],['authData',data]]))),
    }};
  }
  function approvedCredential(algorithm=-257,{legacy=false,status='approved'}={}){
    return{owner_id:owner,credential_id:credentialId,status,sign_count:0,
      ...(!legacy?{key_algorithm:algorithm}:{}),
      ...(algorithm===-257?{public_x:null,public_y:null,public_n:rsa.n,public_e:rsa.e}:
        {public_x:ec.x,public_y:ec.y}),
    };
  }
  function proof(algorithm,challenge,{flags=5,count=1,corrupt=false}={}){
    const data=authData(flags,count),json=clientData('webauthn.get',challenge);
    const key=algorithm===-257?{key:rsaPair.privateKey,padding:constants.RSA_PKCS1_PADDING}:ecPair.privateKey;
    const signature=sign('sha256',Buffer.concat([data,sha256(json)]),key);
    if(corrupt)signature[0]^=1;
    return{id:credentialId,rawId:credentialId,type:'public-key',response:{
      clientDataJSON:b64(json),authenticatorData:b64(data),signature:b64(signature),
    }};
  }
  async function beginRequest(credential=approvedCredential()){
    state.devices.push(credential);
    const res=await callRequest({action:'begin',target});assert.equal(res.statusCode,200);
    return res.body;
  }
  async function executeRequest(beginning,assertion,overrideTarget=target){
    return callRequest({action:'execute',target:overrideTarget,
      challengeId:beginning.challengeId,proof:assertion});
  }
  const results=[];
  async function check(name,run){reset();await run();results.push(name);}

  await check('등록 begin은 두 알고리즘과 platform·UV 필수를 유지한다',async()=>{
    state.devices.push(approvedCredential(-257),{...approvedCredential(-7),credential_id:'revoked-mock',status:'revoked'});
    const res=await callDevice({action:'begin'});assert.equal(res.statusCode,200);
    assert.deepEqual(res.body.options.pubKeyCredParams,[{type:'public-key',alg:-7},{type:'public-key',alg:-257}]);
    assert.deepEqual(res.body.options.authenticatorSelection,{authenticatorAttachment:'platform',
      residentKey:'discouraged',userVerification:'required'});
    assert.equal(res.body.options.attestation,'none');
    assert.deepEqual(res.body.options.excludeCredentials,[{type:'public-key',id:credentialId}]);
    assert.equal(state.deviceInserts.length,0);
  });
  await check('RSA finish는 검증된 공개 n/e와 -257을 pending으로만 저장한다',async()=>{
    const beginning=await callDevice({action:'begin'});
    const res=await callDevice({action:'finish',challengeId:beginning.body.challengeId,
      response:registration(-257,beginning.body.options.challenge)});
    assert.equal(res.statusCode,202);assert.deepEqual(res.body,{status:'pending',approved:false});
    assert.deepEqual(state.deviceInserts,[{owner_id:owner,credential_id:credentialId,key_algorithm:-257,
      public_x:null,public_y:null,public_n:rsa.n,public_e:rsa.e,sign_count:0,status:'pending'}]);
  });
  await check('EC finish는 기존 공개 x/y를 보존하고 RSA 필드는 null로 저장한다',async()=>{
    const beginning=await callDevice({action:'begin'});
    const res=await callDevice({action:'finish',challengeId:beginning.body.challengeId,
      response:registration(-7,beginning.body.options.challenge)});
    assert.equal(res.statusCode,202);assert.equal(res.body.approved,false);
    assert.deepEqual(state.deviceInserts,[{owner_id:owner,credential_id:credentialId,key_algorithm:-7,
      public_x:ec.x,public_y:ec.y,public_n:null,public_e:null,sign_count:0,status:'pending'}]);
  });
  for(const [label,options] of [['origin',{site:'https://wrong-origin.invalid'}],['UV',{flags:0x41}]]){
    await check('등록 '+label+' 검증 실패는 403이며 기기를 저장하지 않는다',async()=>{
      const beginning=await callDevice({action:'begin'});
      const res=await callDevice({action:'finish',challengeId:beginning.body.challengeId,
        response:registration(-257,beginning.body.options.challenge,options)});
      assert.equal(res.statusCode,403);assert.equal(res.body.error,'registration_signature_invalid');
      assert.equal(state.deviceInserts.length,0);
    });
  }
  await check('로그인·학생 신원 게이트는 등록 DB 처리보다 먼저 적용한다',async()=>{
    state.login=null;let res=await callDevice({action:'begin'});assert.equal(res.statusCode,401);
    state.login={kind:'judge',userId:owner};res=await callDevice({action:'begin'});assert.equal(res.statusCode,403);
    assert.equal(state.queries.length,0);
  });
  await check('서명 begin은 승인 기기의 새 공개키 필드를 읽고 UV를 요구한다',async()=>{
    const beginning=await beginRequest();
    assert.equal(beginning.options.userVerification,'required');
    assert.deepEqual(beginning.options.allowCredentials,[{type:'public-key',id:credentialId}]);
    const query=state.queries.find(item=>item.table==='app_devices'&&item.operation==='select');
    for(const field of ['credential_id','key_algorithm','public_x','public_y','public_n','public_e','sign_count','status'])
      assert.ok(query.columns.split(',').includes(field));
    assert.ok(query.filters.some(([kind,key,value])=>kind==='eq'&&key==='status'&&value==='approved'));
  });
  await check('pending 기기는 서명 챌린지와 보호 API에 접근하지 못한다',async()=>{
    state.devices.push(approvedCredential(-257,{status:'pending'}));
    const res=await callRequest({action:'begin',target});assert.equal(res.statusCode,403);
    assert.equal(res.body.error,'device_not_approved');assert.equal(state.challenges.size,0);
    assert.equal(state.delegations.length,0);
  });
  await check('유효 RSA 서명은 실제 검증과 승인·counter 갱신 후에만 내부 위임된다',async()=>{
    const beginning=await beginRequest();
    const res=await executeRequest(beginning,proof(-257,beginning.options.challenge));
    assert.equal(res.statusCode,200);assert.deepEqual(res.body,{mockResource:true});
    assert.equal(state.devices[0].sign_count,1);
    assert.deepEqual(state.delegations,[{approved:true,...target}]);
    const update=state.queries.find(query=>query.operation==='update');
    for(const filter of [['eq','credential_id',credentialId],['eq','owner_id',owner],
      ['eq','status','approved'],['eq','sign_count',0]])assert.ok(update.filters.some(item=>
        JSON.stringify(item)===JSON.stringify(filter)));
    assert.equal(state.challenges.size,0);
  });
  for(const [label,options] of [['signature',{corrupt:true}],['UV',{flags:1}]]){
    await check('RSA '+label+' 검증 실패는 counter 갱신·내부 위임 없이 403이다',async()=>{
      const beginning=await beginRequest();
      const res=await executeRequest(beginning,proof(-257,beginning.options.challenge,options));
      assert.equal(res.statusCode,403);assert.equal(res.body.error,'invalid_request_signature');
      assert.equal(state.queries.filter(query=>query.operation==='update').length,0);
      assert.equal(state.devices[0].sign_count,0);assert.equal(state.delegations.length,0);
    });
  }
  for(const [label,change] of [
    ['승인 회수',()=>{state.devices[0].status='revoked';}],
    ['counter 경쟁',()=>{state.devices[0].sign_count=2;}],
  ]){
    await check('서명 검증 후 '+label+' 발생 시 보호 API 위임을 차단한다',async()=>{
      const beginning=await beginRequest();state.beforeUpdate=change;
      const res=await executeRequest(beginning,proof(-257,beginning.options.challenge));
      assert.equal(res.statusCode,403);assert.equal(res.body.error,'credential_revoked_or_replayed');
      assert.equal(state.delegations.length,0);
    });
  }
  await check('일회용 서명 챌린지는 같은 proof의 두 번째 실행을 거부한다',async()=>{
    const beginning=await beginRequest(),assertion=proof(-257,beginning.options.challenge);
    assert.equal((await executeRequest(beginning,assertion)).statusCode,200);
    const replay=await executeRequest(beginning,assertion);
    assert.equal(replay.statusCode,403);assert.equal(replay.body.error,'challenge_invalid_or_expired');
    assert.equal(state.delegations.length,1);
  });
  await check('서명 대상 경로 변경은 공개키 검증·자료 위임 전에 거부한다',async()=>{
    const beginning=await beginRequest();
    const res=await executeRequest(beginning,proof(-257,beginning.options.challenge),
      {...target,path:'/api/instructor-notices'});
    assert.equal(res.statusCode,403);assert.equal(res.body.error,'signed_target_mismatch');
    assert.equal(state.delegations.length,0);
    assert.equal(state.queries.filter(query=>query.operation==='update').length,0);
  });
  await check('알고리즘 열이 없는 기존 EC 기기도 실제 서명 검증 후 정상 위임된다',async()=>{
    const beginning=await beginRequest(approvedCredential(-7,{legacy:true}));
    const res=await executeRequest(beginning,proof(-7,beginning.options.challenge));
    assert.equal(res.statusCode,200);assert.equal(state.devices[0].sign_count,1);
    assert.equal(state.delegations[0].approved,true);
  });
  assert.equal(networkCalls,0);
  return{mockOnly:true,networkCalls,results};
}

if(process.env.WATCHDOGS_STAGE11_API_MOCK_CHILD==='1'){
  process.stdout.write(JSON.stringify(await runMockSuite()));
}else{
  test('모의 Stage11 API: 합성 로그인·DB와 실제 WebAuthn 검증의 통합',{timeout:20000},async t=>{
    const child=spawnSync(process.execPath,[fileURLToPath(import.meta.url)],{
      encoding:'utf8',timeout:18000,windowsHide:true,
      env:{SystemRoot:process.env.SystemRoot,TEMP:process.env.TEMP,TMP:process.env.TMP,
        WATCHDOGS_STAGE11_API_MOCK_CHILD:'1',SUPABASE_URL:'https://mock-database.invalid',
        SUPABASE_SECRET_KEY:'synthetic-placeholder'},
    });
    assert.equal(child.error,undefined,child.error?.message);
    assert.equal(child.status,0,child.stderr||'격리 API 모의 검사 종료 상태');
    const report=JSON.parse(child.stdout);
    assert.equal(report.mockOnly,true);assert.equal(report.networkCalls,0);
    assert.equal(report.results.length,16);
    for(const name of report.results)await t.test('모의 API: '+name,()=>assert.ok(name));
  });
}
