import {randomUUID} from 'node:crypto';
import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from '../src/verify-login.mjs';

// This route only executes fixed, privacy-safe probes. It never forwards caller
// credentials, accepts a destination URL or writes protected notes.
export const PROBES=Object.freeze({
 public_home:{method:'GET',path:'/',expected:200,step:11,kind:'normal'},
 public_manifest:{method:'GET',path:'/manifest.webmanifest',expected:200,step:11,kind:'normal'},
 deployment_identity:{method:'GET',path:'/aleph.json',expected:200,step:5,kind:'normal'},
 anonymous_notes:{method:'GET',path:'/api/notes',expected:401,step:3,kind:'deny'},
 anonymous_note_item:{method:'GET',
  path:'/api/notes/11111111-1111-4111-8111-111111111111',expected:401,step:8,kind:'deny'},
 anonymous_notices:{method:'GET',path:'/api/instructor-notices',expected:401,step:8,kind:'deny'},
 anonymous_device_status:{method:'GET',path:'/api/device',expected:401,step:11,kind:'deny'},
 unsigned_app_request:{method:'POST',path:'/api/app-request',expected:401,
  step:11,kind:'deny',body:JSON.stringify({action:'execute',
    target:{method:'GET',path:'/api/notes',body:null}})},
 anonymous_restore:{method:'POST',path:'/api/restore',expected:401,
  step:10,kind:'deny',
  body:JSON.stringify({id:'11111111-1111-4111-8111-111111111111'})},
 anonymous_policy:{method:'GET',path:'/api/recovery-policy',expected:401,step:10,kind:'deny'},
 invalid_resource_path:{method:'GET',path:'/api/notes/export',expected:400,step:8,kind:'deny'},
 anonymous_note_create:{method:'POST',path:'/api/notes',expected:401,step:5,
  kind:'deny',body:JSON.stringify({title:'safe synthetic',body:'no credentials'})},
});
const SCHEMA='byteback.probes.v1';
export const listProbeSpecs=()=>Object.entries(PROBES).map(([id,x])=>({
 id,method:x.method,path:x.path,expectedStatus:x.expected,step:x.step,
 kind:x.kind,
}));
function send(res,status,body){
 res.status(status);res.setHeader('Cache-Control','no-store');
 res.setHeader('Content-Type','application/json; charset=utf-8');
 return res.json(body);
}
function bodyOf(req){
 const value=req.body;
 if(typeof value==='string' && value.length<=160) {
  try {const parsed=JSON.parse(value);return parsed&&typeof parsed==='object'?parsed:null;}
  catch{return null;}
 }
 return value&&typeof value==='object'&&!Array.isArray(value)?value:null;
}
export async function evaluateSafeProbe(id,perform=fetch,at=new Date().toISOString()){
 const spec=PROBES[id];
 if(!spec)throw new TypeError('unknown_probe');
 const requestId=randomUUID();
 const url=new URL(spec.path,config.publicAppUrl);
 const options={method:spec.method,redirect:'manual',
  cache:'no-store',signal:AbortSignal.timeout(8000),
  headers:{'X-Request-Id':requestId,
   ...(spec.body?{'Content-Type':'application/json'}:{})},
  ...(spec.body?{body:spec.body}:{}),
 };
 let observedStatus=null;
 try{
  const response=await perform(url,options);
  if(Number.isInteger(response?.status)&&response.status>=100&&response.status<=599)
   observedStatus=response.status;
 }catch{/* failed network probes are recorded as failures with null status */}
 return {requestId,probeId:id,expectedStatus:spec.expected,
  observedStatus,passed:observedStatus===spec.expected,observedAt:at,
  source:'safe_http_self_check'};
}
export default async function handler(req,res){
 if(!['GET','POST'].includes(req.method)||req.url!=='/api/war-room-check')
  return send(res,405,{error:'invalid_probe_method_or_path'});
 const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
 if(!url||!key)return send(res,503,{error:'server_not_configured'});
 const supabase=createClient(url,key,{auth:{
  autoRefreshToken:false,persistSession:false,detectSessionInUrl:false,
 }});
 let verify;
 try{verify=createLoginVerifier({config,supabaseSecretKey:key,supabaseClient:supabase});}
 catch{return send(res,503,{error:'login_verifier_unavailable'});}
 const login=await verify(req.headers?.authorization);
 if(!login)return send(res,401,{error:'authentication_required'});
 if(login.kind!=='student')return send(res,403,{error:'student_required'});
 if(req.method==='GET'){
  const {data,error}=await supabase.from('app_ops_checks')
   .select('request_id,probe_id,expected_status,observed_status,passed,observed_at')
   .eq('owner_id',login.userId).order('observed_at',{ascending:false}).limit(100);
  if(error)return send(res,503,{error:'check_history_unavailable'});
  return send(res,200,{schema:SCHEMA,checkedAt:new Date().toISOString(),
   specs:listProbeSpecs(),checks:(data??[]).map(row=>({
     requestId:row.request_id,probeId:row.probe_id,
     expectedStatus:row.expected_status,observedStatus:row.observed_status,
     passed:row.passed,observedAt:row.observed_at,
   }))});
 }
 const input=bodyOf(req);
 const id=input?.probeId;
 if(!input||Object.keys(input).length!==1||typeof id!=='string'||
  !Object.hasOwn(PROBES,id))return send(res,400,{error:'unknown_or_unsafe_probe'});
 // A per-account cooldown prevents repeated probes from becoming scraping.
 const recent=await supabase.from('app_ops_checks').select('observed_at')
  .eq('owner_id',login.userId).order('observed_at',{ascending:false}).limit(1);
 if(recent.error)return send(res,503,{error:'probe_limit_unavailable'});
 const previous=recent.data?.[0]?.observed_at;
 if(previous && Date.now()-Date.parse(previous)<3000)
  return send(res,429,{error:'probe_cooldown'});
 const result=await evaluateSafeProbe(id);
 const {error}=await supabase.from('app_ops_checks').insert({
  request_id:result.requestId,owner_id:login.userId,
  probe_id:result.probeId,expected_status:result.expectedStatus,
  observed_status:result.observedStatus,passed:result.passed,
  observed_at:result.observedAt,
 });
 if(error)return send(res,503,{error:'probe_record_unavailable'});
 return send(res,200,{schema:SCHEMA,...result});
}
