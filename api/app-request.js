import {randomBytes} from 'node:crypto';
import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from '../src/verify-login.mjs';
import {verifyAssertion,digestBody} from '../src/app-webauthn.mjs';
import {APP_APPROVED} from '../src/app-approval.mjs';
import notes from './notes.js';
import noteItem from './notes/[id].js';
import notices from './instructor-notices.js';
import noticeItem from './instructor-notices/[id].js';

const ORIGIN=new URL(config.publicAppUrl).origin;
const RPID=new URL(config.publicAppUrl).hostname;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu;
const idPath=/^\/api\/(notes|instructor-notices)\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const b64=buf=>Buffer.from(buf).toString('base64url');
function send(res,status,data){
 res.status(status);res.setHeader('Content-Type','application/json; charset=utf-8');
 res.setHeader('Cache-Control','no-store');return res.json(data);
}
function bodyOf(request) {
 if(request.body && typeof request.body==='object'&&!Array.isArray(request.body))return request.body;
 if(typeof request.body==='string'&&request.body.length<=25000){
  try{const obj=JSON.parse(request.body);if(obj&&typeof obj==='object'&&!Array.isArray(obj))return obj;}
  catch{}
 }
 return null;
}
export function validSignedTarget(target){
 if(!target||typeof target!=='object'||Array.isArray(target)
  ||Object.keys(target).sort().join(',')!=='body,method,path')return false;
 const {method,path,body}=target;
 if(typeof path!=='string'||typeof method!=='string'||
  !['GET','POST','PUT','DELETE'].includes(method))return false;
 const collection=path==='/api/notes'||path==='/api/instructor-notices';
 const item=idPath.test(path);
 if(!collection&&!item)return false;
 if(collection && !['GET','POST'].includes(method))return false;
 if(item && !['GET','PUT','DELETE'].includes(method))return false;
 if(method==='GET'||method==='DELETE')return body===null;
 if(typeof body!=='string'||body.length>6000||body.length<2)return false;
 try{const data=JSON.parse(body);return Boolean(data&&typeof data==='object'&&!Array.isArray(data));}
 catch{return false;}
}
export function matchesSignedTarget(challenge,target) {
 return Boolean(challenge && validSignedTarget(target)
  && challenge.method===target.method && challenge.path===target.path
  && challenge.body_sha256===digestBody(target.body));
}
function delegated(target){
 if(target.path==='/api/notes')return notes;
 if(target.path==='/api/instructor-notices')return notices;
 if(target.path.startsWith('/api/notes/'))return noteItem;
 return noticeItem;
}
export default async function handler(req,res){
 if(req.method!=='POST'||req.url!=='/api/app-request')
  return send(res,405,{error:'invalid_app_request'});
 const requestBody=bodyOf(req);
 if(!requestBody||!['begin','execute'].includes(requestBody.action)||
  !validSignedTarget(requestBody.target))return send(res,400,{error:'invalid_signed_target'});
 const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
 if(!url||!key)return send(res,503,{error:'server_not_configured'});
 const supabase=createClient(url,key,{auth:{
  persistSession:false,autoRefreshToken:false,detectSessionInUrl:false,
 }});
 let verify;
 try{verify=createLoginVerifier({config,supabaseSecretKey:key,supabaseClient:supabase});}
 catch{return send(res,503,{error:'login_verifier_unavailable'});}
 const login=await verify(req.headers?.authorization);
 if(!login)return send(res,401,{error:'authentication_required'});
 if(login.kind!=='student')return send(res,403,{error:'student_identity_required'});
 const {data:devices,error:deviceError}=await supabase.from('app_devices')
  .select('credential_id,key_algorithm,public_x,public_y,public_n,public_e,sign_count,status')
  .eq('owner_id',login.userId).eq('status','approved');
 if(deviceError)return send(res,503,{error:'device_status_unavailable'});
 if(!devices?.length)return send(res,403,{error:'device_not_approved'});
 const target=requestBody.target;
 if(requestBody.action==='begin'){
  const challenge=b64(randomBytes(32));
  const {data,error}=await supabase.from('app_device_challenges')
   .insert({owner_id:login.userId,purpose:'request',challenge,
    method:target.method,path:target.path,body_sha256:digestBody(target.body)})
   .select('id').single();
  if(error||!data)return send(res,503,{error:'challenge_unavailable'});
  return send(res,200,{challengeId:data.id,options:{
   challenge,rpId:RPID,timeout:60000,userVerification:'required',
   allowCredentials:devices.map(d=>({type:'public-key',id:d.credential_id})),
  }});
 }
 if(typeof requestBody.challengeId!=='string'||!UUID.test(requestBody.challengeId)||
  !requestBody.proof || typeof requestBody.proof!=='object')
  return send(res,400,{error:'invalid_signed_proof'});
 // Consumed atomically so a previously signed request can never be replayed.
 const {data:challenge,error:challengeError}=await supabase.rpc('stage11_consume_challenge',{
  p_id:requestBody.challengeId,p_owner_id:login.userId,p_purpose:'request',
 });
 if(challengeError)return send(res,503,{error:'challenge_unavailable'});
 if(!challenge)return send(res,403,{error:'challenge_invalid_or_expired'});
 if(!matchesSignedTarget(challenge,target))
  return send(res,403,{error:'signed_target_mismatch'});
 const cred=devices.find(d=>d.credential_id===requestBody.proof.id);
 if(!cred)return send(res,403,{error:'approved_credential_required'});
 let nextCount;
 try {
  nextCount=verifyAssertion({response:requestBody.proof,
   challenge:challenge.challenge,origin:ORIGIN,rpID:RPID,credential:cred});
 }catch{return send(res,403,{error:'invalid_request_signature'});}
 // Approval status and counter are rechecked atomically before accessing data.
 const {data:verified,error:counterError}=await supabase.from('app_devices')
  .update({sign_count:nextCount})
  .eq('credential_id',cred.credential_id).eq('owner_id',login.userId)
  .eq('status','approved').eq('sign_count',cred.sign_count)
  .select('credential_id').maybeSingle();
 if(counterError||!verified)return send(res,403,{error:'credential_revoked_or_replayed'});
 // Only this server-internal Symbol can bypass the direct student device gate.
 const safeRequest={...req,method:target.method,url:target.path,
  body:target.body,headers:{...req.headers},[APP_APPROVED]:true};
 return delegated(target)(safeRequest,res);
}
