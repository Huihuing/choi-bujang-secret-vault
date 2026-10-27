import {randomBytes} from 'node:crypto';
import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from '../src/verify-login.mjs';
import {verifyRegistration} from '../src/app-webauthn.mjs';

const ORIGIN=new URL(config.publicAppUrl).origin;
const RPID=new URL(config.publicAppUrl).hostname;
const b64=buf=>Buffer.from(buf).toString('base64url');
function send(res,status,data){
 res.status(status);res.setHeader('Content-Type','application/json; charset=utf-8');
 res.setHeader('Cache-Control','no-store');return res.json(data);
}
function bodyOf(request){
 if(request.body && typeof request.body==='object' && !Array.isArray(request.body))return request.body;
 if(typeof request.body==='string' && request.body.length<=24000){
  try {const body=JSON.parse(request.body);if(body && typeof body==='object'&&!Array.isArray(body))return body;}
  catch{}
 }
 return null;
}
export default async function handler(req,res){
 if(req.url!=='/api/device')return send(res,400,{error:'invalid_device_route'});
 if(!['GET','POST'].includes(req.method))return send(res,405,{error:'method_not_allowed'});
 const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
 if(!url||!key)return send(res,503,{error:'server_not_configured'});
 const client=createClient(url,key,{auth:{autoRefreshToken:false,persistSession:false}});
 const verify=createLoginVerifier({config,supabaseSecretKey:key,supabaseClient:client});
 const login=await verify(req.headers?.authorization);
 if(!login)return send(res,401,{error:'authentication_required'});
 if(login.kind!=='student')return send(res,403,{error:'student_identity_required'});
 const owner=login.userId;
 if(req.method==='GET'){
  const {data,error}=await client.from('app_devices').select('status,requested_at')
   .eq('owner_id',owner).order('requested_at',{ascending:false});
  if(error)return send(res,503,{error:'device_status_unavailable'});
  const approved=(data??[]).filter(item=>item.status==='approved').length;
  const pending=(data??[]).filter(item=>item.status==='pending').length;
  return send(res,200,{approved:approved>0,approvedCount:approved,pendingCount:pending,
   note:'기기 등록 요청은 서버 관리자가 승인하기 전까지 보호 자료 접근 권한이 없습니다.'});
 }
 const body=bodyOf(req);
 if(!body||!['begin','finish'].includes(body.action))return send(res,400,{error:'invalid_device_action'});
 if(body.action==='begin'){
  const challenge=b64(randomBytes(32));
  const {data,error}=await client.from('app_device_challenges')
   .insert({owner_id:owner,purpose:'register',challenge})
   .select('id').single();
  if(error||!data)return send(res,503,{error:'challenge_unavailable'});
  const registered=await client.from('app_devices').select('credential_id')
   .eq('owner_id',owner).neq('status','revoked');
  if(registered.error)return send(res,503,{error:'device_status_unavailable'});
  return send(res,200,{challengeId:data.id,options:{
   challenge,rp:{name:'BYTE BACK 자료실',id:RPID},
   user:{id:b64(randomBytes(32)),name:'자료실 사용자',displayName:'자료실 사용자'},
   pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
   timeout:60000,attestation:'none',
   authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'discouraged',
    userVerification:'required'},
   excludeCredentials:(registered.data??[]).map(x=>({type:'public-key',id:x.credential_id})),
  }});
 }
 const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
 if(typeof body.challengeId!=='string'||!uuid.test(body.challengeId)||!body.response)
  return send(res,400,{error:'invalid_device_registration'});
 const {data:challenge,error:challengeError}=await client.rpc('stage11_consume_challenge',{
  p_id:body.challengeId,p_owner_id:owner,p_purpose:'register',
 });
 if(challengeError)return send(res,503,{error:'challenge_unavailable'});
 if(!challenge)return send(res,403,{error:'challenge_invalid_or_expired'});
 let credential;
 try{
  credential=verifyRegistration({response:body.response,challenge:challenge.challenge,
   origin:ORIGIN,rpID:RPID});
 }catch{return send(res,403,{error:'registration_signature_invalid'});}
 const {error}=await client.from('app_devices').insert({
  owner_id:owner,credential_id:credential.credentialId,
  key_algorithm:credential.keyAlgorithm??-7,
  public_x:credential.publicX??null,public_y:credential.publicY??null,
  public_n:credential.publicN??null,public_e:credential.publicE??null,
  sign_count:credential.signCount,status:'pending',
 });
 if(error)return send(res,409,{error:'registration_not_accepted'});
 // Browser clicks only request; owner may not self-approve credentials.
 return send(res,202,{status:'pending',approved:false});
}
