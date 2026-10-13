import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from '../src/verify-login.mjs';
import {POLICY_ROUTE,exactStage10Path,isVerifiedJudgeB,
 recoveryPolicyHash} from '../src/stage10-restore-contract.mjs';
function json(response,status,body) {
 response.status(status);
 response.setHeader('Content-Type','application/json; charset=utf-8');
 response.setHeader('Cache-Control','no-store');
 return response.json(body);
}
export default async function handler(request,response){
 if(!['GET','POST'].includes(request.method)){
  response.setHeader('Allow','GET, POST');
  return json(response,405,{error:'method_not_allowed'});
 }
 if(!exactStage10Path(request.url,POLICY_ROUTE))
  return json(response,400,{error:'invalid_policy_path'});
 const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
 if(!url||!key)return json(response,503,{error:'server_not_configured'});
 const supabase=createClient(url,key,{auth:{
  autoRefreshToken:false,persistSession:false,detectSessionInUrl:false,
 }});
 let verify;
 try{verify=createLoginVerifier({config,supabaseSecretKey:key,supabaseClient:supabase});}
 catch{return json(response,503,{error:'login_verifier_unavailable'});}
 const login=await verify(request.headers?.authorization);
 if(!login)return json(response,401,{error:'authentication_required'});
 if(!isVerifiedJudgeB(login))return json(response,403,{error:'policy_recovery_not_authorized'});
 if(request.method==='GET'){
  const {data,error}=await supabase.rpc('stage10_policy_preview');
  if(error||!data)return json(response,503,{error:'policy_backup_unavailable'});
  return json(response,200,data);
 }
 const expectedSha256=recoveryPolicyHash(request.body);
 if(!expectedSha256)return json(response,400,{error:'baseline_version_confirmation_required'});
 const {data,error}=await supabase.rpc('stage10_policy_restore',{
  p_expected_sha256:expectedSha256,
 });
 if(error||!data?.restored)return json(response,409,{error:'verified_policy_restore_rejected'});
 return json(response,200,data);
}
