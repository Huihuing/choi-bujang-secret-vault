import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from '../src/verify-login.mjs';
import {RESTORE_ROUTE,exactStage10Path,isVerifiedJudgeB,
  recoveryNoteId,confirmedRestoreResponse} from '../src/stage10-restore-contract.mjs';

function json(response,status,body) {
 response.status(status);
 response.setHeader('Content-Type','application/json; charset=utf-8');
 response.setHeader('Cache-Control','no-store');
 return response.json(body);
}
export default async function handler(request,response) {
 if(request.method!=='POST'){
  response.setHeader('Allow','POST');
  return json(response,405,{error:'method_not_allowed'});
 }
 if(!exactStage10Path(request.url,RESTORE_ROUTE))
  return json(response,400,{error:'invalid_restore_path'});
 const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
 if(!url||!key)return json(response,503,{error:'server_not_configured'});
 const supabase=createClient(url,key,{auth:{
  autoRefreshToken:false,persistSession:false,detectSessionInUrl:false,
 }});
 let verify;
 try { verify=createLoginVerifier({config,supabaseSecretKey:key,supabaseClient:supabase}); }
 catch {return json(response,503,{error:'login_verifier_unavailable'});}
 const login=await verify(request.headers?.authorization);
 if(!login)return json(response,401,{error:'authentication_required'});
 if(!isVerifiedJudgeB(login))return json(response,403,{error:'recovery_not_authorized'});
 const id=recoveryNoteId(request.body);
 if(!id)return json(response,400,{error:'invalid_recovery_target'});
 const {data,error}=await supabase.rpc('stage10_restore_one',{
  p_id:id,p_verified_owner:login.userId,
 });
 if(error){
  // No snapshot bodies, internal SQL errors or ownership details in responses/logs.
  if(error.code==='P0002')return json(response,404,{error:'verified_backup_missing'});
  if(error.code==='42501')return json(response,403,{error:'recovery_not_authorized'});
  return json(response,503,{error:'verified_recovery_unavailable'});
 }
 const verified=confirmedRestoreResponse(data,id);
 if(!verified)return json(response,503,{error:'recovery_verification_failed'});
 return json(response,200,verified);
}
