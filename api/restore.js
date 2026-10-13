import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from '../src/verify-login.mjs';
import {RESTORE_ROUTE,exactStage10Path,isVerifiedJudgeB,
  recoveryNoteOperation} from '../src/stage10-restore-contract.mjs';
import {restoreFromVerifiedSnapshot} from '../src/restore-core.mjs';

function json(response,status,body) {
 // Diagnostics: only a fixed status/error vocabulary. Never log body,
 // token, owner UUID, note ID, request path or snapshot contents.
 const known=new Set(['method_not_allowed','invalid_restore_path','server_not_configured',
  'login_verifier_unavailable','authentication_required','recovery_not_authorized',
  'invalid_recovery_target','verified_backup_missing','backup_verification_failed',
  'backup_check_unavailable','verified_recovery_unavailable',
  'recovery_verification_failed']);
 console.info('aleph_s10_result',JSON.stringify({
  status,
  reason:body?.error && known.has(body.error)?body.error:'ok',
 }));
 response.status(status);
 response.setHeader('Content-Type','application/json; charset=utf-8');
 response.setHeader('Cache-Control','no-store');
 return response.json(body);
}
export default async function handler(request,response) {
 console.info('aleph_s10_entry',JSON.stringify({
  method:request.method==='POST'?'POST':'OTHER',
  authHeader:typeof request.headers?.authorization==='string'?'present':'absent',
 }));
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
 let failureReason='verification';
 const login=await verify(request.headers?.authorization,reason=>{failureReason=reason;});
 const reasons=new Set(['missing','format','issuer','expired','claims','signature','verification']);
 console.info('aleph_s10_auth',JSON.stringify({
  kind:login?.kind==='judge'?'judge':login?.kind==='student'?'student':'null',
  actor:login?.kind==='judge'?(login.identity==='b'?'b':'a'):'none',
  reason:login?'ok':reasons.has(failureReason)?failureReason:'verification',
 }));
 if(!login)return json(response,401,{error:'authentication_required'});
 if(!isVerifiedJudgeB(login))return json(response,403,{error:'recovery_not_authorized'});
 const operation=recoveryNoteOperation(request.body);
 if(!operation)return json(response,400,{error:'invalid_recovery_target'});
 // In a dry run, only the immutable backup is checked; no recovery RPC is run.
 // Legacy POST {id} keeps restoring a single verified, judge-B-owned record.
 const output=await restoreFromVerifiedSnapshot({
  supabase,id:operation.id,ownerId:login.userId,dryRun:operation.dryRun,
 });
 return json(response,output.status,output.body);
}
