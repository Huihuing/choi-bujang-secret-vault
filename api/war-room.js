import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from '../src/verify-login.mjs';
import {RULE_IDS} from '../src/decider.mjs';

// Server-observed, owner-scoped metadata only. No note bodies or access tokens.
const SHA=/^[0-9a-f]{40}$/iu;
// Do not coerce absent / invalid source measurements to a fabricated zero.
const countFromServer=value=>{
 if(typeof value!=='number'&&typeof value!=='string')return null;
 if(typeof value==='string'&&!/^(0|[1-9][0-9]*)$/u.test(value))return null;
 const number=Number(value);
 return Number.isSafeInteger(number)&&number>=0?number:null;
};
function send(res,status,body){
 res.status(status);
 res.setHeader('Cache-Control','no-store');
 res.setHeader('Content-Type','application/json; charset=utf-8');
 return res.json(body);
}
export default async function handler(req,res){
 if(req.method!=='GET'||req.url!=='/api/war-room')
  return send(res,405,{error:'invalid_operations_request'});
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
 const [summary,policy]=await Promise.all([
  supabase.rpc('stage12_ops_summary',{p_owner_id:login.userId}),
  supabase.rpc('stage10_policy_preview'),
 ]);
 if(summary.error||!summary.data)return send(res,503,{error:'operations_summary_unavailable'});
 // A missing or damaged policy snapshot must not be reported as verified.
 if(policy.error||!policy.data?.version||!policy.data?.baseline_sha256)
  return send(res,503,{error:'policy_backup_unverified'});
 const verified=policy.data;
 if(typeof verified.changed_count!=='number'||!Array.isArray(verified.changed_keys))
  return send(res,503,{error:'policy_backup_unverified'});
 const commit=process.env.VERCEL_GIT_COMMIT_SHA??null;
 return send(res,200,{
  schema:'byteback.operations.v1',checkedAt:new Date().toISOString(),
  source:'authenticated_read_only_server_rpc',
  stage:config.step,commit:typeof commit==='string'&&SHA.test(commit)?commit.toLowerCase():null,
  policyRules:{source:'repository_code_only',ids:[...RULE_IDS],
   count:RULE_IDS.length,serverEvaluations:null},
  detector:{source:'src/detect.mjs',implemented:true,
   observedEventCount:null,observation:'not_connected_to_runtime_events'},
  revocation:{source:'ALEPH SDP judge',engineRevocationCount:null,
   observation:'not_connected_to_engine_revocation_records'},
  devices:{
   source:'database_scoped_to_current_account',
   pending:countFromServer(summary.data.pending_devices),
   approved:countFromServer(summary.data.approved_devices),
   revoked:countFromServer(summary.data.revoked_devices),
  },
  recovery:{
   source:'verified_private_database_snapshot',
   baselineVersion:verified.version,verified:true,
   changedPolicyCount:countFromServer(verified.changed_count),
   currentAccountRestoreEvents:countFromServer(summary.data.account_restore_events),
   lastAccountRestoreAt:summary.data.latest_account_restore_at,
  },
  selfChecks:{
   source:'database_scoped_to_current_account',
   recordedCount:countFromServer(summary.data.account_safe_checks),
  },
  officialAssault:{expectedCaseCount:41,importedJudgements:null,
   observation:'official_41_case_results_not_connected'},
 });
}
