import {createClient} from '@supabase/supabase-js';
import packageAiHandler from '../src/package-ai-handler.mjs';
import packageThreatIntelHandler from '../src/package-threat-intel-handler.mjs';
import config from '../aleph.config.json' with {type:'json'};
import {RULE_IDS} from '../src/decider.mjs';

// Public aggregate-only evidence. No user ID, note contents, tokens,
// credential identifiers, device IDs, IPs or raw event rows leave the server.
const commitPattern=/^[0-9a-f]{40}$/iu;
const versionPattern=/^[a-zA-Z0-9_.-]{1,100}$/u;
const count=value=>{
 const n=typeof value==='number'?value:
  (typeof value==='string'&&/^(0|[1-9][0-9]*)$/u.test(value)?Number(value):NaN);
 return Number.isSafeInteger(n)&&n>=0?n:null;
};
export function publicOperationsResponse(record,commit){
 const keys=['device_pending','device_approved','device_revoked',
  'restore_events','probe_events','probe_matches','backup_changed_fields'];
 if(!record||keys.some(k=>count(record[k])===null)
  ||!versionPattern.test(record.backup_version??'')
  ||!Number.isFinite(Date.parse(record.observed_at??'')))return null;
 if(count(record.probe_matches)>count(record.probe_events))return null;
 return {
  schema:'byteback.public-operations.v1',
  source:'server_database_aggregate',
  observedAt:record.observed_at,
  stage:config.step,
  commit:typeof commit==='string'&&commitPattern.test(commit)?commit.toLowerCase():null,
  policyRules:{declaredInSource:RULE_IDS.length,engineDecisions:null},
  detector:{eventCount:null,source:'engine_events_not_connected'},
  revocation:{engineRevokedCount:null,source:'engine_records_not_connected'},
  deviceState:{pending:count(record.device_pending),
   approved:count(record.device_approved),revoked:count(record.device_revoked)},
  recovery:{version:record.backup_version,
   changedPolicyEntries:count(record.backup_changed_fields),
   verifiedRestoreEvents:count(record.restore_events)},
  safeHttpChecks:{recorded:count(record.probe_events),
   expectedStatusMatched:count(record.probe_matches)},
  judgeCases:{target:41,verified:null,source:'judge_case_records_not_connected'},
 };
}
function respond(res,status,body){
 res.status(status);res.setHeader('Content-Type','application/json; charset=utf-8');
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 return res.json(body);
}
export default async function handler(req,res){
 // The Hobby packaging build removes only the two thin API entrypoints.
 // Both rewrite destinations dispatch to the same authenticated handlers.
 if(req.query?.__package_route==='ai')return packageAiHandler(req,res);
 if(req.query?.__package_route==='threat-intel')return packageThreatIntelHandler(req,res);

 // Vercel's protected deployment links may append routing/query metadata.
 // This function is already bound to /api/war-room-summary by file routing.
 // Do not authorize based on user-controlled query strings.
 if(req.method!=='GET')
  return respond(res,405,{error:'method_not_allowed'});
 const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
 if(!url||!key)return respond(res,503,{error:'operations_evidence_unavailable'});
 const client=createClient(url,key,{auth:{autoRefreshToken:false,
  persistSession:false,detectSessionInUrl:false}});
 const {data,error}=await client.rpc('stage12_public_operational_snapshot');
 if(error)return respond(res,503,{error:'operations_evidence_unavailable'});
 const summary=publicOperationsResponse(data,process.env.VERCEL_GIT_COMMIT_SHA);
 if(!summary)return respond(res,503,{error:'operations_evidence_unverified'});
 return respond(res,200,summary);
}
