import {readFile,writeFile} from 'node:fs/promises';
import {decide} from './decide.mjs';
import {extract} from './read-alerts.mjs';
const RULES=new URL('./deny-rules.json',import.meta.url);
const LOGS=new URL('../alerts.log',import.meta.url);
const TTL_MS=15*60_000;
const IDENT=/^[a-zA-Z0-9_.:-]{1,128}$/u;
const ALERT=/^[a-zA-Z0-9_.:-]{1,80}$/u;

// lookupSubject must be a server-owned, verified mapping from the monitored
// account to the SDP's pseudonymous subjectId. Never derive it from a user
// claimed id in the Wazuh payload or from the browser-provided source IP.
export function makeRule(alert,decision,observedAt=Date.now(),lookupSubject=()=>null){
 const facts=extract(alert),id=alert?.id,account=facts.account;
 const start=Date.parse(facts.time??'');
 if(decision?.action!=='block'||Number(decision.confidence)<.85||
  typeof id!=='string'||!ALERT.test(id)||
  typeof account!=='string'||!IDENT.test(account)||
  !Number.isFinite(start)||!Number.isFinite(observedAt)||
  start>observedAt+5000||observedAt>=start+TTL_MS||
  typeof lookupSubject!=='function')return null;
 const confirmed=decide(alert);
 if(confirmed.action!=='block'||confirmed.reason!==decision.reason)return null;
 const subjectId=lookupSubject(account);
 if(typeof subjectId!=='string'||!IDENT.test(subjectId))return null;
 return {
  id:'xdr.privilege.'+id,
  subjectId,alertId:id,pattern:confirmed.reason,
  startsAt:new Date(start).toISOString(),
  expiresAt:new Date(start+TTL_MS).toISOString(),
 };
}
export function rulesFromDecisions(records,lookupSubject=()=>null){
 const rules=[],seen=new Set();
 for(const row of records){
  if(row.fixtureNormal)continue;
  const rule=makeRule(row.alert,row.decision,Date.parse(row.alert?.timestamp??''),lookupSubject);
  if(rule&&!seen.has(rule.id)){rules.push(rule);seen.add(rule.id);}
 }
 return rules;
}
export async function persistRules(rules){
 if(!Array.isArray(rules))throw new TypeError('Expected rules array');
 await writeFile(RULES,JSON.stringify(rules,null,2)+'\n','utf8');
}
export async function writeAlerts(decisions){
 let current='';
 try{current=await readFile(LOGS,'utf8');}
 catch(error){if(error?.code!=='ENOENT')throw error;}
 const existing=current.split(/\r?\n/u).filter(Boolean)
  .filter(line=>!line.includes('"module":"privilege"'));
 const added=decisions.filter(item=>['block','alert'].includes(item.action)
   &&ALERT.test(item.alertId??'')).map(item=>JSON.stringify({
    module:'privilege',alertId:item.alertId,action:item.action,
    confidence:item.confidence,pattern:item.reason,
   }));
 const all=[...existing,...added];
 await writeFile(LOGS,all.length?all.join('\n')+'\n':'','utf8');
 return added.length;
}
export async function loadRules(){
 try{
  const value=JSON.parse(await readFile(RULES,'utf8'));
  return Array.isArray(value)?value:[];
 }catch(error){if(error?.code==='ENOENT')return [];throw error;}
}
export function createSessionGuard(baseDecide,getRules=loadRules){
 return async function privilegeGuard(request,context={}){
  // Preserve any existing deny / step_up; only further restrict already-allowed sessions.
  const original=await baseDecide(request,context);
  if(original?.decision!=='allow')return original;
  // request.subjectId must have been validated by the trusted ZTNA engine.
  const subjectId=request?.subjectId;
  const now=Number.isFinite(context?.now)?context.now:Date.now();
  if(typeof subjectId==='string'&&IDENT.test(subjectId)){
   const rules=await getRules();
   const match=rules.find(rule=>rule?.subjectId===subjectId
    &&typeof rule.id==='string'&&rule.id.startsWith('xdr.privilege.')
    &&Date.parse(rule.startsAt)<=now&&now<Date.parse(rule.expiresAt));
   if(match){
    return {schema:'aleph.decision.v1',requestId:request.requestId,
     decision:'deny',reasonCode:'starter_not_ready',ruleIds:[match.id]};
   }
  }
  return original;
 };
}
