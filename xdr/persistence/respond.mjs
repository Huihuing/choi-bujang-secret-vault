import {readFile,writeFile} from 'node:fs/promises';
import {decide} from './decide.mjs';
import {extract} from './read-alerts.mjs';
const RULES=new URL('./deny-rules.json',import.meta.url);
const LOGS=new URL('../alerts.log',import.meta.url);
const TTL_MS=15*60*1000;
const DEVICE=/^[a-f0-9]{16}$/u;
const ALERT=/^[A-Za-z0-9_.:-]{1,80}$/u;
export function makeRule(alert,decision,observedAt=Date.now(),resolveDevice=()=>null){
 const facts=extract(alert);
 // Real isolation requires a trusted SDP identity resolution function.
 // Wazuh event fields alone are never authoritative device IDs.
 const deviceId=typeof resolveDevice==='function'?resolveDevice(alert):null;
 const id=alert?.id;
 const started=Date.parse(facts.time??'');
 if(decision?.action!=='block'||Number(decision.confidence)<0.85
   ||typeof id!=='string'||!ALERT.test(id)
   ||typeof deviceId!=='string'||!DEVICE.test(deviceId)
   ||!Number.isFinite(started)||!Number.isFinite(observedAt)
   ||started>observedAt+5000||observedAt>=started+TTL_MS)return null;
 // The bridge never trusts an unverified injected "block" result.
 const confirmed=decide(alert);
 if(confirmed.action!=='block'||confirmed.reason!==decision.reason)return null;
 return {
  id:'xdr.persistence.'+id,
  deviceId,
  sourceIp:facts.sourceIp,
  alertId:id,
  pattern:confirmed.reason,
  startsAt:new Date(started).toISOString(),
  expiresAt:new Date(started+TTL_MS).toISOString(),
 };
}
export function rulesFromDecisions(records,resolveDevice=()=>null){
 const rules=[],seen=new Set();
 for(const item of records){
  if(item.fixtureNormal)continue;
  const rule=makeRule(item.alert,item.decision,Date.parse(item.alert?.timestamp??''),resolveDevice);
  if(rule&&!seen.has(rule.id)){rules.push(rule);seen.add(rule.id);}
 }
 return rules;
}
export async function persistRules(rules){
 if(!Array.isArray(rules))throw new TypeError('Expected rules array');
 await writeFile(RULES,JSON.stringify(rules,null,2)+'\n','utf8');
}
export async function writeAlerts(decisions){
 let previous='';
 try{previous=await readFile(LOGS,'utf8');}
 catch(error){if(error?.code!=='ENOENT')throw error;}
 const existing=previous.split(/\r?\n/u).filter(Boolean)
   .filter(line=>!line.includes('"module":"persistence"'));
 const next=decisions.filter(item=>['block','alert'].includes(item.action)
    &&ALERT.test(item.alertId??'')).map(item=>JSON.stringify({
     module:'persistence',alertId:item.alertId,action:item.action,
     confidence:item.confidence,pattern:item.reason,
    }));
 const lines=[...existing,...next];
 await writeFile(LOGS,lines.length?lines.join('\n')+'\n':'','utf8');
 return next.length;
}
export async function loadRules(){
 try{
  const parsed=JSON.parse(await readFile(RULES,'utf8'));
  return Array.isArray(parsed)?parsed:[];
 }catch(error){if(error?.code==='ENOENT')return [];throw error;}
}
// request.deviceId is a 16-character identifier verified by the ZTNA engine.
// Never quarantine an entire shared source IP or trust browser-supplied IDs.
export function createIsolationGuard(baseDecide,getRules=loadRules){
 return async function persistenceGuard(request,context={}){
  const original=await baseDecide(request,context);
  // XDR only further restricts an already-allowed ZTNA request.
  if(original?.decision!=='allow')return original;
  const trustedId=request?.deviceId;
  const now=Number.isFinite(context?.now)?context.now:Date.now();
  if(typeof trustedId==='string'&&DEVICE.test(trustedId)){
   const rules=await getRules();
   const match=rules.find(rule=>rule?.deviceId===trustedId
      &&typeof rule?.id==='string'&&rule.id.startsWith('xdr.persistence.')
      &&Number.isFinite(Date.parse(rule.startsAt))
      &&Date.parse(rule.startsAt)<=now&&now<Date.parse(rule.expiresAt));
   if(match)return {
    schema:'aleph.decision.v1',requestId:request.requestId,
    decision:'deny',reasonCode:'starter_not_ready',ruleIds:[match.id],
   };
  }
  return original;
 };
}
