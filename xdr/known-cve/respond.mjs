import {readFile,writeFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {decide} from './decide.mjs';
import {extract} from './read-alerts.mjs';
const RULE_FILE=new URL('./deny-rules.json',import.meta.url);
const LOG_FILE=new URL('../alerts.log',import.meta.url);
const TTL_MS=15*60*1000;
const ALERT_ID=/^[A-Za-z0-9_.:-]{1,80}$/u;

export function makeRule(alert,decision,observedAt=Date.now()){
 const location=extract(alert);
 if(decision?.action!=='block'||Number(decision.confidence)<0.85
   ||!location.sourceIp||isIP(location.sourceIp)===0
   ||!location.time||!ALERT_ID.test(alert?.id??''))return null;
 // Never trust an externally supplied "block" label without independently
 // confirming the same clear exploit signature in the original alert.
 const check=decide(alert);
 if(check.action!=='block'||check.reason!==decision.reason)return null;
 const started=Date.parse(location.time);
 if(!Number.isFinite(started)||!Number.isFinite(observedAt)
   ||started>observedAt+5000||observedAt>=started+TTL_MS)return null;
 return {
  id:'xdr.known-cve.'+alert.id,
  sourceIp:location.sourceIp,
  alertId:alert.id,
  pattern:check.reason,
  startsAt:new Date(started).toISOString(),
  expiresAt:new Date(started+TTL_MS).toISOString(),
 };
}
export function rulesFromDecisions(records){
 // If the same source is used by a known-normal event in this batch,
 // quarantine automatically generated address-wide deny candidates instead
 // of risking a false-positive for a legitimate user on a shared IP.
 const normalIps=new Set(records.filter(x=>x.fixtureNormal)
  .map(x=>extract(x.alert).sourceIp).filter(Boolean));
 const seen=new Set(),rules=[];
 for(const row of records){
  if(row.fixtureNormal)continue;
  const rule=makeRule(row.alert,row.decision,Date.parse(row.alert?.timestamp));
  if(rule&&!normalIps.has(rule.sourceIp)&&!seen.has(rule.id)){
   seen.add(rule.id);rules.push(rule);
  }
 }
 return rules;
}
export async function persistRules(rules){
 if(!Array.isArray(rules))throw new TypeError('Expected rule array');
 await writeFile(RULE_FILE,JSON.stringify(rules,null,2)+'\n','utf8');
}
export async function writeAlerts(decisions){
 let existing='';
 try{existing=await readFile(LOG_FILE,'utf8');}
 catch(error){if(error?.code!=='ENOENT')throw error;}
 const retained=existing.split(/\r?\n/u).filter(Boolean)
  .filter(line=>!line.includes('"module":"known-cve"'));
 const written=decisions.filter(x=>['block','alert'].includes(x.action)
  &&ALERT_ID.test(x.alertId)).map(x=>JSON.stringify({
   module:'known-cve',
   alertId:x.alertId,
   action:x.action,
   confidence:x.confidence,
   pattern:x.reason,
 }));
 const merged=[...retained,...written];
 await writeFile(LOG_FILE,merged.length?merged.join('\n')+'\n':'','utf8');
 return written.length;
}
export async function loadRules(){
 try{
  const json=JSON.parse(await readFile(RULE_FILE,'utf8'));
  return Array.isArray(json)?json:[];
 }catch(error){
  if(error?.code==='ENOENT')return [];
  throw error;
 }
}
