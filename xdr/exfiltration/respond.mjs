import {readFile,writeFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {decide} from './decide.mjs';
const RULES=new URL('./deny-rules.json',import.meta.url);
const LOGS=new URL('../alerts.log',import.meta.url);
const TTL=15*60000;
const IDENT=/^[A-Za-z0-9_.:-]{1,80}$/u;
function dst(a){
 return a?.data?.dstip??a?.data?.dstIp??a?.data?.destination_ip??a?.data?.destinationIp
  ??a?.data?.destination?.ip??a?.data?.network?.dstip??a?.destination?.ip??null;
}
export function makeRule(alert,decision,now=Date.now()){
 const confirm=decide(alert),id=alert?.id,ip=dst(alert);
 const start=Date.parse(alert?.timestamp??alert?.['@timestamp']??'');
 if(decision?.action!=='block'||Number(decision.confidence)<.85
  ||confirm.action!=='block'||confirm.reason!==decision.reason
  ||typeof id!=='string'||!IDENT.test(id)||isIP(ip??'')===0
  ||!Number.isFinite(now)||!Number.isFinite(start)||start>now+5000||now>=start+TTL)return null;
 return {id:'xdr.exfiltration.'+id,destinationIp:ip,alertId:id,
  pattern:confirm.reason,startsAt:new Date(start).toISOString(),expiresAt:new Date(start+TTL).toISOString()};
}
export function rulesFromDecisions(rows){
 const normals=new Set(rows.filter(x=>x.fixtureNormal).map(x=>dst(x.alert)).filter(Boolean));
 const found=new Set(),rules=[];
 for(const row of rows){
  if(row.fixtureNormal)continue;
  const rule=makeRule(row.alert,row.decision,Date.parse(row.alert?.timestamp??''));
  if(rule&&!normals.has(rule.destinationIp)&&!found.has(rule.id)){found.add(rule.id);rules.push(rule);}
 }
 return rules;
}
export async function persistRules(rules){
 if(!Array.isArray(rules))throw new TypeError('Expected rules array');
 await writeFile(RULES,JSON.stringify(rules,null,2)+'\n','utf8');
}
export async function writeAlerts(decisions){
 let current='';
 try{current=await readFile(LOGS,'utf8');}catch(error){if(error?.code!=='ENOENT')throw error;}
 const before=current.split(/\r?\n/u).filter(Boolean).filter(x=>!x.includes('"module":"exfiltration"'));
 const added=decisions.filter(d=>['block','alert'].includes(d.action)&&IDENT.test(d.alertId??''))
 .map(d=>JSON.stringify({module:'exfiltration',alertId:d.alertId,
  action:d.action,confidence:d.confidence,pattern:d.reason}));
 const lines=[...before,...added];
 await writeFile(LOGS,lines.length?lines.join('\n')+'\n':'','utf8');
 return added.length;
}
export async function loadRules(){
 try{const x=JSON.parse(await readFile(RULES,'utf8'));return Array.isArray(x)?x:[];}
 catch(error){if(error?.code==='ENOENT')return [];throw error;}
}
// Caller must supply verified gateway context.destinationIp, never a browser field.
export function createDestinationGuard(baseDecide,getRules=loadRules){
 return async function guardedDecide(request,context={}){
  const ip=context?.destinationIp,now=Number.isFinite(context?.now)?context.now:Date.now();
  if(typeof ip==='string'&&isIP(ip)){
   const match=(await getRules()).find(r=>r?.destinationIp===ip&&typeof r.id==='string'
    &&r.id.startsWith('xdr.exfiltration.')&&Date.parse(r.startsAt)<=now&&now<Date.parse(r.expiresAt));
   if(match)return {schema:'aleph.decision.v1',requestId:request.requestId,
    decision:'deny',reasonCode:'starter_not_ready',ruleIds:[match.id]};
  }
  return baseDecide(request,context);
 };
}
