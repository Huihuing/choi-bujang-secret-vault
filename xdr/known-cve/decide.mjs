// Standalone, offline CVE-2021-44228 / MITRE T1190 detector.
// These names mirror xdr/known-cve/patterns.json. No imports, I/O or network.
const PATTERNS=Object.freeze({
 lookup:'log4shell-jndi-lookup',
 encoded:'log4shell-encoded-lookup',
 scanner:'log4shell-scan-indicator',
 normal:'normal-event',
});
const CODE=/\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)\s*:\/\//iu;
const SOFT_JNDI=/\bjndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\b/iu;
const EXPLICIT_CVE=/\bCVE[- ]?2021[- ]?44228\b/iu;
const HINT=/(?:\blog4shell\b|\blog4j\b.{0,40}(?:scan|probe|exploit|vulnerab|lookup)|취약점.{0,15}(?:탐지|점검|시도)|\bjndi\b.{0,40}(?:lookup|scan|test))/iu;
function bounded(value){
 return typeof value==='string'?value.slice(0,8192):'';
}
function requestFields(alert){
 const data=alert?.data;
 const fields=[];
 const add=value=>{if(typeof value==='string'&&fields.length<32)fields.push(bounded(value));};
 if(!data||typeof data!=='object')return fields;
 for(const key of ['url','uri','request_uri','request','http_request','path','query','args',
   'payload','body','userAgent','user_agent','request_line','request_body','request_headers']){
  add(data[key]);
 }
 for(const root of [data.headers,data.http?.headers,data.http,data.extra_data]){
  if(typeof root==='string')add(root);
  else if(root&&typeof root==='object'){
   for(const [key,v] of Object.entries(root).slice(0,24)){
    if(/^(?:headers|request|payload|uri|url|query|body|user.?agent|x-|referer|cookie|accept|host)/iu.test(key)
      ||root===data.headers||root===data.http?.headers)add(v);
   }
  }
 }
 add(alert?.full_log);
 return fields;
}
function normalize(raw){
 let text=bounded(raw);
 for(let j=0;j<2;j++){
  try{
   const next=decodeURIComponent(text);
   if(next===text)break;
   text=next.slice(0,8192);
  }catch{break;}
 }
 // Normalize simple nested Log4j character transformations for detection.
 // No interpretation, evaluation, network request or recursive expansion.
 for(let k=0;k<3;k++){
  const next=text
   .replace(/\$\{lower:([a-z])\}/giu,(_,v)=>v.toLowerCase())
   .replace(/\$\{upper:([a-z])\}/giu,(_,v)=>v.toUpperCase())
   .replace(/\$\{::-([a-z])\}/giu,(_,v)=>v);
  if(next===text)break;
  text=next;
 }
 return text;
}
function mitreIds(alert){
 const m=alert?.rule?.mitre;
 const ids=Array.isArray(m)?m:Array.isArray(m?.id)?m.id:
  typeof m?.id==='string'?[m.id]:[];
 return ids.filter(v=>typeof v==='string');
}
function output(confidence,reason){
 return {action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',
  confidence,reason};
}
export function decide(alert){
 const level=Number(alert?.rule?.level??alert?.ruleLevel);
 const severity=Number.isFinite(level)?level:0;
 const tagged=mitreIds(alert).some(t=>/^T1190(?:\.|$)/u.test(t));
 const description=bounded(alert?.rule?.description??alert?.description);
 const cve=EXPLICIT_CVE.test(description)||EXPLICIT_CVE.test(bounded(alert?.rule?.cve));
 const descriptionHint=HINT.test(description)||cve;
 const fields=requestFields(alert);
 let direct=false,encoded=false,weak=false;
 for(const field of fields){
  const canonical=normalize(field);
  if(CODE.test(canonical)){
   direct=true;
   if(!CODE.test(field))encoded=true;
   break;
  }
  if(SOFT_JNDI.test(canonical))weak=true;
 }
 if(direct){
  // Direct recognized exploit syntax in an actual request is strong enough
  // to block, even if a Wazuh rule forgot to set the MITRE tag.
  return output(0.97,encoded?PATTERNS.encoded:PATTERNS.lookup);
 }
 // Description-only signature does not prove malicious request content:
 // report it for inspection unless trusted Wazuh details corroborate it.
 if(CODE.test(normalize(description))&&(tagged||cve||severity>=8)){
  return output(0.75,PATTERNS.scanner);
 }
 if((tagged||cve||weak||descriptionHint)&&severity>=4){
  return output(tagged&&severity>=10?0.75:0.6,PATTERNS.scanner);
 }
 if((tagged||cve||weak)&&severity>0)return output(0.55,PATTERNS.scanner);
 return output(0.05,PATTERNS.normal);
}
