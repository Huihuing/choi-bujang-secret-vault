// Standalone, offline CVE-2021-44228 / MITRE T1190 detector.
// These names mirror xdr/known-cve/patterns.json. No imports, I/O or network.
const PATTERNS=Object.freeze({
 lookup:'log4shell-jndi-lookup',
 encoded:'log4shell-encoded-lookup',
 scanner:'log4shell-scan-indicator',
 repeated:'log4shell-repeated-exploit',
 normal:'normal-event',
});
// Require a concrete protocol and hostname: incomplete fragments are warnings.
const CODE=/\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)\s*:\/\/[a-z0-9][a-z0-9.-]*/iu;
const BARE=/\bjndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)\s*:\/\/[a-z0-9][a-z0-9.-]*/iu;
const SOFT_JNDI=/\bjndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\b/iu;
const EXPLICIT_CVE=/\bCVE[- ]?2021[- ]?44228\b/iu;
const HINT=/(?:\blog4shell\b|\blog4j\b.{0,40}(?:scan|probe|exploit|vulnerab|lookup)|취약점.{0,15}(?:탐지|점검|시도)|\bjndi\b.{0,40}(?:lookup|scan|test)|\bnuclei\b|log4j[-_ ]?scanner)/iu;
const CVE_FAMILY=/(?:\blog4j(?:2)?\b|\blog4shell\b|\bjndi\b|CVE[- ]?2021[- ]?44228|로그\s*4\s*j|원격\s*(?:명령|코드|조회)|(?:jndi|remote).{0,25}(?:lookup|exploit)|취약점.{0,15}(?:악용|공격)|(?:exploit|attack).{0,30}(?:logging|lookup))/iu;
const SCAN_ONLY=/(?:스캔|진단|점검|검사|탐색|교육|설치\s*안내|업데이트|패치|매뉴얼|문서\s*조회|\bscan(?:ner|ning)?\b|\bprobe\b|\bcheck(?:er|ing)?\b|\baudit\b|\btesting\b|\bnuclei\b|log4j[-_ ]?scanner)/iu;
function bounded(value){
 return typeof value==='string'?value.slice(0,8192):'';
}
function requestFields(alert){
 // Bounded scan of HTTP request evidence only; do not recursively inspect
 // the entire Wazuh object (metadata and benign documentation are not payloads).
 const fields=[],seen=new Set();
 const add=value=>{if(typeof value==='string'&&fields.length<64)fields.push(bounded(value));};
 const walk=(root,depth=0)=>{
  if(fields.length>=64||depth>4||root==null)return;
  if(typeof root==='string'){add(root);return;}
  if(typeof root!=='object'||seen.has(root))return;
  seen.add(root);
  if(Array.isArray(root)){
   for(const value of root.slice(0,64))walk(value,depth+1);
   return;
  }
  // Values in explicitly designated request trees are admissible. Names and
  // keys by themselves are not treated as exploit evidence.
  for(const value of Object.values(root).slice(0,64))walk(value,depth+1);
 };
 const data=alert?.data;
 if(data&&typeof data==='object'){
  for(const key of ['url','uri','request_uri','http_request','path','query','args',
   'payload','body','userAgent','user_agent','useragent','request_line','request_body',
   'request_headers','headers','http','request','extra_data','parameters','params']){
   walk(data[key]);
  }
 }
 walk(alert?.full_log);
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
   .replace(/\$\{::-([a-z])\}/giu,(_,v)=>v)
   // The Log4j default-value form can be used to split literal characters.
   // Decode only a single ASCII letter; never evaluate environment values.
   .replace(/\$\{env:[A-Za-z_][A-Za-z0-9_]*:-([a-z])\}/giu,(_,v)=>v);
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
function baseDecide(alert){
 const level=Number(alert?.rule?.level??alert?.ruleLevel);
 const severity=Number.isFinite(level)?level:0;
 const tagged=mitreIds(alert).some(t=>/^T1190(?:\.|$)/u.test(t));
 const description=bounded(alert?.rule?.description??alert?.description);
 const cve=EXPLICIT_CVE.test(description)||EXPLICIT_CVE.test(bounded(alert?.rule?.cve));
 const descriptionHint=HINT.test(description)||cve;
 const rawCount=alert?.data?.count;
 const count=typeof rawCount==='number'||(typeof rawCount==='string'&&/^\d{1,7}$/u.test(rawCount))
   ? Number(rawCount):NaN;
 const fields=requestFields(alert);
 let direct=false,encoded=false,bare=false,weak=false;
 for(const field of fields){
  const canonical=normalize(field);
  if(CODE.test(canonical)){
   direct=true;
   if(!CODE.test(field))encoded=true;
   break;
  }
  if(BARE.test(canonical))bare=true;
  if(SOFT_JNDI.test(canonical))weak=true;
 }
 if(direct){
  // Explicit Log4j lookup in an HTTP request: strong even without Wazuh tags.
  return output(0.97,encoded?PATTERNS.encoded:PATTERNS.lookup);
 }
 if(bare&&(tagged||severity>=4)){
  // Complete bare lookup requires Wazuh corroboration to avoid blocking
  // low-severity educational searches containing only JNDI terminology.
  return output(0.93,PATTERNS.lookup);
 }
 // Distinguish a benign low-severity CVE article/documentation lookup from
 // Wazuh's explicit correlated exploitation classification.
 if(severity<=3&&!tagged)return output(0.05,PATTERNS.normal);
 // Wazuh can summarize repeated exploit requests in its rule metadata,
 // without retaining a literal JNDI payload in each alert's data.url.
 // Require corroborating T1190, high severity, repeated events AND an
 // exploit-family marker. Scanner-only evidence must remain alert.
 const related=CVE_FAMILY.test(description)||cve;
 const onlyScanner=SCAN_ONLY.test(description)
   && !/(?:악용|공격|실행|우회|삽입|노출|exploit(?:ation|ed)?|injection|execution|RCE)/iu.test(description);
 if(tagged&&severity>=10&&Number.isInteger(count)&&count>=5
   &&related&&!onlyScanner){
  return output(0.96,PATTERNS.repeated);
 }
 // An explicit, complete lookup in the Wazuh description is a strong alert
 // only when corroborated by a tag, CVE or high rule severity.
 const completeDescription=CODE.test(normalize(description))||BARE.test(normalize(description));
 if(completeDescription){
  if(tagged||cve||severity>=8)return output(0.9,PATTERNS.lookup);
  return output(0.6,PATTERNS.scanner);
 }
 if((tagged||cve||bare||weak||descriptionHint)&&severity>=4){
  return output(tagged&&severity>=10?0.75:0.6,PATTERNS.scanner);
 }
 if((tagged||cve||bare||weak||descriptionHint)&&severity>0)return output(0.55,PATTERNS.scanner);
 return output(0.05,PATTERNS.normal);
}

// Production judgment is solely the evidence-based classifier; no diagnostic override.
export function decide(alert){return baseDecide(alert);}
