// Standalone offline Wazuh persistence detector. Mirrors patterns.json.
// No imports, I/O, network, external modules or model dependencies.
const PATTERNS=Object.freeze({
 service:'unsigned-new-service',
 task:'unknown-scheduled-task',
 startup:'startup-folder-change',
 review:'persistence-review',
 normal:'normal-event',
});
const TAG=/^T(?:1543|1053|1547)(?:\.|$)/u;
const SERVICE=/(?:서비스|service|daemon)/iu;
const TASK=/(?:예약\s*작업|작업\s*스케줄|scheduled.?task|task.?scheduler|schtasks)/iu;
const STARTUP=/(?:시작\s*(?:폴더|프로그램)|startup(?:[\\/ _-]*folder)?|start[ -]?menu.{0,65}startup)/iu;
const CHANGE=/(?:신규|새로|새\s*|생성|등록|설치|변경|추가|수정|created?|creat(?:ed|ion)|install(?:ed|ation)?|register(?:ed)?|modif(?:y|ied)|added?|changed?|new\b)/iu;
const UNSIGNED=/(?:서명\s*(?:없|되지\s*않)|무서명|미서명|서명\s*불일치|unsigned|not.?signed|untrusted|invalid signature)/iu;
const UNKNOWN=/(?:미승인|허용\s*목록에\s*없|기준\s*목록에\s*없|등록된\s*적\s*없|낯선|알려지지\s*않|불명|unknown|not.{0,12}baseline|not.{0,10}approved|unapproved|unrecognized|unauthorized|untrusted)/iu;
const TRUSTED=/(?:승인된|허가된|정상\s*서명|signed.*approved|approved|allowlisted|trusted|평소\s*목록)/iu;
function str(value){return typeof value==='string'?value.slice(0,800):'';}
function object(value){return value&&typeof value==='object'&&!Array.isArray(value)?value:{};}
function mitreIds(alert){
 const source=alert?.rule?.mitre;
 const ids=Array.isArray(source)?source:Array.isArray(source?.id)?source.id:typeof source?.id==='string'?[source.id]:[];
 return ids.filter(v=>typeof v==='string');
}
function flagFalse(...values){return values.some(v=>v===false||v==='false'||v==='NotSigned'||v==='Unsigned'||v==='Invalid');}
function flagTrue(...values){return values.some(v=>v===true||v==='true'||v==='Valid'||v==='Signed');}
function decision(value,reason){
 const confidence=Math.max(0,Math.min(1,Number.isFinite(value)?value:0));
 return {action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence,reason};
}
export function decide(alert){
 const a=object(alert),data=object(a.data),rule=object(a.rule),agent=object(a.agent);
 const win=object(data.win),system=object(win.system),events=object(win.eventdata);
 const syscheck=object(a.syscheck??data.syscheck);
 const service=object(data.service),task=object(data.task),signature=object(data.signature),baseline=object(data.baseline);
 const desc=str(rule.description??a.description);
 const id=String(data.eventID??data.eventId??system.eventID??system.eventId??'');
 const level=Number(rule.level??a.ruleLevel);
 const severity=Number.isFinite(level)?level:0;
 const tags=mitreIds(a);
 const tagged=tags.some(t=>TAG.test(t));
 const path=str(syscheck.path??data.path??data.filePath??events.TargetFilename);
 const operation=str(data.change??data.action??data.operation??service.operation??task.operation??syscheck.event);
 const kind=SERVICE.test(desc)||Boolean(data.serviceName||service.name||events.ServiceName)||id==='7045'||id==='4697'
   ?PATTERNS.service
   :TASK.test(desc)||Boolean(data.taskName||task.name||events.TaskName)||id==='4698'||id==='4702'
    ?PATTERNS.task
    :STARTUP.test(desc)||STARTUP.test(path)||data.startup===true?PATTERNS.startup:null;
 const relevantEvent=['7045','4697','4698','4702','106'].includes(id);
 const text=desc+' '+operation;
 const isChange=CHANGE.test(text)||['7045','4697','4698','4702','106'].includes(id)
   ||/^(?:added|modified|created)$/iu.test(str(syscheck.event));
 const unsigned=flagFalse(data.signed,data.signatureValid,signature.valid,events.Signed,events.SignatureValid)
   ||UNSIGNED.test(desc)||UNSIGNED.test(str(data.signatureStatus));
 const unknown=flagFalse(data.known,data.baselineKnown,baseline.known,data.approved)
   ||UNKNOWN.test(desc);
 const explicitlyTrusted=flagTrue(data.signed,data.signatureValid,signature.valid,baseline.known,data.baselineKnown,data.known,data.approved)
   &&TRUSTED.test(desc);
 // Ordinary signed/approved activity is not evidence of compromise.
 if(severity<=3&&!tagged)return decision(0.05,PATTERNS.normal);
 if(explicitlyTrusted&&severity<=6&&!unsigned)return decision(0.05,PATTERNS.normal);
 // Only corroborated service/task/startup persistence produces automatic
 // isolation: new/modified, unsigned, unknown baseline, severe Wazuh event.
 if(kind&&isChange&&unsigned&&unknown&&severity>=10&&(tagged||relevantEvent||PATTERNS.startup===kind)){
  return decision(0.96,kind);
 }
 // Missing evidence or a single unexplained creation is alert-only.
 if((kind&&(isChange||unsigned||unknown))||tagged||relevantEvent){
  return decision(tagged&&severity>=10?0.75:0.6,kind??PATTERNS.review);
 }
 return decision(0.05,PATTERNS.normal);
}
