// Pure offline privilege-escalation detector (MITRE T1068/T1078).
// PATTERNS must match xdr/privilege/patterns.json. No imports, IO, or network.
const PATTERNS=Object.freeze({
 group:'unapproved-admin-group-add',
 command:'unexpected-privileged-command',
 offHours:'off-hours-elevation',
 review:'privilege-review',
 normal:'normal-event',
});
const TAG=/^T(?:1068|1078)(?:\.|$)/u;
const ADMIN=/(?:administrators?|domain admins?|enterprise admins?|sudoers?|관리자|관리\s*그룹|권한\s*상승|높은\s*권한|privileg(?:e|ed)|elevat(?:ion|ed))/iu;
const JOIN=/(?:그룹.{0,35}(?:추가|등록|가입)|(?:member|user|account).{0,35}(?:add|join)|added.{0,35}(?:group|member)|joined|granted|권한.{0,15}(?:부여|추가)|멤버\s*추가)/iu;
const COMMAND=/(?:command|명령|powershell|administrator command|privileged action)/iu;
const UNAPPROVED=/(?:unauthori[sz]ed|unapproved|untrusted|unexpected|미승인|승인되지\s*않|허가되지\s*않|권한\s*없이|비정상|평소와\s*다른|not.{0,12}approved|not.{0,12}baseline)/iu;
const NIGHT=/(?:off[- ]?hours?|after[- ]?hours?|outside.{0,15}(?:business|work)|업무\s*시간\s*밖|근무\s*시간\s*외|심야|야간)/iu;
const ACCOUNT_RE=/^[A-Za-z0-9_.-]{1,80}$/u;
function obj(v){return v!==null&&typeof v==='object'&&!Array.isArray(v)?v:{};}
function str(v){return typeof v==='string'?v.slice(0,1200):'';}
function mitre(alert){
 const v=alert?.rule?.mitre;
 const ids=Array.isArray(v)?v:Array.isArray(v?.id)?v.id:typeof v?.id==='string'?[v.id]:[];
 return ids.some(id=>typeof id==='string'&&TAG.test(id));
}
function result(confidence,reason){
 return {action:confidence>=.85?'block':confidence>=.5?'alert':'record',confidence,reason};
}
export function decide(alert){
 const a=obj(alert),r=obj(a.rule),d=obj(a.data),w=obj(d.win),sys=obj(w.system),ev=obj(w.eventdata);
 const description=str(r.description??a.description),level=Number(r.level??a.ruleLevel);
 const severity=Number.isFinite(level)?level:0;
 const tagged=mitre(a);
 const eventId=String(d.eventID??d.eventId??sys.eventID??sys.eventId??'');
 const target=str(d.groupName??d.group??d.targetGroup??ev.TargetUserName??ev.GroupName);
 const operation=str(d.operation??d.change??d.action);
 const admin=ADMIN.test(description+' '+target+' '+operation)||d.adminRole===true;
 const addition=JOIN.test(description+' '+operation)||/\b(?:add(?:ed)?|joined|grant(?:ed)?)\b/iu.test(operation)
  ||['4728','4732','4756'].includes(eventId);
 const memberEvent=['4728','4732','4756'].includes(eventId);
 const groupEvent=admin&&(addition||memberEvent);
 const commandEvidence=d.privilegedCommand===true||COMMAND.test(description)||
  (typeof d.command==='string'&&COMMAND.test(operation));
 const novelty=d.firstSeen===true||/^(?:first|new)$/iu.test(str(d.novelty))||
  /(?:처음\s*(?:보는|실행)|first[- ]?seen|previously unseen)/iu.test(description);
 const elevated=d.elevation===true||d.adminRole===true||/elevat|관리자\s*명령|권한\s*상승/iu.test(description);
 const unauthorized=d.approved===false||d.expected===false||d.baselineKnown===false||
  UNAPPROVED.test(description);
 const permitted=d.approved===true||d.baselineKnown===true||d.expected===true;
 const offHours=d.outsideBusinessHours===true||NIGHT.test(description);
 // An approved, recognized maintenance session is not an escalation.
 if(permitted&&!unauthorized)return result(.05,PATTERNS.normal);
 if(severity<=3&&!tagged)return result(.05,PATTERNS.normal);
 // For automatic account-wide denial demand strong, independent evidence.
 if(groupEvent&&unauthorized&&severity>=10&&(tagged||memberEvent))
  return result(.97,PATTERNS.group);
 if(commandEvidence&&novelty&&elevated&&unauthorized&&severity>=10&&tagged)
  return result(.95,PATTERNS.command);
 if(offHours&&elevated&&unauthorized&&severity>=10&&tagged)
  return result(.92,PATTERNS.offHours);
 if(groupEvent||commandEvidence||offHours||tagged){
  return result(severity>=8?.75:.6,PATTERNS.review);
 }
 return result(.05,PATTERNS.normal);
}
