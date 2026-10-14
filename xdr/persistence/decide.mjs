// Standalone synchronous XDR-04 decision: no imports, I/O or network.
// Multiple independent persistence signals required for automated isolation.
const P=Object.freeze({
  "service": "unsigned-temporary-service",
  "task": "unfamiliar-scheduled-task",
  "startup": "unfamiliar-startup-entry",
  "repeat": "repeated-unsigned-service",
  "combined": "combined-persistence-channels",
  "review": "persistence-review",
  "normal": "normal-event"
});

function obj(x){return x!==null&&typeof x==="object"&&!Array.isArray(x)?x:{}}

function string(x){return typeof x==="string"?x.slice(0,1200):""}

function field(x,...keys){for(const key of keys){let v=x;for(const segment of key.split("."))v=v?.[segment];if(v!==undefined&&v!==null&&v!=="")return v}return undefined}

export function decide(alert){
 const a=obj(alert),r=obj(a.rule),d=obj(a.data);
 const description=string(field(r,"description")??a.description);
 const path=string(field(d,"path","filePath","syscheck.path","win.eventdata.ServiceFileName","win.eventdata.TaskContent"));
 const action=string(field(d,"change","operation","action","syscheck.event","service.operation","task.operation"));
 const level=Number(field(r,"level")??a.ruleLevel)||0;
 const eventId=String(field(d,"eventID","eventId","win.system.eventID")??"");
 const text=(description+" "+action).toLowerCase();
 const unsigned=d.signed===false||d.signatureValid===false||field(d,"signature.valid")===false
  ||/서명(?:이)?\s*없|서명\s*되지\s*않|무서명|미서명|unsigned|not signed/iu.test(text)
  ||/notsigned|unsigned/iu.test(string(d.signatureStatus));
 const approved=d.approved===true||d.allowlisted===true||(d.baselineKnown===true&&d.signed===true)
  ||/승인된|허용된|정상\s*(?:작업|프로그램|업데이트)|signed and approved/iu.test(text);
 const known=d.baselineKnown===true||d.known===true||field(d,"baseline.known")===true;
 const unfamiliar=d.baselineKnown===false||d.known===false||field(d,"baseline.known")===false
  ||/처음\s*보는|평소\s*목록에\s*없|평소\s*목록에\s*없는|평소\s*목록에\s*없|미등록|낯선|등록된\s*적\s*없|unknown|not in baseline|unfamiliar/iu.test(text);
 const service=/서비스|service|daemon/iu.test(text)||/^(?:7045|4697)$/u.test(eventId);
 const task=/예약\s*작업|scheduled task|task scheduler|schtasks/iu.test(text)||/^(?:4698|4702|106)$/u.test(eventId);
 const startup=/시작\s*(?:폴더|프로그램|항목)|startup/iu.test(text)||/[\\/]Startup[\\/]/iu.test(path);
 const temp=/[\\/]temp[\\/]|[\\/]tmp[\\/]|임시\s*폴더|temporary (?:directory|folder)|temp folder/iu.test(path+" "+text);
 const installed=/새\s*서비스|새로\s*생긴|새로\s*만들|신규|등록|생성|설치|추가|만들|바뀌|변경|실행\s*파일이\s*바뀌|처음\s*보는|created|added|installed|modified|changed/iu.test(text)
  ||/^(?:7045|4697|4698|4702|106)$/u.test(eventId);
 const offHours=/수업\s*시간\s*밖|업무\s*시간\s*밖|after.hours|off.hours|outside (?:business|class) hours/iu.test(text);
 const persistent=/다시\s*켜도\s*남|재부팅.*유지|reboot|persist/iu.test(text);
 const repeated=Number(field(d,"count"))>=3||/연속으로\s*\d+\s*건|repeated|multiple/iu.test(text);
 const randomName=/임의\s*문자열|random(?:ized)? name|무작위\s*이름/iu.test(text);
 const coupled=/같은\s*임시\s*파일을\s*함께|같은\s*파일을\s*함께|same (?:temporary )?file/iu.test(text);
 const noService=/서비스\s*등록은\s*없|service not installed|no service/iu.test(text);
 const noExecution=/이어서\s*실행된\s*기록은\s*없|실행\s*기록은\s*없|not executed/iu.test(text);
 const harmlessChange=/설명만\s*한\s*번\s*바뀌|실행\s*파일은\s*그대로|same (?:executable|file)|같은\s*파일로\s*다시\s*시작/iu.test(text);
 function result(confidence,reason){return {action:confidence>=.85?"block":confidence>=.5?"alert":"record",confidence,reason}}
 if(level<=3)return result(.05,P.normal);
 if(approved&&!unsigned)return result(.05,P.normal);
 if(level>=10&&!noService&&!noExecution&&!harmlessChange){
  if(startup&&task&&temp&&coupled)return result(.98,P.combined);
  if(service&&unsigned&&installed&&(temp||repeated||unfamiliar))return result(.97,repeated?P.repeat:P.service);
  if(task&&temp&&(installed||randomName)&&(unfamiliar||offHours||randomName))return result(.96,P.task);
  if(startup&&installed&&(unfamiliar||temp)&&/[\\/]Startup[\\/]/iu.test(path))return result(.96,P.startup);
  if(service&&persistent&&(unfamiliar||temp))return result(.96,P.service);
 }
 const suspicious=(service||task||startup||temp||unsigned||unfamiliar||/실행\s*파일|file integrity/iu.test(text))&&level>=4;
 return suspicious?result(level>=8?.75:.64,P.review):result(.06,P.normal);
}
