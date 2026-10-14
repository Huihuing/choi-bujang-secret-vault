// Pure XDR-05 Wazuh privilege decision: no imports, I/O or network.
// MITRE T1068 and T1078. Blocking requires correlated privilege-change evidence.
const PATTERNS=Object.freeze({
  group:'unexpected-admin-group-change',
  command:'unexpected-elevated-command',
  session:'new-address-admin-session',
  identity:'cross-account-privileged-use',
  review:'privilege-review',
  normal:'normal-event'
});
function obj(v){return v!==null&&typeof v==='object'&&!Array.isArray(v)?v:{};}
function val(v,...paths){
 for(const path of paths){
  let z=v;
  for(const seg of path.split('.'))z=z?.[seg];
  if(z!==undefined&&z!==null&&z!=='')return z;
 }
 return undefined;
}
function str(v){return typeof v==='string'?v.slice(0,1300):'';}
function result(confidence,reason){
 return {action:confidence>=.85?'block':confidence>=.5?'alert':'record',confidence,reason};
}
export function decide(alert){
 const a=obj(alert),r=obj(a.rule),d=obj(a.data);
 const level=Number(val(r,'level')??val(a,'ruleLevel'))||0;
 const description=str(val(r,'description')??val(a,'description'));
 const group=str(val(d,'group','groupName','targetGroup','win.eventdata.TargetUserName','win.eventdata.GroupName'));
 const operation=str(val(d,'operation','change','action'));
 const text=(description+' '+operation).toLowerCase();
 const groupText=(group+' '+text).toLowerCase();
 const code=String(val(d,'eventID','eventId','win.system.eventID')??'');
 const approved=d.approved===true||d.authorized===true||d.expected===true||d.allowlisted===true
  ||/\b(?:approved|authorized|routine admin work|expected elevation)\b|승인된|허용된|승인\s*받은|정상\s*승인/iu.test(text);
 const unauthorized=d.approved===false||d.authorized===false||d.expected===false
  ||/unauthorized|unapproved|미승인|무단\s*(?:관리자|권한)/iu.test(text);
 const isAdmin=/(?:관리자|administrators?|domain admins?|enterprise admins?|sudoers?|elevat(?:ion|ed)|권한\s*상승|admin(?:istrator)?)/iu.test(groupText);
 const groupAdd=/(?:추가됐|추가와|추가되|추가한|추가했습니다|그룹에\s*들어가|다시\s*관리자로\s*들어|그룹\s*(?:추가|등록)|added|joined|re-?added|member added)/iu.test(text+' '+operation)
  ||(['4728','4732','4756'].includes(code)&&/add|added/i.test(operation));
 const groupChange=isAdmin&&groupAdd
  &&(/관리자\s*그룹|관리자로\s*들어|관리자\s*권한|administrators|domain admins/iu.test(groupText)||d.adminRole===true);
 const command=/(?:관리자\s*명령|권한\s*명령|elevated\s*command|privileged\s*command|admin(?:istrator)?\s*command)/iu.test(text)
  ||(isAdmin&&/명령\s*실행/iu.test(text))||d.privilegedCommand===true;
 const executed=/실행|run|execut(?:ed|ion)/iu.test(text)||d.executed===true;
 const noCommand=/명령은\s*없|명령\s*없이|명령\s*실행\s*(?:없|안)|command\s*(?:not|never)\s*executed/iu.test(text);
 const unknownIP=d.firstSeen===true||d.unknownAddress===true
  ||/처음\s*보는\s*(?:주소|IP)|주소는\s*처음\s*봅니다|new\s*(?:ip|address)|unfamiliar\s*(?:ip|address)/iu.test(text);
 const offHours=d.offHours===true||d.outsideBusinessHours===true
  ||/수업\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|업무\s*시간\s*밖|after[- ]?hours|off[- ]?hours/iu.test(text);
 const newAdmin=/방금\s*관리자가\s*된|newly\s*(?:promoted|elevated)|just\s*promoted/iu.test(text);
 const sessionChanged=/세션.{0,30}(?:관리자\s*권한|elevat)|session.{0,30}(?:admin|elevat)/iu.test(text);
 const crossAccount=/다른\s*계정의\s*권한으로|another\s*account.s\s*privileg|impersonat/iu.test(text);
 const rejoined=/빠진\s*계정.{0,30}다시\s*관리자로|removed.{0,30}re[- ]?added/iu.test(text);
 const multiple=Number(val(d,'count')??0)>=3||/계정\s*\d+\s*개|multiple\s*account/iu.test(text);
 const negatedAdmin=/관리자\s*그룹은\s*아닙니다|not\s*(?:an?\s*)?admin(?:istrator)?\s*group/iu.test(text);
 const canceled=/취소|실패|변경은\s*없|변경\s*없|권한\s*사용\s*취소|cancel(?:ed|led)|failed|denied/iu.test(text);
 if(approved&&!unauthorized)return result(.05,PATTERNS.normal);
 if(level<=3)return result(.05,PATTERNS.normal);
 if(level>=10&&!canceled&&!negatedAdmin&&!noCommand){
  if(groupChange&&(command&&executed||multiple||rejoined||/원격\s*주소|다른\s*주소|관리자\s*그룹에\s*추가/iu.test(text)))
   return result(.97,PATTERNS.group);
  if(command&&executed&&(newAdmin||offHours&&unknownIP))
   return result(.97,PATTERNS.command);
  if(command&&executed&&crossAccount)
   return result(.96,PATTERNS.identity);
  if(sessionChanged&&unknownIP)
   return result(.96,PATTERNS.session);
  if(groupChange&&command&&executed)
   return result(.97,PATTERNS.group);
 }
 const suspicious=isAdmin||groupAdd||command||sessionChanged||unknownIP||offHours
  ||/권한|계정\s*종류|그룹|명령|파일\s*권한|privilege|group\s*change/iu.test(text);
 if(suspicious&&level>=4)return result(level>=8?.74:.62,PATTERNS.review);
 return result(.06,PATTERNS.normal);
}
