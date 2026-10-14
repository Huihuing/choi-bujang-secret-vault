// Pure synchronous XDR-06 decision; original Wazuh facts only. No imports or I/O.
const P=Object.freeze({
  "bulk": "new-destination-bulk-exfiltration",
  "archive": "off-hours-archive-exfiltration",
  "repeat": "repeated-large-transfer",
  "alternate": "unusual-port-bulk-transfer",
  "whole": "whole-repository-transfer",
  "c2": "c2-repeated-transfer",
  "compressed": "consecutive-archives-new-destination",
  "review": "outbound-transfer-review",
  "normal": "normal-transfer"
});

function object(x){return x!==null&&typeof x==="object"&&!Array.isArray(x)?x:{}}

function field(x,...paths){for(const path of paths){let v=x;for(const part of path.split("."))v=v?.[part];if(v!==undefined&&v!==null&&v!=="")return v}return undefined}

function asText(x){return typeof x==="string"?x.slice(0,1100):""}

function amount(x){
 if(typeof x==="number")return Number.isFinite(x)&&x>=0?x:0;
 if(typeof x!=="string")return 0;
 const m=x.trim().match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|MiB|GB|GiB|TB|TiB)?$/iu);
 if(!m)return 0;
 return Number(m[1])*({B:1,KB:1e3,MB:1e6,MIB:1048576,GB:1e9,GIB:1073741824,TB:1e12,TIB:1099511627776}[String(m[2]||"B").toUpperCase()]||1);
}

function externalAddress(x){
 if(typeof x!=="string")return false;
 const m=x.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
 if(m){const a=m.slice(1).map(Number);if(a.some(n=>n>255))return false;return !(a[0]===0||a[0]===10||a[0]===127||a[0]>=224||(a[0]===172&&a[1]>=16&&a[1]<=31)||(a[0]===192&&a[1]===168)||(a[0]===169&&a[1]===254));}
 if(/^[a-f0-9:]+$/iu.test(x)&&x.includes(":"))return !/^(?:fe80|fc|fd|::1)/iu.test(x);
 return /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/iu.test(x)&&!/\.(?:local|internal|localhost)$/iu.test(x);
}

function bool(x){
 if(x===true||x===1)return true;
 if(x===false||x===0)return false;
 if(typeof x!=="string")return null;
 return /^(?:true|yes|1|new|unknown)$/iu.test(x)?true:/^(?:false|no|0|known)$/iu.test(x)?false:null;
}

export function decide(alert){
 const a=object(alert),d=object(a.data),r=object(a.rule);
 const desc=asText(field(r,"description")??field(a,"description"));
 const text=(desc+" "+asText(field(d,"action","operation","event_type","message"))).toLowerCase();
 const dest=field(d,"dstip","dstIp","dst_ip","dest_ip","destIp","destination_ip","destinationIp","destination.ip","remote_ip","remoteIp","network.dstip","flow.dst_ip")??field(a,"destination.ip","dstip");
 const size=Math.max(amount(field(d,"bytes","bytes_sent","bytesSent","bytes_out","outboundBytes","outbound_bytes","transferBytes","transfer_bytes","transfer.bytes","file.size","size")),amount(field(d,"size_mb","transfer_size_mb"))*1e6);
 const typical=amount(field(d,"avg_bytes","baselineBytes","baseline_bytes","usualBytes","transfer.baselineBytes"));
 const large=size>=50000000||(size>=10000000&&typical>=1000000&&size>=typical*5);
 const files=amount(field(d,"files","file_count","filesSent","files_sent"));
 const repeats=amount(field(d,"count","transferCount","repeats","transfers"));
 const severity=Number(field(r,"level")??field(a,"ruleLevel"))||0;
 const mitre=field(r,"mitre")??field(a,"mitre"),tags=Array.isArray(mitre)?mitre:Array.isArray(mitre?.id)?mitre.id:typeof mitre?.id==="string"?[mitre.id]:[];
 const technique=tags.some(t=>typeof t==="string"&&/^T(?:1041|1048)(?:\.|$)/u.test(t));
 const direction=asText(field(d,"direction","flow.direction","network.direction","transfer.direction")).toLowerCase();
 const inbound=/^(?:in|inbound|receive|received|download|ingress)$/u.test(direction);
 const approved=d.approved===true||d.authorized===true||d.allowlisted===true||d.expected===true||/\b(?:approved|authorized|routine|allowlisted|scheduled backup)\b|승인된|허용된|정상\s*(?:업무|전송|백업)/iu.test(text);
 const unapproved=d.approved===false||d.authorized===false||/\b(?:unapproved|unauthorized)\b|미승인|무단\s*반출/iu.test(text);
 const novel=bool(field(d,"newDestination","firstSeenDestination","destination_first_seen","firstSeen","isNewDestination","destination.new"))===true||d.destinationKnown===false
  ||/처음\s*보는\s*(?:목적지|주소)|평소와\s*다른\s*주소|신규\s*(?:목적지|주소)|낯선\s*(?:목적지|주소)|first[- ]?seen|new destination|unknown destination/iu.test(text);
 const offHours=bool(field(d,"offHours","outsideBusinessHours","off_hours","afterHours","outside_business_hours"))===true
  ||/(?:수업|업무|근무)\s*시간\s*(?:밖|외)|after[- ]?hours|off[- ]?hours|overnight|야간/iu.test(text);
 const archive=d.compressedFile===true||d.isArchive===true||/압축\s*파일|\.zip\b|compressed|archive/iu.test(text+" "+asText(field(d,"filename","fileName","file.name")));
 const repeated=repeats>=3||/연속|반복|\d+\s*번|repeated|consecutive/iu.test(text);
 const sameDestination=/같은\s*목적지|same destination/iu.test(text);
 const multipleDestinations=/목적지\s*(?:두|여러|\d+)\s*곳|multiple destinations/iu.test(text);
 const command=/명령\s*통로|C2 channel|command.and.control/iu.test(text);
 const unusualPort=/평소에\s*쓰지\s*않던\s*포트|비표준\s*포트|unusual port/iu.test(text);
 const manyDocuments=/메모\s*묶음|자료\s*\d+\s*건|묶음|batch of files/iu.test(text);
 const wholeRepository=/자료실\s*전체|whole repository|entire repository/iu.test(text);
 const outbound=/나갔|올라갔|전송|송신|반출|복사됐|유출|uploaded|sent|outbound|egress/iu.test(text)
  ||/^(?:out|outbound|egress|upload|sent)$/iu.test(direction)||field(d,"bytes_sent","bytes_out","outboundBytes")!==undefined;
 const external=externalAddress(dest)||d.externalDestination===true||/외부\s*(?:주소|목적지)|external destination/iu.test(text);
 function result(confidence,reason){return {action:confidence>=.85?"block":confidence>=.5?"alert":"record",confidence,reason}}
 if(inbound||approved&&!unapproved)return result(.05,P.normal);
 if(severity<=3&&size<1000000)return result(.06,P.normal);
 if(external&&outbound&&large&&severity>=9){
  if(offHours&&archive&&novel)return result(.98,P.archive);
  if(command&&repeated&&novel&&(repeats>=3||severity>=11))return result(.97,P.c2);
  if(unusualPort&&files>=50)return result(.96,P.alternate);
  if(wholeRepository&&files>=100)return result(.99,P.whole);
  if(archive&&novel&&repeated&&files>=3)return result(.96,P.compressed);
  if(archive&&novel&&multipleDestinations)return result(.95,P.compressed);
  if(sameDestination&&repeated&&repeats>=5)return result(.96,P.repeat);
  if(novel&&(files>=50||manyDocuments||archive&&offHours))return result(.97,P.bulk);
 }
 const hint=novel||offHours||archive||command||unusualPort||repeated||manyDocuments||large
  ||/전송|나갔|압축|목적지|파일|자료\s*\d+\s*건|백업|transfer|upload|외부|읽힌\s*뒤/iu.test(text);
 if(hint&&(severity>=4||technique))return result(severity>=8?.76:.64,P.review);
 return result(.08,P.normal);
}
