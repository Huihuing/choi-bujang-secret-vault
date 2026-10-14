// Pure offline detector. No imports, IO or network. PATTERNS mirror patterns.json.
const PATTERNS=Object.freeze({
  "large": "new-destination-bulk-exfiltration",
  "archive": "off-hours-archive-exfiltration",
  "review": "outbound-transfer-review",
  "normal": "normal-transfer"
});
function obj(v){return v&&typeof v==="object"&&!Array.isArray(v)?v:{}}

function s(v){return typeof v==="string"?v.slice(0,1200):""}

function first(...a){return a.find(x=>x!==undefined&&x!==null)}

function bytes(v){
 if(typeof v==="number")return Number.isFinite(v)&&v>=0?v:0;
 if(typeof v!=="string")return 0;
 const m=v.trim().match(/^(\d+(?:\.\d+)?)\s*(B|KB|KIB|MB|MIB|GB|GIB)?$/iu);
 return m?Number(m[1])*({B:1,KB:1e3,KIB:1024,MB:1e6,MIB:1048576,GB:1e9,GIB:1073741824}[String(m[2]||"B").toUpperCase()]):0;
}

function tagged(r){
 const v=r?.mitre,a=Array.isArray(v)?v:Array.isArray(v?.id)?v.id:typeof v?.id==="string"?[v.id]:[];
 return a.some(x=>typeof x==="string"&&/^T(?:1041|1048)(?:\.|$)/u.test(x));
}

function externalIP(ip){
 if(typeof ip!=="string")return false;
 const m=ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
 if(!m)return /^[0-9a-f:]+$/iu.test(ip)&&ip.includes(":")&&!/^fe80:|^fc|^fd|^::1$/iu.test(ip);
 const v=m.slice(1).map(Number);if(v.some(n=>n>255))return false;
 return !(v[0]===0||v[0]===10||v[0]===127||v[0]>=224||(v[0]===172&&v[1]>=16&&v[1]<=31)||(v[0]===192&&v[1]===168)||(v[0]===169&&v[1]===254));
}

export function decide(a){
 a=obj(a);
 const r=obj(a.rule),d=obj(a.data),net=obj(d.network),tx=obj(d.transfer),f=obj(d.file),dest=obj(d.destination);
 const description=s(first(r.description,a.description));
 const context=(description+" "+s(first(d.operation,d.action,d.event_type))+" "+s(first(d.protocol,tx.protocol))).toLowerCase();
 const destination=first(d.dstip,d.dstIp,d.destination_ip,d.destinationIp,d.remote_ip,d.remoteIp,dest.ip,net.dstip);
 const sz=bytes(first(d.bytes_sent,d.bytesSent,d.outboundBytes,d.outbound_bytes,d.bytes_out,d.bytesOut,d.transfer_bytes,d.transferBytes,tx.bytesSent,tx.bytes,tx.size,d.fileSize,f.size,d.bytes));
 const outbound=/^(?:out|outbound|egress|upload|sent|external)$/iu.test(s(first(d.direction,net.direction,tx.direction)))
   ||[d.bytes_sent,d.bytesSent,d.outboundBytes,d.outbound_bytes,d.bytes_out,d.bytesOut,tx.bytesSent].some(v=>v!==undefined)
   ||/\b(?:outbound|egress|upload(?:ed|ing)?|sent|sending|exfiltrat(?:ion|ed)|export(?:ed)?)\b|외부\s*전송|외부\s*반출|유출|업로드|반출/iu.test(context);
 const external=externalIP(destination)||d.externalDestination===true||dest.external===true||net.external===true;
 const unknown=d.newDestination===true||d.firstSeenDestination===true||d.firstSeen===true||d.destinationKnown===false||d.isNewDestination===true
  ||/(?:first[- ]?seen|never[- ]?seen|new|unknown|unfamiliar).{0,28}(?:destination|external (?:ip|host|address))|처음\s*(?:보는|관측된?)\s*(?:목적지|외부\s*주소)|신규\s*목적지|낯선\s*(?:주소|목적지)/iu.test(context);
 const large=sz>=100*1048576||d.largeTransfer===true||d.unusuallyLarge===true||d.volumeAnomaly===true||tx.unusuallyLarge===true
  ||/(?:large|bulk|massive|unusual(?:ly)?\s*(?:large|high))\s*(?:file|transfer|upload|data)|대용량|대량\s*(?:전송|반출|유출)/iu.test(context);
 const off=d.outsideBusinessHours===true||d.offHours===true||d.afterHours===true||tx.offHours===true
  ||/\b(?:off[- ]?hours|after[- ]?hours|outside (?:working|business) hours|nighttime)\b|업무\s*시간\s*(?:외|밖)|근무\s*시간\s*(?:외|밖)|심야|야간/iu.test(context);
 const filename=s(first(d.filename,d.fileName,d.path,f.name,f.path,tx.fileName));
 const archive=d.compressedFile===true||d.isArchive===true||f.compressed===true||/\.(?:zip|7z|rar|tar|tgz|gz|bz2|xz)(?:\?|$)/iu.test(filename)
  ||/\b(?:archive|compressed|zip file|tarball)\b|압축\s*(?:파일|자료)|압축파일/iu.test(context);
 const approved=d.approved===true||d.authorized===true||d.allowlisted===true||d.baselineKnown===true||d.sanctioned===true||d.expected===true;
 const unapproved=d.approved===false||d.authorized===false||d.expected===false;
 const severity=Number(first(r.level,a.ruleLevel))||0;
 const t=tagged(r);
 const relevant=t||/\b(?:exfiltrat(?:ion|ed)|data transfer|file upload|external upload)\b|자료\s*(?:유출|반출)|정보\s*유출/iu.test(context);
 function result(n,reason){return {action:n>=.85?"block":n>=.5?"alert":"record",confidence:n,reason}}
 if(approved&&!unapproved)return result(.04,PATTERNS.normal);
 if(!external||!outbound)return result(.08,PATTERNS.normal);
 if(unknown&&large&&relevant&&severity>=10)return result(.97,PATTERNS.large);
 if(off&&archive&&(large||unapproved)&&relevant&&severity>=10)return result(.94,PATTERNS.archive);
 if(unknown||large||off&&archive||t)return result(severity>=8?.73:.63,PATTERNS.review);
 return result(.08,PATTERNS.normal);
}
