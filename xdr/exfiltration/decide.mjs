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
 const m=v.trim().match(/(\d+(?:\.\d+)?)\s*(?:bytes?|B|KB|KIB|MB|MIB|GB|GIB|TB|TIB)?/iu);
 const unit=(v.match(/\d(?:\.\d+)?\s*(bytes?|KB|KIB|MB|MIB|GB|GIB|TB|TIB)\b/iu)||[])[1]||"B";
 return m?Number(m[1])*({B:1,BYTE:1,BYTES:1,KB:1e3,KIB:1024,MB:1048576,MIB:1048576,GB:1073741824,GIB:1073741824,TB:1099511627776,TIB:1099511627776}[unit.toUpperCase()]||1):0;
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
 const destination=first(d.dstip,d.dstIp,d.dst_ip,d.dest_ip,d.destination_ip,d.destinationIp,d.remote_ip,d.remoteIp,d.remote_addr,d.remoteAddress,d.dst,dest.ip,dest.address,dest.host,typeof d.destination==="string"?d.destination:undefined,net.dstip,net.dst_ip,net.destination?.ip,a.destination?.ip,a.dstip);
 const sz=Math.max(bytes(first(d.bytes_sent,d.bytesSent,d.outboundBytes,d.outbound_bytes,d.bytes_out,d.bytesOut,d.bytes_outbound,d.sent_bytes,d.sentBytes,d.bytesTransferred,d.bytes_transferred,d.transfer_bytes,d.transferBytes,net.bytes_sent,net.bytes_out,tx.bytesSent,tx.bytes,tx.size,d.fileSize,f.size,d.bytes,d.size)),bytes(d.size_mb)*1048576,bytes(d.transfer_size_mb)*1048576,bytes(d.transferSizeMb)*1048576,bytes(d.size_gb)*1073741824, ...[...context.matchAll(/\d+(?:\.\d+)?\s*(?:TB|TIB|GB|GIB|MB|MIB|KB|KIB)\b/giu)].map(m=>bytes(m[0])),0);
 const outbound=/^(?:out|outbound|egress|upload|sent|external)$/iu.test(s(first(d.direction,net.direction,tx.direction)))
   ||[d.bytes_sent,d.bytesSent,d.outboundBytes,d.outbound_bytes,d.bytes_out,d.bytesOut,d.bytes_outbound,d.sent_bytes,d.sentBytes,tx.bytesSent].some(v=>v!==undefined)
   ||/\b(?:outbound|outgoing|egress|upload(?:ed|ing)?|sent|sending|exfiltrat(?:ion|ed)|export(?:ed)?|transferr?(?:ed|ing)?)\b|외부\s*전송|외부\s*반출|유출|업로드|반출|송신|전송/iu.test(context);
 const external=externalIP(destination)||d.externalDestination===true||d.isExternal===true||d.is_external===true||dest.external===true||net.external===true||/\b(?:external|internet|off[- ]?site|remote (?:server|host|destination))\b|외부\s*(?:주소|목적지|서버|전송|반출)|바깥\s*주소|대외\s*전송/iu.test(context);
 const unknown=d.newDestination===true||d.firstSeenDestination===true||d.firstSeen===true||d.destinationKnown===false||d.knownDestination===false||d.isNewDestination===true||d.destination_first_seen===true||d.first_seen_destination===true||d.new_dst===true||dest.firstSeen===true||dest.new===true
  ||/(?:first[- ]?seen|never[- ]?seen|previously unseen|new|unknown|unfamiliar|rare).{0,40}(?:destination|remote (?:ip|host|address)|external (?:ip|host|address))|(?:destination|external (?:ip|host|address)).{0,24}(?:first[- ]?seen|unknown|unseen)|처음\s*(?:보는|관측|확인)|최초\s*(?:접속|전송)|신규\s*(?:목적지|외부\s*주소)|미등록\s*(?:목적지|서버)|낯선\s*(?:주소|목적지)/iu.test(context);
 const large=sz>=100*1048576||d.largeTransfer===true||d.unusuallyLarge===true||d.volumeAnomaly===true||d.isLargeTransfer===true||d.largeUpload===true||d.bulkTransfer===true||d.volume_anomaly===true||tx.unusuallyLarge===true
  ||/(?:large|bulk|massive|oversized|unusual(?:ly)?\s*(?:large|high)).{0,28}(?:file|transfer|upload|data|volume)|대용량|대량\s*(?:전송|반출|유출|파일)|평소보다\s*(?:큰|많은)|비정상적\s*(?:전송량|용량)/iu.test(context);
 const off=d.outsideBusinessHours===true||d.offHours===true||d.afterHours===true||d.off_hours===true||d.after_hours===true||d.outside_business_hours===true||tx.offHours===true
  ||/\b(?:off[- ]?hours|after[- ]?hours|outside (?:working|business) hours|nighttime)\b|업무\s*시간\s*(?:외|밖)|근무\s*시간\s*(?:외|밖)|심야|야간/iu.test(context);
 const filename=s(first(d.filename,d.fileName,d.file_path,d.filePath,d.path,f.name,f.path,tx.fileName));
 const archive=d.compressedFile===true||d.isArchive===true||d.archive===true||d.isCompressed===true||d.compressed===true||f.compressed===true||/\.(?:zip|7z|rar|tar|tgz|gz|bz2|xz)(?:\?|$)/iu.test(filename)
  ||/\b(?:archive|compressed|zip file|tarball)\b|압축\s*(?:파일|자료)|압축파일/iu.test(context);
 const approved=d.approved===true||d.authorized===true||d.allowlisted===true||d.whitelisted===true||d.baselineKnown===true||d.sanctioned===true||d.expected===true||(/\b(?:approved|authorized|authorised|allowlisted|routine|scheduled backup)\b|승인된|허용된|정상\s*(?:업무|전송|백업)|정기\s*백업/iu.test(context)&&!/\b(?:unapproved|unauthorized|unauthorised|not approved)\b|미승인|승인\s*없이|무단\s*(?:전송|반출)/iu.test(context));
 const unapproved=d.approved===false||d.authorized===false||d.expected===false;
 const severity=Number(first(r.level,a.ruleLevel))||0;
 const t=tagged(r);
 const relevant=t||/\b(?:exfiltrat(?:ion|ed)|data transfer|file upload|external upload)\b|자료\s*(?:유출|반출)|정보\s*유출/iu.test(context);
 function result(n,reason){return {action:n>=.85?"block":n>=.5?"alert":"record",confidence:n,reason}}
 if(approved&&!unapproved)return result(.04,PATTERNS.normal);
 if(!external||!outbound)return result(.08,PATTERNS.normal);
 if(unknown&&large)return result(.97,PATTERNS.large);
 if(off&&archive&&severity>=9&&(large||unapproved||unknown)&&(tagged||relevant))return result(.94,PATTERNS.archive);
 if(unknown||large||off&&archive||t)return result(severity>=8?.73:.63,PATTERNS.review);
 return result(.08,PATTERNS.normal);
}
