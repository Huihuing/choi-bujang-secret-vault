import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const DEFAULT=new URL('../fixtures/privilege.json',import.meta.url);
function redact(value){
 if(typeof value!=='string')return null;
 const s=value.replace(/[\r\n\t]+/gu,' ').slice(0,500);
 if(/-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\bsb_(?:secret|publishable)_\S+|\beyJ[A-Za-z0-9_-]{12,}\./iu.test(s))return '[redacted]';
 return s.replace(/\b(?:password|passwd|token|secret|api[-_ ]?key|authorization|cookie)\s*[:=]\s*[^\s,;]+/giu,'[redacted]');
}
export function extract(alert){
 const stamp=alert?.timestamp??alert?.['@timestamp']??alert?.time??null;
 const src=alert?.data?.srcip??alert?.source?.ip??alert?.srcip??null;
 const user=alert?.data?.srcuser??alert?.data?.dstuser??alert?.account??null;
 const level=Number(alert?.rule?.level??alert?.ruleLevel);
 return {
  time:typeof stamp==='string'&&Number.isFinite(Date.parse(stamp))?new Date(stamp).toISOString():null,
  sourceIp:typeof src==='string'&&isIP(src)?src:null,
  account:typeof user==='string'&&/^[A-Za-z0-9_.-]{1,48}$/u.test(user)?user:user==null?null:'[redacted]',
  ruleLevel:Number.isInteger(level)&&level>=0&&level<=16?level:null,
  description:redact(alert?.rule?.description??alert?.description??null),
 };
}
export function parseAlerts(source){
 const parsed=typeof source==='string'?JSON.parse(source):source;
 const alerts=Array.isArray(parsed)?parsed:parsed?.alerts;
 if(!Array.isArray(alerts))throw new TypeError('Expected Wazuh alerts array');
 return alerts.map(extract);
}
export async function readAlerts(path=DEFAULT){
 return parseAlerts(await readFile(path,'utf8'));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const alerts=await readAlerts(process.argv[2]??DEFAULT);
  for(const item of alerts)console.log(JSON.stringify(item));
  console.error('alerts='+alerts.length+' extracted='+alerts.length);
 }catch{console.error('Could not read privilege fixture');process.exitCode=1;}
}
