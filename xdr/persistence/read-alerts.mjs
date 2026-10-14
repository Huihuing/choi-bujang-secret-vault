import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const DEFAULT=new URL('../fixtures/persistence.json',import.meta.url);
function cleanDescription(value){
 if(typeof value!=='string')return null;
 const s=value.replace(/[\r\n\t]+/gu,' ').slice(0,500);
 if(/-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\bsb_(?:secret|publishable)_\S+|\beyJ[A-Za-z0-9_-]{12,}\./iu.test(s))return '[redacted]';
 return s.replace(/\b(?:password|passwd|token|secret|api[-_ ]?key|authorization|cookie)\s*[:=]\s*[^\s,;]+/giu,'[redacted]');
}
export function extract(alert){
 const timestamp=alert?.timestamp??alert?.['@timestamp']??alert?.time??null;
 const ip=alert?.data?.srcip??alert?.source?.ip??alert?.srcip??null;
 const user=alert?.data?.srcuser??alert?.data?.dstuser??alert?.account??null;
 const level=Number(alert?.rule?.level??alert?.ruleLevel);
 return {
  time:typeof timestamp==='string'&&Number.isFinite(Date.parse(timestamp))?new Date(timestamp).toISOString():null,
  sourceIp:typeof ip==='string'&&isIP(ip)?ip:null,
  account:typeof user==='string'&&/^[A-Za-z0-9_.-]{1,48}$/u.test(user)?user:user==null?null:'[redacted]',
  ruleLevel:Number.isInteger(level)&&level>=0&&level<=16?level:null,
  description:cleanDescription(alert?.rule?.description??alert?.description??null),
 };
}
export function parseAlerts(source){
 const parsed=typeof source==='string'?JSON.parse(source):source;
 const rows=Array.isArray(parsed)?parsed:parsed?.alerts;
 if(!Array.isArray(rows))throw new TypeError('Expected Wazuh alert array');
 return rows.map(extract);
}
export async function readAlerts(path=DEFAULT){
 return parseAlerts(await readFile(path,'utf8'));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const entries=await readAlerts(process.argv[2]??DEFAULT);
  for(const row of entries)console.log(JSON.stringify(row));
  console.error('alerts='+entries.length+' extracted='+entries.length);
 }catch{console.error('Unable to parse persistence Wazuh fixture');process.exitCode=1;}
}
