import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const DEFAULT=new URL('../fixtures/exfiltration.json',import.meta.url);
function redact(value){
 if(typeof value!=='string')return null;
 const s=value.replace(/[\r\n\t]+/gu,' ').slice(0,500);
 if(/-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\beyJ[A-Za-z0-9_-]{12,}\./iu.test(s))return '[redacted]';
 return s.replace(/\b(?:password|passwd|token|secret|api[-_ ]?key|authorization|cookie)\s*[:=]\s*[^\s,;]+/giu,'[redacted]');
}
export function extract(alert){
 const time=alert?.timestamp??alert?.['@timestamp']??alert?.time;
 const src=alert?.data?.srcip??alert?.source?.ip??alert?.srcip;
 const account=alert?.data?.srcuser??alert?.data?.user??alert?.account;
 const level=Number(alert?.rule?.level??alert?.ruleLevel);
 return {
  time:typeof time==='string'&&Number.isFinite(Date.parse(time))?new Date(time).toISOString():null,
  sourceIp:typeof src==='string'&&isIP(src)?src:null,
  account:typeof account==='string'&&/^[A-Za-z0-9_.-]{1,64}$/u.test(account)?account:account==null?null:'[redacted]',
  ruleLevel:Number.isInteger(level)&&level>=0&&level<=16?level:null,
  description:redact(alert?.rule?.description??alert?.description??null)
 };
}
export function parseAlerts(source){
 const json=typeof source==='string'?JSON.parse(source):source;
 const alerts=Array.isArray(json)?json:json?.alerts;
 if(!Array.isArray(alerts))throw new TypeError('Expected Wazuh alerts');
 return alerts.map(extract);
}
export async function readAlerts(path=DEFAULT){return parseAlerts(await readFile(path,'utf8'));}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const rows=await readAlerts(process.argv[2]??DEFAULT);
  for(const row of rows)console.log(JSON.stringify(row));
  console.error('alerts='+rows.length+' extracted='+rows.length);
 }catch{console.error('Could not load exfiltration alerts');process.exitCode=1;}
}
