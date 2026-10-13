import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const DEFAULT=new URL('../fixtures/known-cve.json',import.meta.url);
function redact(value){
 if(typeof value!=='string')return null;
 let text=value.replace(/[\r\n]+/gu,' ').slice(0,500);
 // Never print passwords, API tokens, private keys or captured credentials.
 if(/-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\beyJ[A-Za-z0-9_-]{12,}\.|\bsb_(?:secret|publishable)_\S+/iu.test(text))
  return '[redacted]';
 text=text.replace(/\b(?:password|passwd|token|secret|api[-_ ]?key|authorization|cookie)\s*[:=]\s*[^\s,;]+/giu,'[redacted]');
 return text;
}
export function extract(alert){
 const when=alert?.timestamp??alert?.['@timestamp']??alert?.time??null;
 const ip=alert?.data?.srcip??alert?.srcip??alert?.source?.ip??null;
 const account=alert?.data?.srcuser??alert?.data?.dstuser??alert?.account??null;
 const level=Number(alert?.rule?.level??alert?.ruleLevel);
 return {
  time:typeof when==='string'&&Number.isFinite(Date.parse(when))
   ?new Date(when).toISOString():null,
  sourceIp:typeof ip==='string'&&isIP(ip)?ip:null,
  account:typeof account==='string'&&/^[A-Za-z0-9_.-]{1,48}$/u.test(account)
   ?account:account==null?null:'[redacted]',
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
export async function readAlerts(url=DEFAULT){
 return parseAlerts(await readFile(url,'utf8'));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const data=await readAlerts(process.argv[2]??DEFAULT);
  data.forEach(a=>console.log(JSON.stringify(a)));
  console.error('alerts='+data.length+' extracted='+data.length);
 }catch(error){console.error('Unable to read known-cve Wazuh fixture');process.exitCode=1;}
}
