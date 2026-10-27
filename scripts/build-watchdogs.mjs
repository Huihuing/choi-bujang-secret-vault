import {lstat,mkdir,readFile,readdir,writeFile} from 'node:fs/promises';
import {isAbsolute,join,resolve} from 'node:path';

const FILES=Object.freeze(['index.html','app.js','style.css']);
async function inspect(path,kind,{optional=false}={}){
 let stat;
 try{stat=await lstat(path);}catch(error){if(optional&&error.code==='ENOENT')return false;throw error;}
 if(stat.isSymbolicLink()||(kind==='directory'?!stat.isDirectory():!stat.isFile()||stat.nlink!==1))
  throw Error('WATCHDOGS_UNSAFE_PATH');
 return true;
}

// Only these public UI files are built. Collectors, launchers, configuration,
// credentials, tests and runtime data never enter the hosted static directory.
export async function buildWatchdogsAssets({root}={}){
 if(typeof root!=='string'||!isAbsolute(root))throw Error('WATCHDOGS_ROOT_REQUIRED');
 const project=resolve(root),source=join(project,'on-client','student','pc-monitor');
 const publicRoot=join(project,'public'),output=join(publicRoot,'watchdogs');
 await inspect(project,'directory');
 for(const part of [join(project,'on-client'),join(project,'on-client','student'),source])
  await inspect(part,'directory');
 const assets=new Map();
 for(const name of FILES){
  const path=join(source,name);await inspect(path,'file');assets.set(name,await readFile(path));
 }
 let html=assets.get('index.html').toString('utf8');
 if(!/<html\b[^>]*>/i.test(html)||!/<\/head>/i.test(html)
  ||!(/\bsrc\s*=\s*["']\/app\.js["']/i.test(html))
  ||!(/\bhref\s*=\s*["']\/style\.css["']/i.test(html)))
  throw Error('WATCHDOGS_HTML_CONTRACT_MISMATCH');
 html=html.replace(/<html\b[^>]*>/i,tag=>tag
  .replace(/\sdata-watchdogs-hosted(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?/gi,'')
  .replace(/>$/,' data-watchdogs-hosted="true">'))
  .replace(/(\bsrc\s*=\s*["'])\/app\.js(["'])/gi,'$1/watchdogs/app.js$2')
  .replace(/(\bhref\s*=\s*["'])\/style\.css(["'])/gi,'$1/watchdogs/style.css$2');
 assets.set('index.html',Buffer.from(html,'utf8'));
 await inspect(publicRoot,'directory',{optional:true});
 if(await inspect(output,'directory',{optional:true})){
  if((await readdir(output)).some(name=>!FILES.includes(name)))throw Error('WATCHDOGS_UNEXPECTED_OUTPUT');
  for(const name of FILES)await inspect(join(output,name),'file',{optional:true});
 }
 await mkdir(output,{recursive:true});
 for(const [name,bytes] of assets)await writeFile(join(output,name),bytes);
 return {directory:output,files:[...FILES]};
}
