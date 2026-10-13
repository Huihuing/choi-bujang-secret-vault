import {createClient} from '@supabase/supabase-js';
import config from '../aleph.config.json' with {type:'json'};
import {createLoginVerifier} from './verify-login.mjs';

export function sendNoticeJson(response,status,body) {
  response.status(status);
  response.setHeader('Content-Type','application/json; charset=utf-8');
  response.setHeader('Cache-Control','no-store');
  return response.json(body);
}
export function noticeBody(request) {
  let value=request.body;
  if (typeof value==='string') {
    try {value=JSON.parse(value);} catch{return null;}
  }
  if (!value || typeof value!=='object' || Array.isArray(value)
      || Object.keys(value).sort().join(',')!=='body,title') return null;
  if (typeof value.title!=='string'||typeof value.body!=='string') return null;
  const title=value.title.trim(),content=value.body.trim();
  return title && content && title.length<=120 && content.length<=4000 ? {title,content}:null;
}
export async function noticeContext(request,response) {
  const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
  if (!url||!key) {sendNoticeJson(response,503,{error:'server_not_configured'});return null;}
  const supabase=createClient(url,key,{auth:{
    autoRefreshToken:false,persistSession:false,detectSessionInUrl:false,
  }});
  let verify;
  try { verify=createLoginVerifier({config,supabaseSecretKey:key,supabaseClient:supabase}); }
  catch {sendNoticeJson(response,503,{error:'login_verifier_not_configured'});return null;}
  const login=await verify(request.headers?.authorization);
  if (!login) {sendNoticeJson(response,401,{error:'authentication_required'});return null;}
  return {supabase,login};
}
