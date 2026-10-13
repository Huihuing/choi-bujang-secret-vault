import {randomUUID} from 'node:crypto';
import {exactResourcePath,hasStoredInstructorAccess} from '../src/resource-zones.mjs';
import {noticeBody,noticeContext,sendNoticeJson} from '../src/notice-api-context.mjs';

export default async function handler(request,response) {
  if (!['GET','POST'].includes(request.method)) {
    response.setHeader('Allow','GET, POST');
    return sendNoticeJson(response,405,{error:'method_not_allowed'});
  }
  if (!exactResourcePath(request.url,'instructor-notices')) {
    return sendNoticeJson(response,400,{error:'invalid_resource_path'});
  }
  const ctx=await noticeContext(request,response);
  if (!ctx) return;
  if (request.method==='GET') {
    const {data,error}=await ctx.supabase.from('instructor_notices')
      .select('id,title,content,created_at').order('created_at',{ascending:true}).order('id',{ascending:true});
    if (error) return sendNoticeJson(response,503,{error:'notices_unavailable'});
    return sendNoticeJson(response,200,{notices:(data??[]).map(n=>({id:n.id,title:n.title,body:n.content}))});
  }
  let authorized=false;
  try {authorized=await hasStoredInstructorAccess(ctx.supabase,ctx.login);}
  catch {return sendNoticeJson(response,503,{error:'instructor_permission_unavailable'});}
  if (!authorized) return sendNoticeJson(response,403,{error:'instructor_required'});
  const input=noticeBody(request);
  if (!input) return sendNoticeJson(response,400,{error:'invalid_notice'});
  const id=randomUUID();
  const {error}=await ctx.supabase.from('instructor_notices').insert({id,...input});
  if (error) return sendNoticeJson(response,503,{error:'notice_create_failed'});
  return sendNoticeJson(response,201,{id});
}
