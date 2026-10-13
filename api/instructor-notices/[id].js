import {exactResourcePath,hasStoredInstructorAccess} from '../../src/resource-zones.mjs';
import {noticeBody,noticeContext,sendNoticeJson} from '../../src/notice-api-context.mjs';

export default async function handler(request,response) {
  if (!['GET','PUT'].includes(request.method)) {
    response.setHeader('Allow','GET, PUT');
    return sendNoticeJson(response,405,{error:'method_not_allowed'});
  }
  const id=exactResourcePath(request.url,'instructor-notices',true);
  if (!id) return sendNoticeJson(response,400,{error:'invalid_notice_id'});
  const ctx=await noticeContext(request,response);
  if (!ctx) return;
  if (request.method==='PUT') {
    let instructor=false;
    try {instructor=await hasStoredInstructorAccess(ctx.supabase,ctx.login);}
    catch {return sendNoticeJson(response,503,{error:'instructor_permission_unavailable'});}
    if (!instructor) return sendNoticeJson(response,403,{error:'instructor_required'});
    const input=noticeBody(request);
    if (!input) return sendNoticeJson(response,400,{error:'invalid_notice'});
    const {data,error}=await ctx.supabase.from('instructor_notices')
      .update({...input,updated_at:new Date().toISOString()})
      .eq('id',id).select('id,title,content').maybeSingle();
    if (error) return sendNoticeJson(response,503,{error:'notice_update_failed'});
    if (!data) return sendNoticeJson(response,404,{error:'notice_not_found'});
    response.setHeader('X-Resource-Id','instructor-notices:'+id);
    return sendNoticeJson(response,200,{id:data.id,title:data.title,body:data.content});
  }
  const {data,error}=await ctx.supabase.from('instructor_notices')
    .select('id,title,content').eq('id',id).maybeSingle();
  if (error) return sendNoticeJson(response,503,{error:'notices_unavailable'});
  if (!data) return sendNoticeJson(response,404,{error:'notice_not_found'});
  response.setHeader('X-Resource-Id','instructor-notices:'+id);
  return sendNoticeJson(response,200,{id:data.id,title:data.title,body:data.content});
}
