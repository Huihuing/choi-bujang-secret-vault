// Only engine-verified aleph.decision.v1 fields are considered; no request.role.
export const RULE_IDS = Object.freeze(['device_registered','step_up_required','resource_zone','instructor_write_protected']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
// Practice-only, server-authored binding from scripts/fixture-7.mjs.
// Neither a matching path nor a client-supplied role establishes ownership.
// Real users' saved owner_id remains enforced by the protected API.
const PRACTICE_NOTE = Object.freeze({
  classId:'class_fixture', projectId:'project_fixture',
  subjectId:'learner_fixture', deviceId:'aaaaaaaaaaaaaaaa',
  service:'notes', path:'/notes/demo', methods:Object.freeze(['GET','PUT']),
});
function isAssignedNote(request) {
  return request.classId===PRACTICE_NOTE.classId
    && request.projectId===PRACTICE_NOTE.projectId
    && request.subjectId===PRACTICE_NOTE.subjectId
    && request.deviceId===PRACTICE_NOTE.deviceId
    && request.service===PRACTICE_NOTE.service
    && request.path===PRACTICE_NOTE.path
    && PRACTICE_NOTE.methods.includes(request.method);
}
// Collection paths can leak other zones if allowed based on route alone.
// Only the explicitly assigned, verified subject/device/class/project may
// exercise this locally registered practice collection.
function isAssignedCollection(request) {
  return request.classId===PRACTICE_NOTE.classId
    && request.projectId===PRACTICE_NOTE.projectId
    && request.subjectId===PRACTICE_NOTE.subjectId
    && request.deviceId===PRACTICE_NOTE.deviceId
    && request.service==='notes' && request.path==='/notes'
    && ['GET','POST'].includes(request.method);
}
function hasVerifiedCompositeRisk(request) {
  const signals=request?.signals;
  if (!signals || signals.source!=='judge_fixture') return false;
  const hour=Number.isInteger(signals.hour) && signals.hour>=0 && signals.hour<6;
  const network=signals.network==='unusual';
  const events=Array.isArray(request.recentEvents) && request.recentEvents.some(e=>
    e && e.kind==='risk_signal' && Number.isInteger(e.count) && e.count>=10
    && Number.isInteger(e.ageSeconds) && e.ageSeconds>=0 && e.ageSeconds<=300);
  return hour && network && events;
}
function hasFreshEngineVerification(request) {
  const step=request?.stepUp;
  return step?.verified===true && Number.isInteger(step.authAgeSeconds)
    && step.authAgeSeconds>=0 && step.authAgeSeconds<=120;
}
function trustedZone(request) {
  const {service,method,path,route}=request;
  if (typeof request.subjectId!=='string' || !request.subjectId || !DEVICE_ID.test(request.deviceId??'')
    || typeof method!=='string' || typeof path!=='string' || typeof route!=='string'
    || path.includes('?') || path.includes('#')
    || (request.queryLength !== undefined && request.queryLength !== 0)) return null;
  const zones=[
    {service:'notes',prefix:'/notes',collection:['GET','POST'],item:['GET','PUT','DELETE']},
    {service:'instructor-notices',prefix:'/instructor-notices',collection:['GET','POST'],item:['GET','PUT']},
  ];
  for (const z of zones) {
    if (service!==z.service) continue;
    if (path===z.prefix && z.collection.includes(method) && route===method+' '+z.prefix) return z;
    const id=path.startsWith(z.prefix+'/')?path.slice(z.prefix.length+1):'';
    if ((UUID.test(id) || (service==='notes' && id==='demo'))
      && z.item.includes(method) && route===method+' '+z.prefix+'/:id') return z;
  }
  return null;
}
function result(request,decision,reasonCode,ruleId) {
  return {schema:'aleph.decision.v1',requestId:request.requestId,decision,reasonCode,ruleIds:[ruleId]};
}
export async function decide(request) {
  if (request?.deviceRegistered!==true) return result(request,'deny','device_not_registered','device_registered');
  const z=trustedZone(request);
  if (!z) return result(request,'deny','resource_not_allowed','resource_zone');
  // For a single note, fail closed unless the engine's verified subject,
  // device, class, project, method and exact path match a server-assigned resource.
  // This static fixture is NOT a binding for real Supabase users.
  if (z.service==='notes') {
    const assigned = request.path==='/notes'
      ? isAssignedCollection(request)
      : isAssignedNote(request);
    if (!assigned) {
      return result(request,'deny','resource_not_allowed','resource_zone');
    }
  }
  if (z.service==='instructor-notices' && request.method!=='GET') {
    // v1 has NO engine-verified instructor role; notice writing is checked at the final API.
    return result(request,'deny','instructor_required','instructor_write_protected');
  }
  if (hasVerifiedCompositeRisk(request) && !hasFreshEngineVerification(request)) {
    return result(request,'step_up','step_up_required','step_up_required');
  }
  return result(request,'allow','approved','resource_zone');
}
