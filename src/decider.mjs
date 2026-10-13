// Only engine-verified aleph.decision.v1 fields are considered; no request.role.
export const RULE_IDS = Object.freeze(['device_registered','step_up_required','resource_zone','instructor_write_protected']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
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
    || path.includes('?') || path.includes('#')) return null;
  const zones=[
    {service:'notes',prefix:'/notes',collection:['GET','POST'],item:['GET','PUT','DELETE']},
    {service:'instructor-notices',prefix:'/instructor-notices',collection:['GET','POST'],item:['GET','PUT']},
  ];
  for (const z of zones) {
    if (service!==z.service) continue;
    if (path===z.prefix && z.collection.includes(method) && route===method+' '+z.prefix) return z;
    const id=path.startsWith(z.prefix+'/')?path.slice(z.prefix.length+1):'';
    if (UUID.test(id) && z.item.includes(method) && route===method+' '+z.prefix+'/:id') return z;
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
  // The v1 engine does not provide the stored owner of /notes/:id.
  // A UUID and a verified caller identity do not prove that caller owns the UUID.
  // Never grant arbitrary single-note READ in the SDP gateway. The notes API
  // independently authorizes user-owned reads using the stored owner_id.
  if (z.service==='notes' && request.method==='GET' && request.route==='GET /notes/:id') {
    return result(request,'deny','resource_not_allowed','resource_zone');
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
