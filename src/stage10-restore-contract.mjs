// Stage 10 single-record restore validation. No user-provided identity/owner.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA=/^[0-9a-f]{64}$/u;
export const RESTORE_ROUTE='/api/restore';
export const POLICY_ROUTE='/api/recovery-policy';

export function exactStage10Path(raw, route) {
  if (typeof raw!=='string' || ![RESTORE_ROUTE,POLICY_ROUTE].includes(route)) return false;
  let parsed;
  try { parsed=new URL(raw,'https://local.invalid'); } catch {return false;}
  return parsed.pathname===route && parsed.search==='' && parsed.hash==='';
}
export function isVerifiedJudgeB(login) {
  return login?.kind==='judge' && login.identity==='b'
    && typeof login.userId==='string' && UUID.test(login.userId)
    && typeof login.runId==='string' && UUID.test(login.runId);
}
function parseBody(body) {
  if (typeof body==='string') {
    if(body.length>2048)return null;
    try { body=JSON.parse(body); } catch {return null;}
  }
  return body && typeof body==='object' && !Array.isArray(body)?body:null;
}
export function recoveryNoteId(body) {
  const value=parseBody(body);
  return value && Object.keys(value).join(',')==='id'
    && typeof value.id==='string' && UUID.test(value.id)
    ? value.id.toLowerCase() : null;
}
// Legacy POST {id} remains unchanged. Only {id,dryRun:true} adds a
// read-only preview. All other fields, false flags and aliases are rejected.
export function recoveryNoteOperation(body) {
  const value=parseBody(body);
  if (!value || typeof value.id!=='string' || !UUID.test(value.id)) return null;
  const keys=Object.keys(value).sort();
  if (keys.length===1 && keys[0]==='id') {
    return {id:value.id.toLowerCase(),dryRun:false};
  }
  if (keys.length===2 && keys[0]==='dryRun' && keys[1]==='id'
    && value.dryRun===true) return {id:value.id.toLowerCase(),dryRun:true};
  return null;
}
export function recoveryPolicyHash(body) {
  const value=parseBody(body);
  return value && Object.keys(value).join(',')==='expectedSha256'
    && typeof value.expectedSha256==='string' && SHA.test(value.expectedSha256)
    ? value.expectedSha256 : null;
}
export function confirmedRestoreResponse(result,id) {
  return result?.restored===true && result.id?.toLowerCase()===id
    && typeof result.content_sha256==='string' && SHA.test(result.content_sha256)
    && result.snapshot_version==='stage10_before_attack_v1'
    ? {restored:true,id,content_sha256:result.content_sha256,snapshot_version:result.snapshot_version}
    : null;
}
