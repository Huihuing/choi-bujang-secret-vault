// Stage 10: operations on a previously authenticated judge B's single note.
// Never read credentials or record bodies, and never write before preflight.
import { confirmedRestoreResponse } from './stage10-restore-contract.mjs';

const SHA=/^[a-f0-9]{64}$/u;
const FIELDS=new Set(['missing','title','content','created_at']);
const VERSION='stage10_before_attack_v1';
const result=(status,error)=>({status,body:{error}});
function dbError(error,phase) {
  if (error?.code==='P0002') return result(404,'verified_backup_missing');
  if (error?.code==='42501') return result(403,'recovery_not_authorized');
  if (error?.code==='22000') return result(409,'backup_verification_failed');
  return result(503,phase==='read'?'backup_check_unavailable':'verified_recovery_unavailable');
}
export function verifiedSnapshot(input,id) {
  if (!input || input.backup_verified!==true || input.id?.toLowerCase()!==id
    || input.snapshot_version!==VERSION || !SHA.test(input.record_sha256??'')
    || !SHA.test(input.content_sha256??'') || !SHA.test(input.policy_sha256??'')
    || !Array.isArray(input.changed_fields) || input.changed_fields.length>4
    || input.changed_fields.some(field=>!FIELDS.has(field))
    || new Set(input.changed_fields).size!==input.changed_fields.length
    || (input.changed_fields.includes('missing') && input.changed_fields.length!==1)) return null;
  return Object.freeze({
    id,snapshot_version:VERSION,record_sha256:input.record_sha256,
    content_sha256:input.content_sha256,policy_sha256:input.policy_sha256,
    changed_fields:Object.freeze([...input.changed_fields]),
  });
}
export async function restoreFromVerifiedSnapshot({supabase,id,ownerId,dryRun=false}) {
  const {data:source,error:readError}=await supabase.rpc('stage10_note_preview',{
    p_id:id,p_verified_owner:ownerId,
  });
  if (readError) return dbError(readError,'read');
  const snapshot=verifiedSnapshot(source,id);
  if (!snapshot) return result(409,'backup_verification_failed');

  // Explicit preflight: read-only response showing approved version/field diff.
  // This returns BEFORE stage10_restore_verified, including its audit writes.
  if (dryRun) {
    return {status:200,body:{
      preview:true,backup_verified:true,id,
      snapshot_version:snapshot.snapshot_version,
      record_sha256:snapshot.record_sha256,
      content_sha256:snapshot.content_sha256,
      changed_fields:[...snapshot.changed_fields],
    }};
  }

  // DB re-reads and verifies the pinned version + hashes in one transaction.
  const {data:restored,error:restoreError}=await supabase.rpc('stage10_restore_verified',{
    p_id:id,p_verified_owner:ownerId,
    p_expected_record_sha256:snapshot.record_sha256,
    p_expected_version:snapshot.snapshot_version,
    p_expected_policy_sha256:snapshot.policy_sha256,
  });
  if (restoreError) return dbError(restoreError,'write');
  const checked=confirmedRestoreResponse(restored,id);
  if (!checked || restored.backup_verified!==true
    || restored.record_sha256!==snapshot.record_sha256
    || restored.content_sha256!==snapshot.content_sha256
    || restored.policy_sha256!==snapshot.policy_sha256
    || restored.snapshot_version!==snapshot.snapshot_version
    || JSON.stringify(restored.changed_fields)!==JSON.stringify(snapshot.changed_fields)) {
    return result(503,'recovery_verification_failed');
  }
  return {status:200,body:{
    ...checked,backup_verified:true,changed_fields:[...snapshot.changed_fields],
  }};
}
