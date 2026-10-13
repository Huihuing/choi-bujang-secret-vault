-- Stage 10 database routines already deployed.
-- Records the source for repeatable deployment; contains no record data.
-- Scope: inspect before applying; no production policy DDL here.
CREATE OR REPLACE FUNCTION public.stage10_note_preview(p_id uuid, p_verified_owner uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
 snap stage10_restore.notes_snapshot%ROWTYPE;
 active public.notes%ROWTYPE;
 policy stage10_restore.policy_baseline%ROWTYPE;
 integrity_hash text;
 policy_hash text;
 changes jsonb;
BEGIN
 SELECT * INTO policy FROM stage10_restore.policy_baseline
 WHERE version='stage10_before_attack_v1' FOR SHARE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'policy_backup_missing' USING ERRCODE='P0002';
 END IF;
 policy_hash:=encode(extensions.digest(
   pg_catalog.convert_to(policy.manifest::text,'UTF8'),'sha256'),'hex');
 IF policy.manifest_sha256 IS DISTINCT FROM policy_hash THEN
  RAISE EXCEPTION 'policy_backup_unverified' USING ERRCODE='22000';
 END IF;
 SELECT * INTO snap FROM stage10_restore.notes_snapshot
 WHERE id=p_id FOR SHARE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'note_backup_missing' USING ERRCODE='P0002';
 END IF;
 IF snap.owner_id IS DISTINCT FROM p_verified_owner THEN
  RAISE EXCEPTION 'backup_owner_forbidden' USING ERRCODE='42501';
 END IF;
 integrity_hash:=encode(extensions.digest(pg_catalog.convert_to(
   pg_catalog.jsonb_build_array(snap.id::text,snap.owner_id::text,snap.title,snap.content)::text,
   'UTF8'),'sha256'),'hex');
 IF snap.record_sha256 IS DISTINCT FROM integrity_hash
 OR snap.content_sha256 IS DISTINCT FROM encode(extensions.digest(
   pg_catalog.convert_to(snap.content,'UTF8'),'sha256'),'hex') THEN
  RAISE EXCEPTION 'note_backup_unverified' USING ERRCODE='22000';
 END IF;
 SELECT * INTO active FROM public.notes WHERE id=p_id;
 IF FOUND AND active.owner_id IS DISTINCT FROM p_verified_owner THEN
  RAISE EXCEPTION 'live_owner_forbidden' USING ERRCODE='42501';
 END IF;
 IF active.id IS NULL THEN
  changes:=pg_catalog.jsonb_build_array('missing');
 ELSE
  SELECT coalesce(pg_catalog.jsonb_agg(field ORDER BY field),'[]'::jsonb)
    INTO changes FROM (VALUES
       ('title',active.title IS DISTINCT FROM snap.title),
       ('content',active.content IS DISTINCT FROM snap.content),
       ('created_at',active.created_at IS DISTINCT FROM snap.created_at)
    ) fields(field,changed)
   WHERE changed;
 END IF;
 RETURN pg_catalog.jsonb_build_object(
   'backup_verified',true,
   'snapshot_version',policy.version,
   'snapshot_verified_at',policy.verified_at,
   'record_sha256',snap.record_sha256,
   'content_sha256',snap.content_sha256,
   'policy_sha256',policy.manifest_sha256,
   'id',snap.id,
   'changed_fields',changes);
END;
$function$;

CREATE OR REPLACE FUNCTION public.stage10_restore_verified(p_id uuid, p_verified_owner uuid, p_expected_record_sha256 text, p_expected_version text, p_expected_policy_sha256 text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
 preflight jsonb;
 outcome jsonb;
 post public.notes%ROWTYPE;
BEGIN
 -- This second read and digest validation prevents changing the backup between
 -- the API's first preflight and the actual write.
 preflight:=public.stage10_note_preview(p_id,p_verified_owner);
 IF preflight->>'backup_verified'<>'true'
    OR preflight->>'record_sha256' IS DISTINCT FROM p_expected_record_sha256
    OR preflight->>'snapshot_version' IS DISTINCT FROM p_expected_version
    OR preflight->>'policy_sha256' IS DISTINCT FROM p_expected_policy_sha256 THEN
  RAISE EXCEPTION 'stale_or_unverified_backup' USING ERRCODE='22000';
 END IF;
 outcome:=public.stage10_restore_one(p_id,p_verified_owner);
 SELECT * INTO post FROM public.notes WHERE id=p_id;
 IF NOT FOUND OR post.owner_id IS DISTINCT FROM p_verified_owner
    OR encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.jsonb_build_array(post.id::text,post.owner_id::text,
         post.title,post.content)::text,'UTF8'),'sha256'),'hex')
         IS DISTINCT FROM p_expected_record_sha256 THEN
   RAISE EXCEPTION 'restored_record_verification_failed' USING ERRCODE='22000';
 END IF;
 RETURN outcome || pg_catalog.jsonb_build_object(
  'backup_verified',true,
  'record_sha256',p_expected_record_sha256,
  'policy_sha256',p_expected_policy_sha256,
  'changed_fields',preflight->'changed_fields');
END;
$function$;

REVOKE ALL ON FUNCTION public.stage10_note_preview(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage10_note_preview(uuid,uuid) TO service_role;
REVOKE ALL ON FUNCTION public.stage10_restore_verified(uuid,uuid,text,text,text)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage10_restore_verified(uuid,uuid,text,text,text) TO service_role;
NOTIFY pgrst,'reload schema';
