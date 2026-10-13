-- Stage 10 verified recovery baseline.
-- IMPORTANT: run only after confirming pre-attack clean data and policy.
-- Never run this as a method to bless already compromised content or settings.
-- This migration stores no specific student's note data in Git.
CREATE SCHEMA IF NOT EXISTS stage10_restore;
REVOKE ALL ON SCHEMA stage10_restore FROM PUBLIC,anon,authenticated,service_role;

CREATE TABLE IF NOT EXISTS stage10_restore.notes_snapshot (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL,
  title text NOT NULL,
  content text NOT NULL,
  created_at timestamptz NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  record_sha256 text NOT NULL CHECK (record_sha256 ~ '^[0-9a-f]{64}$'),
  checkpointed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS stage10_restore.restore_audit (
 audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 note_id uuid NOT NULL,verified_owner uuid NOT NULL,
 before_sha256 text,restored_sha256 text NOT NULL,
 restored_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS stage10_restore.policy_baseline (
 version text PRIMARY KEY,manifest jsonb NOT NULL,
 manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
 verified_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS stage10_restore.policy_trial (
 version text PRIMARY KEY REFERENCES stage10_restore.policy_baseline(version),
 manifest jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS stage10_restore.policy_audit (
 audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 baseline_version text NOT NULL,changed_policy_keys jsonb NOT NULL,
 restored_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON ALL TABLES IN SCHEMA stage10_restore FROM PUBLIC,anon,authenticated,service_role;

-- Pre-attack checkpoint: store the unmodified row, owner and two hashes.
INSERT INTO stage10_restore.notes_snapshot
 (id,owner_id,title,content,created_at,content_sha256,record_sha256)
SELECT id,owner_id,title,content,created_at,
 encode(extensions.digest(convert_to(content,'UTF8'),'sha256'),'hex'),
 encode(extensions.digest(convert_to(
  jsonb_build_array(id::text,owner_id::text,title,content)::text,
  'UTF8'),'sha256'),'hex')
FROM public.notes
WHERE owner_id IS NOT NULL AND title IS NOT NULL AND content IS NOT NULL
ON CONFLICT(id) DO NOTHING;

-- Record a verified trial policy copy; never change production pg_policies here.
WITH manifest AS (
 SELECT coalesce(jsonb_object_agg(
  tablename||':'||policyname,
  jsonb_build_object('roles',roles,'command',cmd,'using',qual,'with_check',with_check)
 ),'{}'::jsonb) AS value
 FROM pg_policies WHERE schemaname='public'
 AND tablename IN ('notes','instructor_notices','instructor_memberships')
)
INSERT INTO stage10_restore.policy_baseline(version,manifest,manifest_sha256)
SELECT 'stage10_before_attack_v1',value,
 encode(extensions.digest(convert_to(value::text,'UTF8'),'sha256'),'hex')
FROM manifest ON CONFLICT(version) DO NOTHING;
INSERT INTO stage10_restore.policy_trial(version,manifest)
SELECT version,manifest FROM stage10_restore.policy_baseline
WHERE version='stage10_before_attack_v1'
ON CONFLICT(version) DO NOTHING;

-- Installation into public.notes creates snapshots for new notes before future edits.
CREATE OR REPLACE FUNCTION stage10_restore.checkpoint_new_note()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
BEGIN
  IF NEW.owner_id IS NULL OR NEW.title IS NULL OR NEW.content IS NULL THEN
    RAISE EXCEPTION 'invalid_note_checkpoint';
  END IF;
  INSERT INTO stage10_restore.notes_snapshot
    (id,owner_id,title,content,created_at,content_sha256,record_sha256)
  VALUES (NEW.id,NEW.owner_id,NEW.title,NEW.content,NEW.created_at,
    encode(extensions.digest(pg_catalog.convert_to(NEW.content,'UTF8'),'sha256'),'hex'),
    encode(extensions.digest(pg_catalog.convert_to(
      pg_catalog.jsonb_build_array(NEW.id::text,NEW.owner_id::text,NEW.title,NEW.content)::text,
      'UTF8'),'sha256'),'hex'))
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$function$
;
REVOKE ALL ON FUNCTION stage10_restore.checkpoint_new_note()
 FROM PUBLIC,anon,authenticated,service_role;
DROP TRIGGER IF EXISTS stage10_note_insert_checkpoint ON public.notes;
CREATE TRIGGER stage10_note_insert_checkpoint
AFTER INSERT ON public.notes
FOR EACH ROW EXECUTE FUNCTION stage10_restore.checkpoint_new_note();

-- Service-role only RPCs. API handlers verify signed B before calling them.
CREATE OR REPLACE FUNCTION public.stage10_restore_one(p_id uuid, p_verified_owner uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
  snap stage10_restore.notes_snapshot%ROWTYPE;
  prior public.notes%ROWTYPE;
  verified public.notes%ROWTYPE;
  before_hash text;
  expected_record text;
BEGIN
  SELECT * INTO snap
    FROM stage10_restore.notes_snapshot WHERE id=p_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'snapshot_not_found' USING ERRCODE='P0002';
  END IF;
  IF snap.owner_id<>p_verified_owner THEN
    RAISE EXCEPTION 'snapshot_owner_forbidden' USING ERRCODE='42501';
  END IF;

  expected_record:=encode(extensions.digest(pg_catalog.convert_to(
    pg_catalog.jsonb_build_array(
      snap.id::text,snap.owner_id::text,snap.title,snap.content)::text,
    'UTF8'),'sha256'),'hex');
  IF snap.record_sha256<>expected_record
      OR snap.content_sha256<>encode(
        extensions.digest(pg_catalog.convert_to(snap.content,'UTF8'),'sha256'),'hex') THEN
    RAISE EXCEPTION 'snapshot_integrity_failed' USING ERRCODE='22000';
  END IF;

  SELECT * INTO prior FROM public.notes WHERE id=p_id FOR UPDATE;
  IF FOUND THEN
    IF prior.owner_id IS DISTINCT FROM p_verified_owner THEN
      RAISE EXCEPTION 'note_owner_forbidden' USING ERRCODE='42501';
    END IF;
    before_hash:=encode(extensions.digest(
      pg_catalog.convert_to(prior.content,'UTF8'),'sha256'),'hex');
  END IF;

  INSERT INTO public.notes (id,owner_id,title,content,created_at)
  VALUES (snap.id,snap.owner_id,snap.title,snap.content,snap.created_at)
  ON CONFLICT(id) DO UPDATE
   SET title=excluded.title,content=excluded.content
   WHERE public.notes.owner_id=excluded.owner_id
  RETURNING * INTO verified;
  IF NOT FOUND OR verified.id IS DISTINCT FROM snap.id
      OR verified.owner_id IS DISTINCT FROM snap.owner_id
      OR verified.title IS DISTINCT FROM snap.title
      OR verified.content IS DISTINCT FROM snap.content THEN
    RAISE EXCEPTION 'restore_verification_failed' USING ERRCODE='22000';
  END IF;

  INSERT INTO stage10_restore.restore_audit
    (note_id,verified_owner,before_sha256,restored_sha256)
  VALUES (snap.id,p_verified_owner,before_hash,snap.content_sha256);

  RETURN pg_catalog.jsonb_build_object(
    'restored',true,'id',snap.id,'content_sha256',snap.content_sha256,
    'snapshot_version','stage10_before_attack_v1');
END;
$function$
;
REVOKE ALL ON FUNCTION public.stage10_restore_one(uuid,uuid)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage10_restore_one(uuid,uuid) TO service_role;

CREATE OR REPLACE FUNCTION public.stage10_policy_preview()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
 baseline stage10_restore.policy_baseline%ROWTYPE;
 trial stage10_restore.policy_trial%ROWTYPE;
 changed jsonb;
BEGIN
 SELECT * INTO baseline FROM stage10_restore.policy_baseline
 WHERE version='stage10_before_attack_v1';
 SELECT * INTO trial FROM stage10_restore.policy_trial
 WHERE version='stage10_before_attack_v1';
 IF NOT FOUND OR baseline.version IS NULL
    OR baseline.manifest_sha256<>encode(extensions.digest(
    pg_catalog.convert_to(baseline.manifest::text,'UTF8'),'sha256'),'hex') THEN
    RAISE EXCEPTION 'policy_backup_integrity_failed' USING ERRCODE='22000';
 END IF;
 SELECT coalesce(jsonb_agg(key ORDER BY key),'[]'::jsonb) INTO changed
 FROM (
  SELECT key FROM pg_catalog.jsonb_object_keys(baseline.manifest) AS key
  UNION
  SELECT key FROM pg_catalog.jsonb_object_keys(trial.manifest) AS key
 ) all_keys
 WHERE baseline.manifest->key IS DISTINCT FROM trial.manifest->key;
 RETURN pg_catalog.jsonb_build_object('version',baseline.version,
  'baseline_sha256',baseline.manifest_sha256,'changed_keys',changed,'changed_count',
  pg_catalog.jsonb_array_length(changed));
END;
$function$
;
REVOKE ALL ON FUNCTION public.stage10_policy_preview()
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage10_policy_preview() TO service_role;

CREATE OR REPLACE FUNCTION public.stage10_policy_restore(p_expected_sha256 text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
 baseline stage10_restore.policy_baseline%ROWTYPE;
 preview jsonb;
BEGIN
 SELECT * INTO baseline FROM stage10_restore.policy_baseline
 WHERE version='stage10_before_attack_v1' FOR SHARE;
 IF NOT FOUND OR baseline.manifest_sha256 IS DISTINCT FROM p_expected_sha256
  OR baseline.manifest_sha256<>encode(extensions.digest(
   pg_catalog.convert_to(baseline.manifest::text,'UTF8'),'sha256'),'hex') THEN
  RAISE EXCEPTION 'policy_backup_integrity_failed' USING ERRCODE='22000';
 END IF;
 preview:=public.stage10_policy_preview();
 UPDATE stage10_restore.policy_trial SET manifest=baseline.manifest,updated_at=now()
 WHERE version=baseline.version;
 IF NOT FOUND THEN RAISE EXCEPTION 'policy_trial_missing' USING ERRCODE='P0002'; END IF;
 INSERT INTO stage10_restore.policy_audit(baseline_version,changed_policy_keys)
 VALUES (baseline.version,preview->'changed_keys');
 RETURN pg_catalog.jsonb_build_object('restored',true,
  'version',baseline.version,'affected_keys',preview->'changed_keys');
END;
$function$
;
REVOKE ALL ON FUNCTION public.stage10_policy_restore(text)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage10_policy_restore(text) TO service_role;
NOTIFY pgrst, 'reload schema';
