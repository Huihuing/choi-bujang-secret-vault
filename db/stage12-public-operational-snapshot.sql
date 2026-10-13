-- Stage 12: public read-only operational evidence without identity or note data.
-- This function can only be called by the server's service_role.
-- GET /api/war-room-summary strips the response to non-sensitive totals.
CREATE OR REPLACE FUNCTION public.stage12_public_operational_snapshot()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=''
AS $$
DECLARE
 policy jsonb;
BEGIN
 SELECT public.stage10_policy_preview() INTO policy;
 IF policy IS NULL
    OR policy->>'version' IS NULL
    OR policy->>'baseline_sha256' IS NULL
    OR (policy->>'changed_count') IS NULL THEN
   RAISE EXCEPTION 'verified_policy_snapshot_unavailable';
 END IF;
 RETURN pg_catalog.jsonb_build_object(
  'observed_at', pg_catalog.now(),
  'device_pending', (SELECT pg_catalog.count(*) FROM public.app_devices WHERE status='pending'),
  'device_approved', (SELECT pg_catalog.count(*) FROM public.app_devices WHERE status='approved'),
  'device_revoked', (SELECT pg_catalog.count(*) FROM public.app_devices WHERE status='revoked'),
  'restore_events', (SELECT pg_catalog.count(*) FROM stage10_restore.restore_audit),
  'probe_events', (SELECT pg_catalog.count(*) FROM public.app_ops_checks),
  'probe_matches', (SELECT pg_catalog.count(*) FROM public.app_ops_checks WHERE passed IS TRUE),
  'backup_version', policy->>'version',
  'backup_changed_fields', (policy->>'changed_count')::integer
 );
END;
$$;
REVOKE ALL ON FUNCTION public.stage12_public_operational_snapshot() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage12_public_operational_snapshot() TO service_role;
NOTIFY pgrst,'reload schema';
