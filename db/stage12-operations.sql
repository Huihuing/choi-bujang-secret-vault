-- Stage 12 operational audit ledger and read-only account-scoped summary.
-- This migration does not copy note contents, change note RLS, or fabricate
-- engine-level attack outcomes.
CREATE TABLE IF NOT EXISTS public.app_ops_checks (
 request_id uuid PRIMARY KEY,
 owner_id uuid NOT NULL,
 probe_id text NOT NULL CHECK(probe_id ~ '^[a-z0-9_]{2,64}$'),
 expected_status integer NOT NULL CHECK(expected_status BETWEEN 100 AND 599),
 observed_status integer CHECK(observed_status BETWEEN 100 AND 599),
 passed boolean NOT NULL DEFAULT false,
 observed_at timestamptz NOT NULL DEFAULT now(),
 source text NOT NULL DEFAULT 'safe_http_self_check'
  CHECK(source='safe_http_self_check')
);
CREATE INDEX IF NOT EXISTS app_ops_checks_owner_time
 ON public.app_ops_checks(owner_id,observed_at DESC);
ALTER TABLE public.app_ops_checks ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.app_ops_checks FROM PUBLIC,anon,authenticated;
GRANT SELECT,INSERT ON public.app_ops_checks TO service_role;

CREATE OR REPLACE FUNCTION public.stage12_ops_summary(p_owner_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE
 device_pending bigint;
 device_approved bigint;
 device_revoked bigint;
 my_restores bigint;
 recent_restore timestamptz;
 my_checks bigint;
BEGIN
 SELECT count(*) FILTER (WHERE status='pending'),
        count(*) FILTER (WHERE status='approved'),
        count(*) FILTER (WHERE status='revoked')
 INTO device_pending,device_approved,device_revoked
 FROM public.app_devices WHERE owner_id=p_owner_id;

 SELECT count(*),max(restored_at) INTO my_restores,recent_restore
 FROM stage10_restore.restore_audit WHERE verified_owner=p_owner_id;

 SELECT count(*) INTO my_checks FROM public.app_ops_checks
 WHERE owner_id=p_owner_id;

 RETURN pg_catalog.jsonb_build_object(
   'pending_devices',device_pending,
   'approved_devices',device_approved,
   'revoked_devices',device_revoked,
   'account_restore_events',my_restores,
   'latest_account_restore_at',recent_restore,
   'account_safe_checks',my_checks);
END;
$$;
REVOKE ALL ON FUNCTION public.stage12_ops_summary(uuid)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage12_ops_summary(uuid) TO service_role;
NOTIFY pgrst,'reload schema';
