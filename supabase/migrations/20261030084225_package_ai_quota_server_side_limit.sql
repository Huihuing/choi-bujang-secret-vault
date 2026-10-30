-- Mirror of Supabase migration 20261030084225 / package_ai_quota_server_side_limit.
-- Applied via Supabase Management API on 2026-10-30.
-- Apply only after reviewing the intended Supabase project and backup.
-- Enforced in PostgreSQL, not an in-memory serverless map.
-- Security invoker + exclusive EXECUTE privilege for service_role.
-- No existing user data or existing tables are modified.
CREATE TABLE IF NOT EXISTS public.package_ai_quota (
  owner_id uuid PRIMARY KEY,
  minute_started_at timestamptz NOT NULL,
  minute_count integer NOT NULL DEFAULT 0 CHECK (minute_count >= 0),
  day_started_on date NOT NULL,
  day_count integer NOT NULL DEFAULT 0 CHECK (day_count >= 0)
);
ALTER TABLE public.package_ai_quota ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.package_ai_quota FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.package_ai_quota TO service_role;

CREATE OR REPLACE FUNCTION public.package_ai_consume(p_owner_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_today date := (clock_timestamp() AT TIME ZONE 'UTC')::date;
  v_row public.package_ai_quota%ROWTYPE;
  v_minute_count integer;
  v_day_count integer;
  v_minute_at timestamptz;
  v_retry integer;
BEGIN
  IF p_owner_id IS NULL THEN
    RAISE EXCEPTION 'invalid_owner';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext(p_owner_id::text), hashtext('package_ai_quota_v1'));
  INSERT INTO public.package_ai_quota
    (owner_id, minute_started_at, minute_count, day_started_on, day_count)
  VALUES (p_owner_id, v_now, 0, v_today, 0)
  ON CONFLICT (owner_id) DO NOTHING;

  SELECT * INTO STRICT v_row
    FROM public.package_ai_quota WHERE owner_id = p_owner_id FOR UPDATE;
  v_minute_at := v_row.minute_started_at;
  v_minute_count := v_row.minute_count;
  v_day_count := v_row.day_count;
  IF v_now < v_minute_at OR v_now - v_minute_at >= interval '60 seconds' THEN
    v_minute_at := v_now;
    v_minute_count := 0;
  END IF;
  IF v_row.day_started_on <> v_today THEN
    v_day_count := 0;
  END IF;
  IF v_minute_count >= 4 OR v_day_count >= 20 THEN
    IF v_day_count >= 20 THEN
      v_retry := GREATEST(1, CEIL(EXTRACT(EPOCH FROM (
        ((v_today + 1)::timestamp AT TIME ZONE 'UTC') - v_now
      )))::integer);
    ELSE
      v_retry := GREATEST(1, CEIL(60 - EXTRACT(EPOCH FROM (v_now - v_minute_at)))::integer);
    END IF;
    RETURN jsonb_build_object('allowed', false, 'retryAfterSeconds', v_retry);
  END IF;
  UPDATE public.package_ai_quota SET
    minute_started_at = v_minute_at,
    minute_count = v_minute_count + 1,
    day_started_on = v_today,
    day_count = v_day_count + 1
  WHERE owner_id = p_owner_id;
  RETURN jsonb_build_object(
    'allowed', true, 'minuteRemaining', 4 - v_minute_count - 1,
    'dayRemaining', 20 - v_day_count - 1
  );
END;
$$;
REVOKE ALL ON FUNCTION public.package_ai_consume(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.package_ai_consume(uuid) TO service_role;
