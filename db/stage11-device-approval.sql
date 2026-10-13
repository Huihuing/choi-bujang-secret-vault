-- Stage 11: WebAuthn device registration is always pending.
-- Approving a credential requires separate trusted administrator verification.
-- No private keys, user data, JWTs, or approval records are committed here.
CREATE TABLE IF NOT EXISTS public.app_devices (
 credential_id text PRIMARY KEY,
 owner_id uuid NOT NULL,
 public_x text NOT NULL CHECK(public_x ~ '^[A-Za-z0-9_-]{43}$'),
 public_y text NOT NULL CHECK(public_y ~ '^[A-Za-z0-9_-]{43}$'),
 sign_count bigint NOT NULL DEFAULT 0 CHECK(sign_count>=0),
 status text NOT NULL DEFAULT 'pending'
  CHECK(status IN ('pending','approved','revoked')),
 requested_at timestamptz NOT NULL DEFAULT now(),
 approved_at timestamptz
);
CREATE INDEX IF NOT EXISTS app_devices_owner_idx ON public.app_devices(owner_id);
ALTER TABLE public.app_devices ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.app_devices FROM PUBLIC,anon,authenticated;
GRANT SELECT,INSERT,UPDATE ON public.app_devices TO service_role;

CREATE TABLE IF NOT EXISTS public.app_device_challenges (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 owner_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('register','request')),
 challenge text NOT NULL CHECK(challenge ~ '^[A-Za-z0-9_-]{43}$'),
 method text,path text,body_sha256 text,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '3 minutes',
 consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS app_challenges_owner_idx
 ON public.app_device_challenges(owner_id,purpose,expires_at);
ALTER TABLE public.app_device_challenges ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.app_device_challenges FROM PUBLIC,anon,authenticated;
GRANT SELECT,INSERT,UPDATE ON public.app_device_challenges TO service_role;

CREATE OR REPLACE FUNCTION public.stage11_consume_challenge(
 p_id uuid,p_owner_id uuid,p_purpose text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $$
DECLARE challenge_row public.app_device_challenges%ROWTYPE;
BEGIN
 UPDATE public.app_device_challenges SET consumed_at=now()
 WHERE id=p_id AND owner_id=p_owner_id AND purpose=p_purpose
  AND consumed_at IS NULL AND expires_at>now()
 RETURNING * INTO challenge_row;
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN pg_catalog.jsonb_build_object(
  'challenge',challenge_row.challenge,'method',challenge_row.method,
  'path',challenge_row.path,'body_sha256',challenge_row.body_sha256);
END
$$;
REVOKE ALL ON FUNCTION public.stage11_consume_challenge(uuid,uuid,text)
 FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.stage11_consume_challenge(uuid,uuid,text)
 TO service_role;
NOTIFY pgrst,'reload schema';

-- Manual ADMIN-ONLY approval pattern; never expose this UPDATE to students:
-- UPDATE public.app_devices
-- SET status='approved',approved_at=now()
-- WHERE credential_id='<independently verified credential ID>'
--   AND owner_id='<independently verified user UUID>'
--   AND status='pending';
-- Revocation is the same trusted-admin update with status='revoked'.
