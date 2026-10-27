-- Windows Hello compatibility: retain ES256 keys and add verified RS256 public components.
-- Apply before deploying the matching api/device.js and api/app-request.js changes.
-- This migration does not create credentials, approve devices, or change RLS/grants.
BEGIN;

ALTER TABLE public.app_devices
 ADD COLUMN IF NOT EXISTS key_algorithm smallint NOT NULL DEFAULT -7,
 ADD COLUMN IF NOT EXISTS public_n text,
 ADD COLUMN IF NOT EXISTS public_e text;

ALTER TABLE public.app_devices
 ALTER COLUMN public_x DROP NOT NULL,
 ALTER COLUMN public_y DROP NOT NULL;

DO $$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_constraint
  WHERE conrelid='public.app_devices'::regclass
   AND conname='app_devices_public_key_shape'
 ) THEN
  ALTER TABLE public.app_devices ADD CONSTRAINT app_devices_public_key_shape CHECK (
   (
    key_algorithm=-7
    AND public_x IS NOT NULL AND public_y IS NOT NULL
    AND public_n IS NULL AND public_e IS NULL
   ) OR (
    key_algorithm=-257
    AND public_x IS NULL AND public_y IS NULL
    AND public_n IS NOT NULL AND public_e IS NOT NULL
    AND public_n ~ '^[A-Za-z0-9_-]+$'
    AND pg_catalog.length(public_n) IN (342,512,683)
    AND public_e='AQAB'
   )
  );
 END IF;
END
$$;

NOTIFY pgrst,'reload schema';
COMMIT;
