-- Applied to the connected Supabase project as stage8_resource_zones.
-- No existing notes or unrelated tables were changed.
create table if not exists public.instructor_memberships (
  user_id uuid primary key references auth.users(id) on delete cascade,
  granted_at timestamptz not null default now()
);
create table if not exists public.instructor_notices (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(trim(title)) between 1 and 120),
  content text not null check (length(trim(content)) between 1 and 4000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.instructor_memberships enable row level security;
alter table public.instructor_notices enable row level security;
revoke all on table public.instructor_memberships from public, anon, authenticated;
revoke all on table public.instructor_notices from public, anon, authenticated;
grant select, insert, update, delete on table public.instructor_memberships to service_role;
grant select, insert, update, delete on table public.instructor_notices to service_role;
-- Only a trusted administrator can grant instructor membership; none are seeded.
