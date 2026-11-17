-- Bonva: secure partner linking (6-character codes), partner data sync, checkout offer tracking.
-- Project: Bonva (etsamfrennwuovjfdakk). Additive: no existing data is changed or removed.

-- ─── partner_links: extend the existing (unused) table ───────────────────────
alter table public.partner_links add column if not exists created_at  timestamptz not null default now();
alter table public.partner_links add column if not exists expires_at  timestamptz;
alter table public.partner_links add column if not exists unlinked_at timestamptz;
alter table public.partner_links drop constraint if exists partner_links_status_check;
alter table public.partner_links add constraint partner_links_status_check
  check (status in ('pending','linked','unlinked','cancelled'));
create index if not exists partner_links_user_a_idx on public.partner_links(user_a_id);
create index if not exists partner_links_user_b_idx on public.partner_links(user_b_id);

-- Old policy let members insert/update/delete rows directly. All writes now go
-- through the functions below; members may only read their own links.
drop policy if exists "Users see their partner links" on public.partner_links;
drop policy if exists partner_links_select_members on public.partner_links;
create policy partner_links_select_members on public.partner_links
  for select to authenticated
  using ((select auth.uid()) = user_a_id or (select auth.uid()) = user_b_id);

-- ─── Helper: is `other` my currently linked partner? ─────────────────────────
create or replace function public.bonva_is_partner(other uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.partner_links l
    where l.status = 'linked'
      and ((l.user_a_id = auth.uid() and l.user_b_id = other)
        or (l.user_b_id = auth.uid() and l.user_a_id = other))
  );
$$;

-- ─── Shared data each partner publishes for the other to read ────────────────
create table if not exists public.partner_shared_data (
  user_id           uuid primary key references auth.users(id) on delete cascade,
  display_name      text check (char_length(display_name) <= 80),
  quiz_scores       jsonb not null default '[]'::jsonb,
  daily_answers     jsonb not null default '[]'::jsonb,
  wellness          jsonb not null default '{}'::jsonb,
  coaching_insights jsonb not null default '[]'::jsonb,
  updated_at        timestamptz not null default now(),
  constraint psd_size check (pg_column_size(quiz_scores) + pg_column_size(daily_answers)
                             + pg_column_size(wellness) + pg_column_size(coaching_insights) < 200000)
);
alter table public.partner_shared_data enable row level security;

drop policy if exists psd_owner_all on public.partner_shared_data;
create policy psd_owner_all on public.partner_shared_data
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

drop policy if exists psd_partner_read on public.partner_shared_data;
create policy psd_partner_read on public.partner_shared_data
  for select to authenticated
  using (public.bonva_is_partner(user_id));

-- ─── Ensure a profiles row exists (partner_links FKs point at profiles) ───────
create or replace function public.bonva_ensure_profile()
returns void
language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, email)
  select u.id, u.email from auth.users u where u.id = auth.uid()
  on conflict (id) do nothing;
end;
$$;

-- ─── Create (or return) my 6-character connection code ───────────────────────
create or replace function public.bonva_partner_create_code()
returns json
language plpgsql security definer set search_path = ''
as $$
declare
  me uuid := auth.uid();
  alphabet text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';  -- no 0/O, 1/I/L
  new_code text;
  bytes bytea;
  i int;
  existing public.partner_links;
begin
  if me is null then raise exception 'not_signed_in' using errcode = '28000'; end if;
  perform public.bonva_ensure_profile();

  if exists (select 1 from public.partner_links
             where status = 'linked' and (user_a_id = me or user_b_id = me)) then
    raise exception 'already_linked' using errcode = 'P0001';
  end if;

  select * into existing from public.partner_links
   where user_a_id = me and status = 'pending' and expires_at > now()
   order by created_at desc limit 1;
  if found then
    return json_build_object('code', existing.invite_code, 'expires_at', existing.expires_at);
  end if;

  update public.partner_links set status = 'cancelled'
   where user_a_id = me and status = 'pending';

  loop
    bytes := decode(replace(gen_random_uuid()::text, '-', ''), 'hex');
    new_code := '';
    for i in 0..5 loop
      new_code := new_code || substr(alphabet, (get_byte(bytes, i) % length(alphabet)) + 1, 1);
    end loop;
    exit when not exists (select 1 from public.partner_links where invite_code = new_code);
  end loop;

  insert into public.partner_links (user_a_id, invite_code, status, expires_at)
  values (me, new_code, 'pending', now() + interval '24 hours');

  return json_build_object('code', new_code, 'expires_at', now() + interval '24 hours');
end;
$$;

-- ─── Cancel my pending code ──────────────────────────────────────────────────
create or replace function public.bonva_partner_cancel_code()
returns void
language plpgsql security definer set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in' using errcode = '28000'; end if;
  update public.partner_links set status = 'cancelled'
   where user_a_id = auth.uid() and status = 'pending';
end;
$$;

-- ─── Join with my partner's code ─────────────────────────────────────────────
create or replace function public.bonva_partner_join(p_code text)
returns json
language plpgsql security definer set search_path = ''
as $$
declare
  me uuid := auth.uid();
  c text := upper(regexp_replace(coalesce(p_code, ''), '[^A-Za-z0-9]', '', 'g'));
  link public.partner_links;
  partner_name text;
begin
  if me is null then raise exception 'not_signed_in' using errcode = '28000'; end if;
  if length(c) <> 6 then raise exception 'invalid_code' using errcode = 'P0001'; end if;
  perform public.bonva_ensure_profile();

  select * into link from public.partner_links
   where invite_code = c and status = 'pending'
   for update;
  if not found or link.expires_at <= now() then
    raise exception 'invalid_code' using errcode = 'P0001';
  end if;
  if link.user_a_id = me then raise exception 'own_code' using errcode = 'P0001'; end if;

  if exists (select 1 from public.partner_links
             where status = 'linked'
               and (user_a_id in (me, link.user_a_id) or user_b_id in (me, link.user_a_id))) then
    raise exception 'already_linked' using errcode = 'P0001';
  end if;

  update public.partner_links
     set user_b_id = me, status = 'linked', linked_at = now(), expires_at = null
   where id = link.id;

  -- Any other open codes from either person are no longer needed.
  update public.partner_links set status = 'cancelled'
   where status = 'pending' and user_a_id in (me, link.user_a_id) and id <> link.id;

  update public.profiles set partner_id = link.user_a_id where id = me;
  update public.profiles set partner_id = me where id = link.user_a_id;

  select coalesce(nullif(s.display_name, ''), nullif(p.my_name, ''), nullif(p.display_name, ''))
    into partner_name
    from public.profiles p left join public.partner_shared_data s on s.user_id = p.id
   where p.id = link.user_a_id;

  return json_build_object('partner_id', link.user_a_id, 'partner_name', partner_name, 'linked_at', now());
end;
$$;

-- ─── Unlink (either partner, any time) ───────────────────────────────────────
create or replace function public.bonva_partner_unlink()
returns void
language plpgsql security definer set search_path = ''
as $$
declare
  me uuid := auth.uid();
  link public.partner_links;
begin
  if me is null then raise exception 'not_signed_in' using errcode = '28000'; end if;
  for link in
    select * from public.partner_links
     where status = 'linked' and (user_a_id = me or user_b_id = me)
     for update
  loop
    update public.partner_links set status = 'unlinked', unlinked_at = now() where id = link.id;
    update public.profiles set partner_id = null
     where id in (link.user_a_id, link.user_b_id);
  end loop;
end;
$$;

-- ─── My current link status ──────────────────────────────────────────────────
create or replace function public.bonva_partner_status()
returns json
language plpgsql stable security definer set search_path = ''
as $$
declare
  me uuid := auth.uid();
  link public.partner_links;
  other uuid;
  partner_name text;
  partner_paid boolean;
begin
  if me is null then return json_build_object('state', 'signed_out'); end if;

  select * into link from public.partner_links
   where status = 'linked' and (user_a_id = me or user_b_id = me)
   order by linked_at desc limit 1;
  if found then
    other := case when link.user_a_id = me then link.user_b_id else link.user_a_id end;
    select coalesce(nullif(s.display_name, ''), nullif(p.my_name, ''), nullif(p.display_name, '')),
           coalesce(p.paid, false)
      into partner_name, partner_paid
      from public.profiles p left join public.partner_shared_data s on s.user_id = p.id
     where p.id = other;
    return json_build_object('state', 'linked', 'partner_id', other, 'partner_name', partner_name,
                             'partner_paid', partner_paid, 'linked_at', link.linked_at);
  end if;

  select * into link from public.partner_links
   where user_a_id = me and status = 'pending' and expires_at > now()
   order by created_at desc limit 1;
  if found then
    return json_build_object('state', 'pending', 'code', link.invite_code, 'expires_at', link.expires_at);
  end if;

  return json_build_object('state', 'none');
end;
$$;

-- Only signed-in users may call these.
revoke all on function public.bonva_is_partner(uuid)          from public, anon;
revoke all on function public.bonva_ensure_profile()          from public, anon, authenticated;
revoke all on function public.bonva_partner_create_code()     from public, anon;
revoke all on function public.bonva_partner_cancel_code()     from public, anon;
revoke all on function public.bonva_partner_join(text)        from public, anon;
revoke all on function public.bonva_partner_unlink()          from public, anon;
revoke all on function public.bonva_partner_status()          from public, anon;
grant execute on function public.bonva_is_partner(uuid)       to authenticated;
grant execute on function public.bonva_partner_create_code()  to authenticated;
grant execute on function public.bonva_partner_cancel_code()  to authenticated;
grant execute on function public.bonva_partner_join(text)     to authenticated;
grant execute on function public.bonva_partner_unlink()       to authenticated;
grant execute on function public.bonva_partner_status()       to authenticated;

-- ─── Checkout offer tracking (which plan/offer a buyer picked, from where) ────
create table if not exists public.checkout_events (
  id         bigint generated always as identity primary key,
  user_id    uuid references auth.users(id) on delete set null,
  plan       text not null check (plan in ('monthly','annual','couples','couples_annual')),
  offer      text check (offer is null or char_length(offer) <= 40),
  source     text check (source is null or char_length(source) <= 40),
  channel    text not null default 'stripe' check (channel in ('stripe','google_play')),
  ref        text check (ref is null or char_length(ref) <= 200),
  created_at timestamptz not null default now()
);
alter table public.checkout_events enable row level security;
drop policy if exists checkout_events_insert on public.checkout_events;
create policy checkout_events_insert on public.checkout_events
  for insert to anon, authenticated
  with check (user_id is null or user_id = (select auth.uid()));
-- No select/update/delete policies: only the dashboard (service role) reads these.
