-- One-time: copy each staff member's phone from Broker Tools' team_members
-- into their Identity profile, so Consultation Agent can find their broker
-- profile. It matches on the phone in the access token.
--
-- team_members.phone is the number brokers used for Consultation Agent's old
-- WhatsApp OTP login (decided 2026-10-12). It is copied as stored
-- ('91XXXXXXXXXX'); Consultation Agent compares the last 10 digits.
--
-- Both tables live in the call_logs project, so this runs in its SQL editor.
-- Run the two SELECTs first and review them. The UPDATE fills only empty
-- phones, never overwrites one an admin set, and is safe to re-run. Each copied
-- phone reaches that user's token at their next sign-in or refresh.

-- 1. What will be copied.
select p.email, tm.name, tm.phone as phone_to_copy
from public.user_profiles p
join public.team_members tm on tm.supabase_user_id = p.user_id
where p.phone = '' and tm.phone <> ''
order by p.email;

-- 2. Who will still have no phone: no team_members row is linked to them by
--    supabase_user_id. Set these by hand with scripts/manage_users.py phone.
select p.email, array_to_string(p.roles, ', ') as roles
from public.user_profiles p
left join public.team_members tm on tm.supabase_user_id = p.user_id
where p.phone = '' and (tm.id is null or tm.phone = '')
order by p.email;

-- 3. The copy.
update public.user_profiles p
set phone = tm.phone
from public.team_members tm
where tm.supabase_user_id = p.user_id
  and p.phone = ''
  and tm.phone <> '';
