-- A roster shaped like production before 004: roles in user_profiles.roles,
-- desk in team_members.role.
insert into auth.users (id, email) values
    ('00000000-0000-0000-0000-000000000001', 'admin@allset.in'),
    ('00000000-0000-0000-0000-000000000002', 'tech@allset.in'),
    ('00000000-0000-0000-0000-000000000003', 'presales@allset.in'),
    ('00000000-0000-0000-0000-000000000004', 'sales@allset.in'),
    ('00000000-0000-0000-0000-000000000005', 'viewer@allset.in');

insert into public.user_profiles (user_id, email, full_name, roles, phone) values
    ('00000000-0000-0000-0000-000000000001', 'admin@allset.in', 'Ad Min', '{admin}', ''),
    ('00000000-0000-0000-0000-000000000002', 'tech@allset.in', 'Te Ch', '{tech}', ''),
    ('00000000-0000-0000-0000-000000000003', 'presales@allset.in', 'Pre Sales', '{presales,viewer}', '919876543210'),
    ('00000000-0000-0000-0000-000000000004', 'sales@allset.in', 'Sa Les', '{sales}', ''),
    ('00000000-0000-0000-0000-000000000005', 'viewer@allset.in', 'Vie Wer', '{viewer}', '');

insert into public.team_members (name, role, phone, email, supabase_user_id) values
    ('Pre Sales', 'presales', '919876543210', 'presales@allset.in', '00000000-0000-0000-0000-000000000003'),
    ('Sa Les', 'sales', '919876543211', 'sales@allset.in', '00000000-0000-0000-0000-000000000004'),
    ('Te Ch', 'tech', '919876543212', 'tech@allset.in', '00000000-0000-0000-0000-000000000002');
