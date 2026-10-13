"""db/004_permissions.sql and db/005_seed_permissions.sql against real Postgres.

The rest of the suite mocks Supabase at the HTTP boundary, so this is where the
SQL itself is proven: the seed reproduces the JSON the equivalence test checks,
the functions refuse what they must, and every change is audited. See
tests/db/conftest.py for how to run it.
"""

# SQL statements read better unbroken than wrapped at 110 columns.
# ruff: noqa: E501

from __future__ import annotations

import json
from itertools import combinations

import pytest

from app.permissions.catalogue import load_manifests, seed_snapshot
from app.permissions.compat import legacy_flags
from app.permissions.snapshot import Snapshot

ADMIN = '00000000-0000-0000-0000-000000000001'
TECH = '00000000-0000-0000-0000-000000000002'
PRESALES = '00000000-0000-0000-0000-000000000003'
SALES = '00000000-0000-0000-0000-000000000004'
VIEWER = '00000000-0000-0000-0000-000000000005'


def q(db, sql, *args):
    with db.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall() if cur.description else None


def one(db, sql, *args):
    return q(db, sql, *args)[0][0]


def raises(db, sqlstate, sql, *args, contains=''):
    import psycopg2

    with db.cursor() as cur:
        cur.execute('savepoint before_error')
        with pytest.raises(psycopg2.Error) as exc:
            cur.execute(sql, args)
        cur.execute('rollback to savepoint before_error')
    assert exc.value.pgcode == sqlstate, exc.value.pgerror
    assert contains in exc.value.pgerror
    return exc.value


def snapshot_json(db):
    return one(db, 'select public.identity_policy_snapshot()')


def snapshot(db):
    return Snapshot.from_json(snapshot_json(db))


def users(db):
    return {u['user_id']: u for u in snapshot_json(db)['users']}


# ── The seed ─────────────────────────────────────────────────────────────────

def test_the_database_resolves_every_role_set_like_the_seed_json(db):
    from_db, from_json = snapshot(db), Snapshot.from_json(seed_snapshot())
    assert set(from_db.services) == set(from_json.services)
    roles = list(from_json.roles)
    for size in range(len(roles) + 1):
        for combo in combinations(roles, size):
            if {'presales', 'sales'} <= set(combo):
                continue
            a, b = from_db.resolve(combo), from_json.resolve(combo)
            for service in from_json.services:
                assert (a[service].access, a[service].primary_role, a[service].permissions) == \
                       (b[service].access, b[service].primary_role, b[service].permissions), (combo, service)
                assert legacy_flags(service, a) == legacy_flags(service, b), (combo, service)


def test_existing_roles_are_copied_into_identity_user_roles(db):
    assert users(db)[PRESALES]['roles'] == ['presales', 'viewer']


def test_desk_is_backfilled_from_team_members_role(db):
    roster = users(db)
    assert roster[PRESALES]['attributes'] == {'broker_tools': {'desk': 'presales'}}
    assert roster[SALES]['attributes'] == {'broker_tools': {'desk': 'sales'}}
    assert roster[TECH]['attributes'] == {}   # team_members.role 'tech' is not a desk


def test_rerunning_004_and_005_changes_nothing(db, database_url):
    from tests.db.conftest import ROOT

    def state():
        return q(db, """select md5(public.identity_policy_snapshot()::text),
                               (select count(*) from public.identity_audit_log),
                               (select string_agg(key || ':' || grants_version, ',' order by key)
                                  from public.identity_services)""")[0]

    before = state()
    with db.cursor() as cur:
        cur.execute((ROOT / 'db' / '004_permissions.sql').read_text(encoding='utf-8'))
        cur.execute((ROOT / 'db' / '005_seed_permissions.sql').read_text(encoding='utf-8'))
    assert state() == before


# ── Users ────────────────────────────────────────────────────────────────────

def test_unknown_role_is_refused(db):
    raises(db, '22023', "select identity_set_user_roles(%s, '{nope}', null)", VIEWER, contains='unknown role: nope')


def test_one_desk_role_with_the_old_wording(db):
    raises(db, '22023', "select identity_set_user_roles(%s, '{presales,sales}', null)", VIEWER,
           contains='a user may hold at most one of presales/sales, got: presales, sales')


def test_a_missing_user_is_not_found(db):
    raises(db, 'P0002', "select identity_set_user_roles('00000000-0000-0000-0000-00000000dead', '{}', null)")


def test_the_last_active_admin_cannot_lose_the_role(db):
    raises(db, '22023', "select identity_set_user_roles(%s, '{tech}', null)", ADMIN, contains='last active admin')
    q(db, "select identity_set_user_roles(%s, '{tech,admin}', null)", TECH)
    assert one(db, "select identity_set_user_roles(%s, '{tech}', null)", ADMIN) == ['tech']


def test_swapping_desks_mirrors_and_audits(db):
    after = one(db, "select identity_set_user_roles(%s, '{sales, viewer, VIEWER}', %s)", PRESALES, ADMIN)
    assert after == ['sales', 'viewer']
    assert one(db, 'select roles from user_profiles where user_id = %s', PRESALES) == ['sales', 'viewer']
    action, actor, before, after = q(db, """select action, actor_email, before, after from identity_audit_log
                                             where target_key = %s order by id desc limit 1""", PRESALES)[0]
    assert (action, actor, before, after) == ('user.roles', 'admin@allset.in', ['presales', 'viewer'], ['sales', 'viewer'])


def test_a_no_op_change_writes_no_audit_row(db):
    count = one(db, 'select count(*) from identity_audit_log')
    q(db, "select identity_set_user_roles(%s, '{viewer,presales}', null)", PRESALES)
    assert one(db, 'select count(*) from identity_audit_log') == count


def test_attributes_are_validated_set_and_readable_through_the_view(db):
    raises(db, '22023', """select identity_set_user_attributes(%s, 'broker_tools', '{"desk": "manager"}', null)""",
           SALES, contains='value not allowed')
    raises(db, '22023', """select identity_set_user_attributes(%s, 'broker_tools', '{"floor": "2"}', null)""",
           SALES, contains='unknown attribute')
    raises(db, 'P0002', "select identity_set_user_attributes(%s, 'nope', '{}', null)", SALES)

    q(db, """select identity_set_user_attributes(%s, 'broker_tools', '{"desk": "presales"}', %s)""", TECH, ADMIN)
    assert q(db, """select value from identity_user_attribute_values
                     where user_id = %s and service_key = 'broker_tools' and attribute_key = 'desk'""",
             TECH) == [('presales',)]
    q(db, """select identity_set_user_attributes(%s, 'broker_tools', '{"desk": ""}', null)""", TECH)
    assert one(db, 'select count(*) from identity_user_attribute_values where user_id = %s', TECH) == 0


# ── Grants ───────────────────────────────────────────────────────────────────

def test_grant_edits_are_checked(db):
    assert one(db, "select grants_version from identity_services where key = 'cms'") == 1
    raises(db, '40001', "select identity_set_service_grants('cms', '{}', 0, null)")
    raises(db, '22023', "select identity_set_service_grants('identity', '{}', null, null)", contains='cannot be edited')
    raises(db, '22023', """select identity_set_service_grants('cms', '{"admin": {"property": {"read": ["all"]}}}', null, null)""",
           contains='superuser')
    raises(db, '22023', """select identity_set_service_grants('cms', '{"viewer": {"property": {"read": ["own"]}}}', null, null)""",
           contains='not in the cms catalogue')
    # A scope of another resource, even in the same service.
    raises(db, '22023', """select identity_set_service_grants('broker_tools', '{"sales": {"report": {"read": ["own_sales"]}}}', null, null)""",
           contains='not in the broker_tools catalogue')


def test_a_grant_edit_replaces_the_matrix_bumps_the_version_and_audits(db):
    grants = one(db, "select identity_service_grants_json(id) from identity_services where key = 'cms'")
    grants['viewer']['media']['update'] = ['all']
    assert one(db, "select identity_set_service_grants('cms', %s::jsonb, 1, %s)", json.dumps(grants), ADMIN) == 2
    assert snapshot(db).resolve(['viewer'])['cms'].permissions['media']['update'] == ['all']
    assert one(db, 'select action from identity_audit_log order by id desc limit 1') == 'service.grants'


# ── Manifests ────────────────────────────────────────────────────────────────

def test_a_push_retires_what_it_omits_and_a_later_push_revives_it(db):
    q(db, """select identity_apply_manifest('broker_tools', '{"resources": {"lead": {"actions": ["read"]}}}', %s)""", ADMIN)
    services = {s['key']: s for s in snapshot_json(db)['services']}
    retired = {r['key'] for r in services['broker_tools']['resources'] if r['retired']}
    assert 'report' in retired and 'lead' not in retired
    assert one(db, """select count(*) from identity_role_grants g
                        join identity_resources r on r.id = g.resource_id
                        join identity_services s on s.id = r.service_id
                       where s.key = 'broker_tools' and r.key = 'report'""") > 0
    assert 'report' not in snapshot(db).resolve(['presales'])['broker_tools'].permissions
    raises(db, '22023', "select identity_delete_retired_resource('broker_tools', 'lead', null)")

    body = {k: v for k, v in load_manifests()['broker_tools'].items() if k in ('resources', 'attributes')}
    q(db, "select identity_apply_manifest('broker_tools', %s::jsonb, null)", json.dumps(body))
    assert snapshot(db).resolve(['presales'])['broker_tools'].permissions['report'] == {'read': ['own', 'own_team_aggregate']}


def test_manifests_cannot_declare_the_implicit_parts(db):
    raises(db, '22023', """select identity_apply_manifest('cms', '{"resources": {"app": {"actions": ["use"]}}}', null)""")
    raises(db, '22023', """select identity_apply_manifest('cms', '{"resources": {"x": {"actions": ["read"], "scopes": {"all": "All"}}}}', null)""")


# ── Roles ────────────────────────────────────────────────────────────────────

def test_role_lifecycle_and_guards(db):
    q(db, "select identity_upsert_role('auditor', 'Auditor', 'Reads reports', 90, null, %s)", ADMIN)
    assert 'auditor' in snapshot(db).roles
    raises(db, '22023', "update identity_roles set key = 'auditor2' where key = 'auditor'", contains='cannot be changed')
    raises(db, '22023', "select identity_delete_role('admin', null)")
    raises(db, '22023', "select identity_delete_role('viewer', null)", contains='held by')
    q(db, "select identity_delete_role('auditor', %s)", ADMIN)
    assert 'auditor' not in snapshot(db).roles
    # PRESALES holds presales and viewer: putting viewer in the desk group clashes.
    raises(db, '23505', "select identity_upsert_role('viewer', 'Viewer', '', 50, 'desk', null)")


# ── Services and keys ────────────────────────────────────────────────────────

def test_service_registration_and_keys(db):
    q(db, "select identity_register_service('reports', 'Reports', 'Dashboards', %s)", ADMIN)
    services = {s['key']: s for s in snapshot_json(db)['services']}
    assert [r['key'] for r in services['reports']['resources']] == ['app']
    raises(db, '22023', "select identity_register_service('reports', 'Reports', '', null)")
    raises(db, '22023', "select identity_update_service('identity', null, null, false, null)")

    key_id = one(db, "select identity_create_service_key('reports', repeat('a', 64), 'abcdef', 'dev', %s)", ADMIN)
    assert {'service': 'reports', 'key_hash': 'a' * 64} in snapshot_json(db)['service_keys']
    q(db, 'select identity_revoke_service_key(%s, %s, %s)', 'reports', key_id, ADMIN)
    assert {'service': 'reports', 'key_hash': 'a' * 64} not in snapshot_json(db)['service_keys']
    raises(db, '23514', "select identity_create_service_key('reports', 'nothex', 'x', '', null)")


# ── Privileges ───────────────────────────────────────────────────────────────

def test_the_audit_log_is_append_only_even_for_the_service_role(db):
    q(db, 'set local role service_role')
    raises(db, '42501', 'update identity_audit_log set action = action')
    raises(db, '42501', 'delete from identity_audit_log')
    assert one(db, 'select identity_user_role_keys(%s)', ADMIN) == ['admin']


def test_the_api_roles_cannot_read_the_policy(db):
    q(db, 'set local role anon')
    raises(db, '42501', 'select * from identity_roles')
    raises(db, '42501', 'select identity_policy_snapshot()')
