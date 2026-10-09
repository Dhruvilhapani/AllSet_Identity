"""The role matrix, table-driven.

Every expectation here is copied from the plan's role table rather than derived
from capabilities.py, so a change to the implementation that quietly alters what
a role grants fails a test instead of silently re-permissioning production.
"""

import pytest

from app.capabilities import (
    ALL_ROLES,
    InvalidRoles,
    build_capabilities,
    build_payload,
    validate_roles,
)

CMS_WRITE_FLAGS = (
    'can_add_property', 'can_edit_property', 'can_publish',
    'can_upload_media', 'can_edit_seo',
)
CMS_ADMIN_FLAGS = ('can_delete_property', 'can_manage_users')


def cms(roles):
    return build_capabilities(sorted(roles))['cms']


def bt(roles):
    return build_capabilities(sorted(roles))['broker_tools']


def ca(roles):
    return build_capabilities(sorted(roles))['consultation_agent']


# ── App access ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize('roles, cms_access, bt_access', [
    ([], False, False),
    (['viewer'], True, False),
    (['editor'], True, False),
    (['manager'], True, False),
    (['sales'], False, True),
    (['presales'], False, True),
    (['lead_manager'], False, True),
    (['admin'], True, True),
    (['tech'], True, True),
    # The worked example from the plan: a salesperson granted CMS read access.
    (['sales', 'viewer'], True, True),
    (['manager', 'sales'], True, True),
    (['editor', 'presales'], True, True),
])
def test_app_access_is_a_union(roles, cms_access, bt_access):
    assert cms(roles)['access'] is cms_access
    assert bt(roles)['access'] is bt_access
    # Consultation Agent is granted to exactly the Broker Tools roles.
    assert ca(roles)['access'] is bt_access


@pytest.mark.parametrize('roles, expected', [
    (['viewer'], None),
    (['sales', 'viewer'], 'sales'),
    (['lead_manager', 'presales'], 'lead_manager'),
    (['admin', 'sales'], 'admin'),
])
def test_consultation_agent_primary_role_matches_broker_tools(roles, expected):
    assert ca(roles)['primary_role'] == expected


# ── CMS capabilities ─────────────────────────────────────────────────────────

@pytest.mark.parametrize('role', ['admin', 'tech'])
def test_global_admins_get_everything_in_cms(role):
    caps = cms([role])
    for flag in CMS_WRITE_FLAGS + CMS_ADMIN_FLAGS:
        assert caps[flag] is True, flag


@pytest.mark.parametrize('role', ['manager', 'editor'])
def test_manager_and_editor_can_write_but_not_delete_or_manage_users(role):
    """The one substantive difference between manager/editor and admin/tech."""
    caps = cms([role])
    for flag in CMS_WRITE_FLAGS:
        assert caps[flag] is True, flag
    for flag in CMS_ADMIN_FLAGS:
        assert caps[flag] is False, flag


@pytest.mark.parametrize('roles', [['viewer'], ['sales'], ['presales'], ['lead_manager'], []])
def test_read_only_and_bt_only_roles_get_no_cms_write(roles):
    caps = cms(roles)
    for flag in CMS_WRITE_FLAGS + CMS_ADMIN_FLAGS:
        assert caps[flag] is False, flag


def test_sales_plus_viewer_is_cms_read_only():
    caps = cms(['sales', 'viewer'])
    assert caps['access'] is True
    for flag in CMS_WRITE_FLAGS + CMS_ADMIN_FLAGS:
        assert caps[flag] is False, flag


def test_union_takes_the_more_permissive_role():
    """viewer must not drag manager down, and manager must not lift viewer's app."""
    assert cms(['manager', 'viewer'])['can_publish'] is True
    assert cms(['admin', 'viewer'])['can_manage_users'] is True


# ── Broker Tools capabilities ────────────────────────────────────────────────

@pytest.mark.parametrize('role', ['admin', 'tech', 'lead_manager'])
def test_unrestricted_roles_see_every_lead(role):
    caps = bt([role])
    assert caps['unrestricted_leads'] is True
    # Consumers check unrestricted_leads first, so the own_* flags stay False.
    assert caps['own_presales'] is False
    assert caps['own_sales'] is False


def test_presales_is_scoped_to_its_own_owner_column():
    caps = bt(['presales'])
    assert caps['unrestricted_leads'] is False
    assert caps['own_presales'] is True
    assert caps['own_sales'] is False


def test_sales_is_scoped_to_its_own_owner_column():
    caps = bt(['sales'])
    assert caps['unrestricted_leads'] is False
    assert caps['own_presales'] is False
    assert caps['own_sales'] is True


@pytest.mark.parametrize('roles', [['manager'], ['editor'], ['viewer'], ['manager', 'editor']])
def test_cms_only_roles_are_refused_by_broker_tools(roles):
    """manager is CMS-only by design; lead_manager is the BT equivalent."""
    caps = bt(roles)
    assert caps['access'] is False
    assert caps['unrestricted_leads'] is False


def test_manager_plus_sales_is_own_leads_not_all_leads():
    """The case that motivated splitting manager from lead_manager."""
    caps = bt(['manager', 'sales'])
    assert caps['access'] is True
    assert caps['unrestricted_leads'] is False
    assert caps['own_sales'] is True
    # ...and CMS access is unaffected.
    assert cms(['manager', 'sales'])['can_publish'] is True


# ── primary_role ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize('roles, expected', [
    (['admin'], 'admin'),
    (['tech'], 'tech'),
    (['manager'], 'manager'),
    (['editor'], 'editor'),
    (['viewer'], 'viewer'),
    (['manager', 'viewer'], 'manager'),
    (['admin', 'viewer'], 'admin'),
    (['sales'], None),
    ([], None),
])
def test_cms_primary_role_follows_precedence(roles, expected):
    assert cms(roles)['primary_role'] == expected


@pytest.mark.parametrize('roles, expected', [
    (['admin'], 'admin'),
    (['tech'], 'tech'),
    (['lead_manager'], 'lead_manager'),
    (['presales'], 'presales'),
    (['sales'], 'sales'),
    (['lead_manager', 'sales'], 'lead_manager'),
    (['viewer'], None),
    ([], None),
])
def test_bt_primary_role_follows_precedence(roles, expected):
    assert bt(roles)['primary_role'] == expected


def test_primary_role_is_deterministic_regardless_of_input_order():
    """Broker Tools writes this into NOT NULL audit columns; it cannot wobble."""
    assert bt(['sales', 'admin'])['primary_role'] == bt(['admin', 'sales'])['primary_role']
    assert cms(['viewer', 'manager'])['primary_role'] == cms(['manager', 'viewer'])['primary_role']


# ── Deactivation ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize('roles', [['admin'], ['tech'], ['manager', 'sales'], ['viewer']])
def test_deactivated_user_gets_no_access_anywhere(roles):
    """Defence in depth: a token issued before deactivation must not outlive it
    by more than the consumer cache TTL, even for an admin."""
    caps = build_capabilities(roles, is_active=False)
    assert caps['cms']['access'] is False
    assert caps['broker_tools']['access'] is False
    for flag in CMS_WRITE_FLAGS + CMS_ADMIN_FLAGS:
        assert caps['cms'][flag] is False, flag
    assert caps['broker_tools']['unrestricted_leads'] is False
    assert caps['consultation_agent'] == {'access': False, 'primary_role': None}


# ── validate_roles ───────────────────────────────────────────────────────────

def test_empty_role_set_is_legal():
    """The offboarding state: account exists, no app access."""
    assert validate_roles([]) == []


@pytest.mark.parametrize('role', ALL_ROLES)
def test_every_declared_role_validates(role):
    assert validate_roles([role]) == [role]


def test_roles_are_normalised_and_sorted():
    assert validate_roles(['  SALES ', 'Viewer']) == ['sales', 'viewer']


def test_duplicates_collapse():
    assert validate_roles(['admin', 'admin']) == ['admin']


def test_output_order_is_stable_across_input_orders():
    """Consumer caches key off this; ordering must not cause a miss."""
    assert validate_roles(['viewer', 'sales']) == validate_roles(['sales', 'viewer'])


@pytest.mark.parametrize('bad', ['agent', 'superuser', 'broker', '', 'Admin ', 'lead-manager'])
def test_unknown_roles_are_rejected(bad):
    """'agent' and 'broker' are retired values from the two old vocabularies —
    they must not sneak back in through a stale client."""
    if bad == 'Admin ':
        pytest.skip('normalises to a valid role; covered by the normalisation test')
    with pytest.raises(InvalidRoles):
        validate_roles([bad])


def test_presales_and_sales_together_are_rejected():
    """team_members.role is single-valued and drives call_sync.py's owner
    auto-assignment, so a user cannot hold both desks."""
    with pytest.raises(InvalidRoles, match='at most one'):
        validate_roles(['presales', 'sales'])


def test_desk_exclusivity_holds_alongside_other_roles():
    with pytest.raises(InvalidRoles, match='at most one'):
        validate_roles(['admin', 'presales', 'sales'])


@pytest.mark.parametrize('bad', ['admin', None, 42, {'role': 'admin'}])
def test_non_list_input_is_rejected(bad):
    """A bare string is the likely client bug; it must not be iterated per-char."""
    with pytest.raises(InvalidRoles):
        validate_roles(bad)


def test_non_string_members_are_rejected():
    with pytest.raises(InvalidRoles):
        validate_roles(['admin', 7])


# ── Payload shape ────────────────────────────────────────────────────────────

def test_payload_shape_is_the_consumer_contract():
    payload = build_payload(
        user_id='11111111-2222-3333-4444-555555555555',
        email='someone@allset.in',
        roles=['manager', 'sales'],
        is_active=True,
        full_name='Some One',
    )
    assert payload['active'] is True
    assert payload['roles'] == ['manager', 'sales']
    assert payload['role_labels'] == ['Manager', 'Sales']
    assert set(payload['apps']) == {'cms', 'broker_tools', 'consultation_agent'}
    assert payload['apps']['consultation_agent'] == {'access': True, 'primary_role': 'sales'}
    assert payload['apps']['cms']['can_publish'] is True
    assert payload['apps']['broker_tools']['own_sales'] is True
    assert payload['apps']['broker_tools']['unrestricted_leads'] is False


def test_payload_marks_deactivated_users_inactive():
    payload = build_payload(
        user_id='11111111-2222-3333-4444-555555555555',
        email='gone@allset.in',
        roles=['admin'],
        is_active=False,
    )
    assert payload['active'] is False
    assert payload['apps']['cms']['access'] is False
