"""The role matrix — the single source of truth for what each role grants.

Both consuming apps read capabilities from here (via /v1/introspect) instead of
reimplementing the rules. That indirection is the point: before this service,
CMS's permission logic existed in three places that disagreed with each other
(users/models.py's can_* properties, properties/views.py's _can_edit helpers,
and admin_ui's client-side ROLE_PERMS map).

Capabilities are the UNION across every role a user holds. A user holding
{sales, viewer} gets own-leads in Broker Tools and read-only in the CMS.
"""

from __future__ import annotations

# ── Roles ────────────────────────────────────────────────────────────────────
# Wire values are lowercase single tokens and must stay that way: they are
# compared against string literals in AllSet_Broker_Tools'
# db/call_logs/001_schema.sql (the team_members_role_check CHECK constraint) and
# in call_sync.py's SQL join on team_members.role. Renaming one is a data
# migration, not a rename. Display labels live in ROLE_LABELS.
ADMIN = 'admin'
TECH = 'tech'
MANAGER = 'manager'
EDITOR = 'editor'
VIEWER = 'viewer'
LEAD_MANAGER = 'lead_manager'
PRESALES = 'presales'
SALES = 'sales'

ALL_ROLES: tuple[str, ...] = (
    ADMIN, TECH, MANAGER, EDITOR, VIEWER, LEAD_MANAGER, PRESALES, SALES,
)

ROLE_LABELS: dict[str, str] = {
    ADMIN: 'Admin',
    TECH: 'Tech',
    MANAGER: 'Manager',
    EDITOR: 'Editor',
    VIEWER: 'Viewer',
    LEAD_MANAGER: 'Lead Manager',
    PRESALES: 'Pre-sales',
    SALES: 'Sales',
}

# admin and tech are the only cross-app roles. They are deliberately
# permission-identical; the distinction is organisational and shows up in audit
# trails (the CMS's created_by/updated_by and Broker Tools' six *_role columns).
_GLOBAL_ADMIN = frozenset({ADMIN, TECH})

# ── CMS ──────────────────────────────────────────────────────────────────────
_CMS_FULL = _GLOBAL_ADMIN                                # + delete, user management
_CMS_WRITE = _GLOBAL_ADMIN | {MANAGER, EDITOR}           # add/edit/publish/media/SEO
_CMS_READ = _CMS_WRITE | {VIEWER}

# ── Broker Tools ─────────────────────────────────────────────────────────────
_BT_UNRESTRICTED = _GLOBAL_ADMIN | {LEAD_MANAGER}        # every lead
_BT_READ = _BT_UNRESTRICTED | {PRESALES, SALES}

# The two "desk" roles select which owner column a lead is matched against
# (fk_presales_owner vs fk_sales_owner). At most one may be held, because
# team_members.role is single-valued and drives call_sync.py's owner
# auto-assignment.
DESK_ROLES = frozenset({PRESALES, SALES})

# Precedence for collapsing a role set down to one string. Several call sites
# need a single value rather than a set: Broker Tools writes author_role /
# completed_by_role / assignee_role into audit columns, firestore_client.py
# branches on it, and admin_ui's role badge keys off it.
_CMS_PRECEDENCE = (ADMIN, TECH, MANAGER, EDITOR, VIEWER)
_BT_PRECEDENCE = (ADMIN, TECH, LEAD_MANAGER, PRESALES, SALES)


class InvalidRoles(ValueError):
    """A role set that must never be persisted."""


def validate_roles(roles: object) -> list[str]:
    """Normalise and validate a role set, or raise InvalidRoles.

    The empty set is legal and means "account exists, no app access" — the clean
    offboarding state, distinct from is_active=False which blocks login outright.

    These same two rules are also enforced as CHECK constraints on
    public.user_profiles. The duplication is deliberate: the role set is the one
    piece of state that must never be wrong, so it does not depend solely on
    application code being correct.
    """
    if not isinstance(roles, (list, tuple, set, frozenset)):
        raise InvalidRoles('roles must be a list')

    normalised: list[str] = []
    for role in roles:
        if not isinstance(role, str):
            raise InvalidRoles(f'role must be a string, got {type(role).__name__}')
        token = role.strip().lower()
        if token not in ALL_ROLES:
            raise InvalidRoles(f'unknown role: {token or role}')
        if token not in normalised:
            normalised.append(token)

    desks = [role for role in normalised if role in DESK_ROLES]
    if len(desks) > 1:
        raise InvalidRoles(
            'a user may hold at most one of presales/sales, got: ' + ', '.join(desks)
        )

    # Sorted so the JWT claim, the DB row and API responses agree byte-for-byte,
    # which keeps consumer-side caches from missing on ordering alone.
    return sorted(normalised)


def _primary_role(held: set[str], precedence: tuple[str, ...]) -> str | None:
    for role in precedence:
        if role in held:
            return role
    return None


def _cms_capabilities(held: set[str]) -> dict:
    full = bool(held & _CMS_FULL)
    write = bool(held & _CMS_WRITE)
    return {
        'access': bool(held & _CMS_READ),
        'primary_role': _primary_role(held, _CMS_PRECEDENCE),
        # Field names match the can_* properties the CMS already serialises to
        # admin_ui, so its 13 existing UI gate sites need no changes.
        'can_add_property': write,
        'can_edit_property': write,
        'can_publish': write,
        'can_upload_media': write,
        'can_edit_seo': write,
        'can_delete_property': full,
        'can_manage_users': full,
    }


def _broker_tools_capabilities(held: set[str]) -> dict:
    unrestricted = bool(held & _BT_UNRESTRICTED)
    return {
        'access': bool(held & _BT_READ),
        'primary_role': _primary_role(held, _BT_PRECEDENCE),
        # Consumers check unrestricted_leads first; the own_* flags only matter
        # when it is False. An unrestricted user has both own_* flags False,
        # which mirrors how _UNRESTRICTED_ROLES short-circuits today.
        'unrestricted_leads': unrestricted,
        'own_presales': PRESALES in held,
        'own_sales': SALES in held,
    }


def _consultation_agent_capabilities(held: set[str]) -> dict:
    # Granted to exactly the Broker Tools roles, by decision rather than by
    # coincidence. It is its own block so the two can diverge later without a
    # change in Consultation Agent's code. It has no roles of its own.
    return {
        'access': bool(held & _BT_READ),
        'primary_role': _primary_role(held, _BT_PRECEDENCE),
    }


_NO_ACCESS_CMS = {
    'access': False, 'primary_role': None,
    'can_add_property': False, 'can_edit_property': False, 'can_publish': False,
    'can_upload_media': False, 'can_edit_seo': False,
    'can_delete_property': False, 'can_manage_users': False,
}

_NO_ACCESS_BT = {
    'access': False, 'primary_role': None,
    'unrestricted_leads': False, 'own_presales': False, 'own_sales': False,
}

_NO_ACCESS_CA = {'access': False, 'primary_role': None}


def build_capabilities(roles: list[str], *, is_active: bool = True) -> dict:
    """Resolve a role set into per-app capabilities.

    A deactivated user resolves to no access anywhere regardless of roles.
    Login already refuses them; denying again here means a token issued before
    deactivation cannot outlive it by more than the consumer cache TTL.
    """
    if not is_active:
        return {
            'cms': dict(_NO_ACCESS_CMS),
            'broker_tools': dict(_NO_ACCESS_BT),
            'consultation_agent': dict(_NO_ACCESS_CA),
        }

    held = set(roles)
    return {
        'cms': _cms_capabilities(held),
        'broker_tools': _broker_tools_capabilities(held),
        'consultation_agent': _consultation_agent_capabilities(held),
    }


def build_payload(
    *,
    user_id: str,
    email: str,
    roles: list[str],
    is_active: bool,
    full_name: str = '',
) -> dict:
    """The response shape shared by /v1/introspect and /v1/auth/me.

    Both return the same object so a consumer's server-side authorisation and
    its client-side UI gating can never drift apart.
    """
    return {
        'active': bool(is_active),
        'user_id': user_id,
        'email': email,
        'full_name': full_name,
        'roles': roles,
        'role_labels': [ROLE_LABELS[role] for role in roles],
        'is_active': bool(is_active),
        'apps': build_capabilities(roles, is_active=is_active),
    }
