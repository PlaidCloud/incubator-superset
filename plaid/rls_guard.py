# coding=utf-8
"""sc-23432 Part 4 -- the fork-side write guard for PlaidCloud-generated RLS.

`git grep -e plaid_rls origin/develop-6.1` returned ZERO before this file: there
was no ownership or prefix protection on `plaid_rls_*` roles or the RLS rules
PlaidCloud's role/rule reconciler generates. A Keycloak `is_admin` claim reaches
Superset Admin (`plaid/security.py`'s `oauth_user_info`, mapped via the deployed
tenant's `AUTH_ROLES_MAPPING`), and Admin holds `Role.can_update_role_users` /
`can_edit` / `can_delete` on roles and full CRUD on `RowLevelSecurityFilter` --
so, unguarded, any customer workspace admin could add themselves (or anyone) to
a `plaid_rls_*` role -- permanent, since nothing else reconciles a roster edit
away -- or delete a Base guard rule, turning off row-level security for that
dataset until PlaidCloud's next reconcile pass.

## What this protects, and what it deliberately does not

Protected: create / rename / roster-write / delete of any Superset Role or
RowLevelSecurityFilter whose ``name`` starts with the reserved stem
``plaid_rls``. That one stem covers both literal forms the plan's naming
scheme produces (sc-23432 non-negotiable 5): roles are always
``plaid_rls_<keycloak-group-id>``; rules are ``plaid_rls_<project-id>_<hash>``
(Regular) or ``plaid_rlsguard_<project-id>_<hash>`` (Base guard). Renaming a
role or rule INTO the stem is blocked symmetrically -- a workspace admin
cannot pre-empt or impersonate a name the reconciler expects to own next.

NOT protected here, disclosed rather than silently assumed to be covered:
dataset identity. ``DatasetPutSchema`` lets a dataset owner rewrite
``table_name`` / ``schema`` / ``catalog`` / ``sql`` behind
``raise_for_ownership``, which any Admin passes -- a second way to point a
generated rule's binding at different data without touching the rule or role
this guard watches at all. Out of scope for Part 4; see sc-23432 (referenced by
description only -- do not cite it in commits/branches/PRs in THIS repo).

## Who may write a protected resource

Exactly one Superset identity: whoever ``PLAID_RLS_AUTOMATION_USERNAME`` names
(default ``admin``, matching the username plaid's own service calls
authenticate to Superset as -- see ``add_superset_user`` /
``superset_get_token`` in the plaid repo, provider ``db``, never Keycloak
OAuth). Every Keycloak-mapped human -- including one holding the ``Admin``
role via an ``is_admin`` claim -- is a DIFFERENT ``ab_user`` row, self-
registered on first login by ``PlaidSecurityManager.auth_user_oauth``, and is
refused here regardless of role. Unconfigured (``None`` / empty string) fails
CLOSED: nobody may write a protected resource, not "anyone may."

## Why this lives in ``plaid/``, and how it attaches

Two different attachment points, because the two resource kinds are wired into
Superset differently:

* Roles: ``SecurityManager.role_api`` is already an override point --
  ``SupersetSecurityManager`` sets it to ``SupersetRoleApi`` (see
  ``superset/security/manager.py``) so that FAB's own
  ``register_views()`` -> ``self.appbuilder.add_api(self.role_api)`` picks up
  the subclass. ``PlaidRoleApi`` here extends that same subclass; wiring it in
  is one line on ``PlaidSecurityManager`` (``role_api = PlaidRoleApi``).
* RLS rules: ``RLSRestApi`` (``superset/row_level_security/api.py``) has no
  equivalent override attribute -- Superset registers the class directly. Its
  ``post`` / ``put`` / ``delete`` / ``bulk_delete`` are monkeypatched in place
  by ``install()`` below, called from ``PlaidSecurityManager.__init__`` --
  which Superset's app factory runs during app construction, well before the
  app accepts its first request, and after ``super().__init__`` has already
  pulled in Superset's own security wiring. Patching the class attribute is
  sufficient: Python resolves ``self.post(...)`` from the class's current
  ``__dict__`` at CALL time, not at route-registration time, so ordering
  relative to ``add_api(RLSRestApi)`` does not matter.
"""

from __future__ import annotations

import functools
import logging

from flask import current_app, g

logger = logging.getLogger(__name__)

# Roles only ever use this exact form (trailing underscore -- a role is never
# a guard). Rules use this stem with either `_` (Regular) or `guard_`
# (Base guard) after it -- `is_protected_rule_name` checks the shorter,
# underscore-less stem so both survive one check.
PLAID_RLS_ROLE_PREFIX = 'plaid_rls_'
PLAID_RLS_NAME_STEM = 'plaid_rls'

DENIAL_MESSAGE = (
    "{name!r} is a PlaidCloud-generated row-access resource. It can only be "
    "written by PlaidCloud's own automation."
)


def is_protected_role_name(name) -> bool:
    return bool(name) and name.startswith(PLAID_RLS_ROLE_PREFIX)


def is_protected_rule_name(name) -> bool:
    return bool(name) and name.startswith(PLAID_RLS_NAME_STEM)


def is_automation_principal() -> bool:
    """True only for the one Superset user plaid's own service calls
    authenticate as -- see the module docstring. Fails CLOSED if
    ``PLAID_RLS_AUTOMATION_USERNAME`` is unset: an empty/missing config value
    must never be read as "no restriction."
    """
    automation_username = current_app.config.get('PLAID_RLS_AUTOMATION_USERNAME')
    if not automation_username:
        return False
    user = getattr(g, 'user', None)
    username = getattr(user, 'username', None)
    return username is not None and username == automation_username


def _denied(api, name):
    logger.warning(
        "Blocked write to protected RLS resource %r by user %r (automation "
        "principal required).",
        name,
        getattr(getattr(g, 'user', None), 'username', None),
    )
    return api.response_403(message=DENIAL_MESSAGE.format(name=name))


class PlaidRoleApi:
    """Mixin applied ahead of the vendor Role API subclass -- see wiring notes
    in ``plaid/security.py``. Guards the four writes that can affect a
    `plaid_rls_*` role's membership or existence; read/list/permission routes
    are untouched.
    """

    def post(self):
        from flask import request
        name = (request.json or {}).get('name') if request.is_json else None
        if is_protected_role_name(name) and not is_automation_principal():
            return _denied(self, name)
        return super().post()

    def put(self, pk):
        from flask import request
        existing = self.datamodel.get(pk)
        requested_name = (request.json or {}).get('name') if request.is_json else None
        current_name = existing.name if existing else None
        # Whichever of the two names is actually the protected one drives
        # both the check and the message -- a rename INTO the prefix must
        # name the (protected) requested name, not the (unprotected) current
        # one, and vice versa for a rename away from it.
        protected_name = next(
            (n for n in (current_name, requested_name) if is_protected_role_name(n)),
            None,
        )
        if protected_name and not is_automation_principal():
            return _denied(self, protected_name)
        return super().put(pk)

    def delete(self, pk):
        existing = self.datamodel.get(pk)
        name = existing.name if existing else None
        if is_protected_role_name(name) and not is_automation_principal():
            return _denied(self, name)
        return super().delete(pk)

    def update_role_users(self, pk):
        existing = self.datamodel.get(pk)
        name = existing.name if existing else None
        if is_protected_role_name(name) and not is_automation_principal():
            return _denied(self, name)
        return super().update_role_users(pk)


def _guard_rls_rule_write(get_names):
    """Wrap an `RLSRestApi` method: block it when any name `get_names(self,
    *args, **kwargs)` returns is protected and the caller is not the
    automation principal. `get_names` returns a list so `bulk_delete` (many
    rules per call) and the single-item routes share one wrapper.
    """
    def decorator(method):
        @functools.wraps(method)
        def wrapped(self, *args, **kwargs):
            names = get_names(self, *args, **kwargs)
            protected = [n for n in names if is_protected_rule_name(n)]
            if protected and not is_automation_principal():
                return _denied(self, protected[0])
            return method(self, *args, **kwargs)
        return wrapped
    return decorator


def _post_names(api):
    from flask import request
    name = (request.json or {}).get('name') if request.is_json else None
    return [name] if name else []


def _put_names(api, pk):
    from flask import request
    existing = api.datamodel.get(pk)
    names = [existing.name] if existing else []
    requested = (request.json or {}).get('name') if request.is_json else None
    if requested:
        names.append(requested)
    return names


def _delete_names(api, pk):
    existing = api.datamodel.get(pk)
    return [existing.name] if existing else []


def _bulk_delete_names(api, **kwargs):
    item_ids = kwargs.get('rison') or []
    names = []
    for pk in item_ids:
        row = api.datamodel.get(pk)
        if row is not None:
            names.append(row.name)
    return names


def install() -> None:
    """Monkeypatch `RLSRestApi`'s four write routes in place. Idempotent --
    safe to call more than once (e.g. module re-import under a reloader).
    """
    from superset.row_level_security.api import RLSRestApi

    if getattr(RLSRestApi, '_plaid_rls_guard_installed', False):
        return

    RLSRestApi.post = _guard_rls_rule_write(_post_names)(RLSRestApi.post)
    RLSRestApi.put = _guard_rls_rule_write(_put_names)(RLSRestApi.put)
    RLSRestApi.delete = _guard_rls_rule_write(_delete_names)(RLSRestApi.delete)
    RLSRestApi.bulk_delete = _guard_rls_rule_write(_bulk_delete_names)(RLSRestApi.bulk_delete)
    RLSRestApi._plaid_rls_guard_installed = True
    logger.info('plaid_rls write guard installed on RLSRestApi.')
