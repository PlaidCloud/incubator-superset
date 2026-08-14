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

Also protected -- and this is the part that is NOT expressible as "patch the
right API methods", see below: acquiring a protected role's entitlement
*without ever writing the role itself*. `FAB's BaseSecurityManager.
get_user_roles` (and Superset's `get_rls_filters`, which is what actually
resolves RLS-rule matching) both compute a user's effective roles as
``user.roles + [role for group in user.groups for role in group.roles]``
(`flask_appbuilder/security/manager.py:1519`). So a `plaid_rls_*` role's
entitlement is ALSO reachable via:

- `RoleApi.update_role_groups` -- ``PUT /api/v1/security/roles/{id}/groups``
  (FAB, `security/sqla/apis/role/api.py:236-306``, sets ``role.groups = [...]``);
- `GroupApi` -- registered whenever ``FAB_ADD_SECURITY_API`` is true (it is,
  both in Superset's own `config.py` default and in every deployed tenant
  config), full CRUD, `edit_columns` include both ``users`` and ``roles``
  (`security/sqla/apis/group/api.py`) -- one `POST` creates a group holding
  the target role with the attacker as a member;
- `UserApi.put` -- the GENERIC ``PUT /api/v1/security/users/{id}`` (distinct
  from `RoleApi.update_role_users`), whose `edit_columns` also include both
  ``roles`` and ``groups`` (`security/sqla/apis/user/api.py:45-54`) and which
  `SupersetUserApi` does not restrict.

None of those three go through the methods the first draft of this guard
patched. **This is not an accident of coverage -- it is the general case.**
Enumerating write-capable API methods is provably incomplete: this file's
own first version missed three of them on its first pass, found only by an
independent review reasoning from the schema outward rather than from the
route table. The fix is therefore NOT "patch three more methods" -- it is
`install_orm_listeners()` below, which vetoes the underlying SQLAlchemy
collection mutation directly, at the three association tables every one of
those paths (and any future one -- a CLI script, a bulk importer, a
not-yet-written admin action) must ultimately write through: ``ab_user_role``,
``ab_group_role``, ``ab_user_group``. A relationship-collection append fires
its event before any SQL is issued and regardless of which side of a
backref-paired relationship (`Role.user` / `User.roles`, `Group.roles` /
`Role.groups`, `Group.users` / `User.groups`) triggered it -- verified
empirically, not assumed; see the test suite. The per-route guards
(`PlaidRoleApi`, `install()`) stay as defense-in-depth -- they give a clean
403 instead of a 500 for the common case -- but the ORM listeners are the
actual control.

NOT protected here, disclosed rather than silently assumed to be covered:
dataset identity. ``DatasetPutSchema`` lets a dataset owner rewrite
``table_name`` / ``schema`` / ``catalog`` / ``sql`` behind
``raise_for_ownership``, which any Admin passes -- a second way to point a
generated rule's binding at different data without touching the rule or role
this guard watches at all. Out of scope for Part 4; see sc-23432 (referenced by
description only -- do not cite it in commits/branches/PRs in THIS repo).

Also NOT protected, and not something an ORM listener can reach: a write
that never goes through the SQLAlchemy ORM at all -- a raw ``INSERT INTO
ab_user_role`` issued outside this application (direct DB access, a
different service sharing the metadata DB). That is a different trust
boundary than this guard is written against.

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

The username check alone is not quite enough: `oauth_user_info`
(`plaid/security.py`) derives the OAuth login's username from a Keycloak
claim (`data.get("name", data["preferred_username"])`) that the logging-in
user's own IdP profile controls, so a Keycloak account whose display name or
username happens to collide with the automation username cannot be ruled
out by name alone. `is_automation_principal` additionally requires that the
CURRENT request was not authenticated via an OAuth session -- FAB stamps
``session['oauth']`` only on the OAuth login path (`security/manager.py:592`),
never on a JWT-bearer API call (which is how plaid's own automation always
authenticates, `provider: 'db'`) -- so an OAuth-derived session can never
satisfy this check regardless of what username it carries.

## Why this lives in ``plaid/``, and how it attaches

Two different attachment points, because the two resource kinds are wired into
Superset differently:

* Roles: ``SecurityManager.role_api`` is already an override point --
  ``SupersetSecurityManager`` sets it to ``SupersetRoleApi`` (see
  ``superset/security/manager.py``) so that FAB's own
  ``register_views()`` -> ``self.appbuilder.add_api(self.role_api)`` picks up
  the subclass. ``PlaidRoleApi`` here extends ``RoleApi`` directly (the same
  class ``SupersetRoleApi`` extends) -- not as a bare mixin: it is always
  combined with ``SupersetRoleApi`` at the point it is actually used
  (``plaid/security.py``'s ``_PlaidGuardedRoleApi``), and declaring the real
  shared ancestor is both correct typing (mypy can see ``post``/``put``/
  ``delete``/``update_role_users``/``datamodel`` are genuinely inherited, not
  merely hoped for) and a truer statement of the contract than an untyped
  mixin would be. Subclassing costs one thing, and it is not obvious:
  overriding a FAB API method deletes that method's route unless the
  override carries the vendor's ``_urls`` forward -- see
  ``_keeps_vendor_route`` (sc-24868).
* RLS rules: ``RLSRestApi`` (``superset/row_level_security/api.py``) has no
  equivalent override attribute -- Superset registers the class directly. Its
  ``post`` / ``put`` / ``delete`` / ``bulk_delete`` are monkeypatched in place
  by ``install()`` below. Importing ``RLSRestApi`` transitively reaches
  ``superset.db_engine_specs.base``, whose module-scope Marshmallow schemas
  call Flask-Babel's ``gettext`` at import time -- which raises
  ``KeyError: 'babel'`` if run before FAB's own ``AppBuilder.init_app``
  registers Babel on the app (``flask_appbuilder/base.py``: the security
  manager is constructed at line 201, Babel at line 202). Calling
  ``install()`` eagerly from ``PlaidSecurityManager.__init__`` -- which runs
  at that line-201 construction step -- therefore crashed every process that
  builds the app, web, celery worker, and celerybeat alike (sc-23432). It is
  instead registered as a Flask ``before_request`` hook
  (``current_app.before_request(rls_guard.install)``, in
  ``plaid/security.py``): FAB registers its own
  ``before_request(self.sm.before_request)`` at ``base.py:207``, strictly
  after Babel exists, and no request is dispatched until long after
  ``create_app()`` returns, so by the time any request reaches a route,
  Babel is present and ``install()`` -- idempotent, see below -- has already
  patched the class before that request's view function runs.

  ⚠️ Deferring past ``add_api(RLSRestApi)`` is NOT free, and the original
  version of this paragraph had the reason exactly backwards. It claimed
  "Python resolves ``self.post(...)`` from the class's current ``__dict__``
  at CALL time, not at route-registration time, so ordering relative to
  ``add_api(RLSRestApi)`` does not matter." FAB never calls ``self.post(...)``
  for a request: ``BaseApi._register_urls`` captures the BOUND METHOD at
  registration and hands it to ``add_url_rule``, and Flask dispatches out of
  ``app.view_functions``. So the class patch reached direct calls (every unit
  test) and nothing else -- the rule guard was inert for every real request
  from the day it shipped. ``install()`` now also repoints those registered
  view functions; see ``_rebind_registered_routes``.
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, TYPE_CHECKING, TypeVar

from flask import current_app, g, Response
from flask_appbuilder.security.sqla.apis import RoleApi

if TYPE_CHECKING:
    from flask_appbuilder.api import BaseApi
    from flask_appbuilder.security.sqla.models import Group, Role, User
    from sqlalchemy.orm.attributes import Event

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Roles only ever use this exact form (trailing underscore -- a role is never
# a guard). Rules use this stem with either `_` (Regular) or `guard_`
# (Base guard) after it -- `is_protected_rule_name` checks the shorter,
# underscore-less stem so both survive one check.
PLAID_RLS_ROLE_PREFIX = "plaid_rls_"
PLAID_RLS_NAME_STEM = "plaid_rls"

DENIAL_MESSAGE = (
    "{name!r} is a PlaidCloud-generated row-access resource. It can only be "
    "written by PlaidCloud's own automation."
)


def is_protected_role_name(name: str | None) -> bool:
    # `is not None` rather than `bool(name)`: both treat `''` the same way
    # (an empty string is falsy either way, and `''.startswith(...)` would
    # correctly return False regardless), but only `is not None` is a form
    # mypy recognizes as narrowing `name` from `str | None` to `str`.
    return name is not None and name.startswith(PLAID_RLS_ROLE_PREFIX)


def is_protected_rule_name(name: str | None) -> bool:
    return name is not None and name.startswith(PLAID_RLS_NAME_STEM)


def _session_is_oauth() -> bool:
    """True iff the CURRENT request authenticated via an OAuth-derived
    session. FAB stamps ``session['oauth']`` only on that path
    (`security/manager.py:592`) -- a JWT-bearer API call, which is how
    plaid's own automation always authenticates, never sets it. See the
    module docstring's "who may write" section for why this matters: the
    username alone is attacker-controlled input on the OAuth path.
    """
    from flask import session

    return "oauth" in session


def _request_identity() -> Any:
    """The user this request authenticates as -- resolving a JWT bearer token
    first, because nothing else has yet.

    sc-24868: every guard in this module runs BEFORE the vendor's
    ``@protect()``, and ``@protect()`` is the only thing that ever turns a
    bearer token into an identity. FAB's ``load_user_jwt`` is registered as
    a ``user_lookup_loader``, so it fires from inside
    ``verify_jwt_in_request()`` and assigns ``g.user`` there -- its own
    comment reads "Set flask g.user to JWT user, we can't do it on before
    request". FAB's ``before_request`` only does ``g.user = current_user``,
    which for a bearer-token request carrying no session cookie is
    Flask-Login's anonymous user.

    So reading ``g.user`` directly would refuse the automation principal
    ITSELF -- plaid authenticates to Superset with an ``Authorization:
    Bearer`` header and nothing else (``superset_rest`` /
    ``superset_get_token``, provider ``db``) -- which is the one identity
    this whole module exists to keep writing. That defect was dormant only
    because the guards never ran; restoring their routes makes it live.

    ``optional=True`` makes a request with no token a no-op rather than an
    error, leaving whatever ``before_request`` established (an OAuth or
    session user, or nobody). A malformed or expired token still raises,
    and is treated here as no identity at all -- fail closed.
    """
    from flask_jwt_extended import verify_jwt_in_request

    try:
        verify_jwt_in_request(optional=True)
    except Exception:  # pylint: disable=broad-except
        # Every failure here means the same thing -- this request carries no
        # usable identity -- and none of them may become a 500 out of a
        # guard: a malformed or expired token (still raised under
        # `optional=True`), or an app with no JWT extension configured
        # (`KeyError: 'JWT_TOKEN_LOCATION'`). The caller is refused below,
        # not crashed.
        logger.debug("rls_guard: no usable bearer identity on this request.")
    return getattr(g, "user", None)


def is_automation_principal() -> bool:
    """True only for the one Superset user plaid's own service calls
    authenticate as -- see the module docstring. Fails CLOSED if
    ``PLAID_RLS_AUTOMATION_USERNAME`` is unset: an empty/missing config value
    must never be read as "no restriction." Also fails closed on an
    OAuth-derived session regardless of username -- see `_session_is_oauth`.
    """
    automation_username = current_app.config.get("PLAID_RLS_AUTOMATION_USERNAME")
    if not automation_username:
        return False
    if _session_is_oauth():
        return False
    username = getattr(_request_identity(), "username", None)
    return username is not None and username == automation_username


def _is_authenticated() -> bool:
    """Whether this request carries any identity at all -- via
    ``_request_identity``, so a bearer token counts, and a caller who holds
    a valid one is never told a protected resource exists but answered 401.
    An unauthenticated request reaches a view carrying Flask-Login's
    ``AnonymousUserMixin``: ``is_authenticated`` False.
    """
    return bool(getattr(_request_identity(), "is_authenticated", False))


def _denied(api: "BaseApi", name: str | None) -> Response:
    """Build the refusal response.

    An unauthenticated caller gets a bare 401 instead of the named 403
    (sc-24868 review). Every guard in this module runs BEFORE the vendor's
    ``@protect()`` -- that decorator sits on the method the guard delegates
    to, and is only reached on the ALLOWED path -- so an anonymous request
    lands here, and a 403 quoting the resource name would let a caller with
    no credentials at all enumerate which role ids are PlaidCloud-generated
    and read the Keycloak group id embedded in each name, purely from the
    403-vs-401 split.

    Delegating to ``super()`` for anonymous callers and letting
    ``@protect()`` answer is NOT the alternative it looks like:
    ``@protect()`` admits a request outright when ``is_item_public`` finds
    the Public role holding the permission (``security/manager.py:1457``),
    so on a workspace that has published role writes the delegation would
    perform the write this module exists to refuse. Refusing here keeps the
    guard fail-closed and changes only what the refusal says.

    Deliberately calls the generic
    ``BaseApi.response(code, **kwargs)`` rather than ``response_403()`` --
    FAB 5.0.2's ``response_403`` takes NO ``message`` argument at all
    (``def response_403(self) -> Response``, hardcoded to "Forbidden"; no
    subclass in FAB or this fork overrides it). ``response_400``/
    ``response_422`` both build their own message the same way this does.
    The earlier version of this file called ``response_403(message=...)``,
    which would have raised ``TypeError`` at the first real invocation --
    masked in testing by a hand-rolled mock that (wrongly) accepted the
    kwarg the real method does not.
    """
    logger.warning(
        "Blocked write to protected RLS resource %r by user %r (automation "
        "principal required).",
        name,
        getattr(getattr(g, "user", None), "username", None),
    )
    if not _is_authenticated():
        return api.response_401()
    return api.response(403, message=DENIAL_MESSAGE.format(name=name))


def _keeps_vendor_route(parent: Callable[..., Any]) -> Callable[[F], F]:
    """Carry the vendor method's FAB route metadata onto an override of it.

    sc-24868: a plain subclass override of a FAB API method silently
    UNREGISTERS that method's route. ``BaseApi._register_urls`` walks
    ``dir(self)`` and calls ``add_url_rule`` only for attributes carrying
    ``_urls`` (which ``@expose`` attaches); an undecorated override shadows
    the decorated vendor attribute, so the route is never added at all.
    Live on bf2 that made ``POST``/``PUT``/``DELETE
    /api/v1/security/roles/`` answer 405 and ``PUT
    /api/v1/security/roles/<id>/users`` answer 404, breaking the
    reconciler's role create and its roster write -- while the guard bodies
    below, being unreachable, never ran.

    Two more attributes have to come along, each silent in a different way
    (parity for all three is asserted by
    ``test_override_carries_every_attribute_fab_reads``):

    * ``_permission_name`` (``@permission_name``) -- the permission scan in
      ``BaseApi.__init__`` reads it to build ``base_permissions``, and
      ``@protect()``, which still runs inside the vendor method these
      delegate to, answers 403 to *everyone* for a permission missing from
      that list. Restoring the route without this trades a 405 for a 403.
    * ``__doc__`` -- FAB's OpenAPI generation parses the YAML block in the
      vendor method's docstring; an override's own (prose) docstring would
      reduce these four operations to a bare tag, silently stripping their
      request/response schemas from ``/api/v1/_openapi``. The guard adds no
      parameter and no status code of its own beyond the 403 it shares with
      every other FAB permission failure, so the vendor's description
      remains the accurate one. Guard behaviour is documented on the class,
      not on the routes.

    The whole ``__dict__`` is deliberately NOT copied: ``@safe`` and
    ``@protect()`` leave a ``__wrapped__`` behind, which would point
    ``inspect.signature`` at a different function than the override.
    """

    def decorator(method: F) -> F:
        method._urls = list(parent._urls)  # type: ignore[attr-defined]
        method._permission_name = parent._permission_name  # type: ignore[attr-defined]
        method.__doc__ = parent.__doc__
        return method

    return decorator


class PlaidRoleApi(RoleApi):
    """Guard mixin for the vendor Role API -- see the wiring notes in the
    module docstring and in ``plaid/security.py``. Guards the four writes
    that can affect a `plaid_rls_*` role's membership or existence;
    read/list/permission routes are untouched. Declared as a `RoleApi`
    subclass (not a bare mixin) because it is always combined with
    `SupersetRoleApi` at its point of use -- see the module docstring.

    Every override here MUST carry ``@_keeps_vendor_route`` -- see its
    docstring; without it the override deletes the very route it guards.
    """

    @_keeps_vendor_route(RoleApi.post)
    def post(self) -> Response:
        from flask import request

        name = (request.json or {}).get("name") if request.is_json else None
        if is_protected_role_name(name) and not is_automation_principal():
            return _denied(self, name)
        return super().post()

    @_keeps_vendor_route(RoleApi.put)
    def put(self, pk: int) -> Response:
        from flask import request

        existing = self.datamodel.get(pk)
        requested_name = (request.json or {}).get("name") if request.is_json else None
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

    @_keeps_vendor_route(RoleApi.delete)
    def delete(self, pk: int) -> Response:
        existing = self.datamodel.get(pk)
        name = existing.name if existing else None
        if is_protected_role_name(name) and not is_automation_principal():
            return _denied(self, name)
        return super().delete(pk)

    # `role_id`, not `pk`: this route is `/<int:role_id>/users`, and Flask
    # passes URL converters as keyword arguments -- an override named `pk`
    # raises TypeError on every call the moment the route is registered again.
    @_keeps_vendor_route(RoleApi.update_role_users)
    def update_role_users(self, role_id: int) -> Response:
        existing = self.datamodel.get(role_id)
        name = existing.name if existing else None
        if is_protected_role_name(name) and not is_automation_principal():
            return _denied(self, name)
        return super().update_role_users(role_id)


GetNamesFn = Callable[..., list[str]]
RlsRouteFn = Callable[..., Response]


def _guard_rls_rule_write(get_names: GetNamesFn) -> Callable[[RlsRouteFn], RlsRouteFn]:
    """Wrap an `RLSRestApi` method: block it when any name `get_names(self,
    *args, **kwargs)` returns is protected and the caller is not the
    automation principal. `get_names` returns a list so `bulk_delete` (many
    rules per call) and the single-item routes share one wrapper.
    """

    def decorator(method: RlsRouteFn) -> RlsRouteFn:
        @functools.wraps(method)
        def wrapped(self: "BaseApi", *args: Any, **kwargs: Any) -> Response:
            names = get_names(self, *args, **kwargs)
            protected = [n for n in names if is_protected_rule_name(n)]
            if protected and not is_automation_principal():
                return _denied(self, protected[0])
            return method(self, *args, **kwargs)

        return wrapped

    return decorator


def _post_names(api: "BaseApi") -> list[str]:
    from flask import request

    name = (request.json or {}).get("name") if request.is_json else None
    return [name] if name else []


def _put_names(api: "BaseApi", pk: int) -> list[str]:
    from flask import request

    existing = api.datamodel.get(pk)
    names = [existing.name] if existing else []
    requested = (request.json or {}).get("name") if request.is_json else None
    if requested:
        names.append(requested)
    return names


def _delete_names(api: "BaseApi", pk: int) -> list[str]:
    existing = api.datamodel.get(pk)
    return [existing.name] if existing else []


def _bulk_delete_names(api: "BaseApi", **kwargs: Any) -> list[str]:
    item_ids = kwargs.get("rison") or []
    names = []
    for pk in item_ids:
        row = api.datamodel.get(pk)
        if row is not None:
            names.append(row.name)
    return names


def _rebind_registered_routes(
    api_class: type[BaseApi], method_names: tuple[str, ...]
) -> None:
    """Point Flask's already-registered view functions at the patched methods.

    sc-24868: without this, `install()` below is INERT for every HTTP
    request. `install()` deliberately runs on the first request, which is
    necessarily after `add_api(RLSRestApi)` -- and FAB does not look the
    handler up on the class at call time. `BaseApi._register_urls` captures
    the BOUND METHOD once, at registration (`attr = getattr(self,
    attr_name)` ... `add_url_rule(url, attr_name, route_handler)`), and
    Flask stores it in `app.view_functions`. Rebinding the class attribute
    afterwards changes what a direct `api.post(...)` call does -- which is
    all the unit tests ever did -- and nothing whatsoever about what the
    route calls. Confirmed live: a `plaid_rls_`-named rule write reached
    Superset's own schema validation with no denial logged.

    Rebuilding the handler through FAB's own `wrap_route_handler_with_hooks`
    rather than assigning the bare bound method keeps any `@before_request`
    hook the vendor class declares -- there are none on `RLSRestApi` today,
    and silently dropping them later would be its own quiet defect.

    Raises rather than logging if an endpoint is missing: this whole module
    fails closed, and the failure it exists to prevent is exactly a guard
    that is present, looks installed, and does nothing.
    """
    from flask_appbuilder.hooks import (
        get_before_request_hooks,
        wrap_route_handler_with_hooks,
    )

    instance = next(
        (v for v in current_app.appbuilder.baseviews if isinstance(v, api_class)), None
    )
    if instance is None:
        raise PlaidRlsGuardError(
            f"{api_class.__name__} is not registered on this app -- the "
            "plaid_rls rule guard cannot attach to its routes."
        )

    hooks = get_before_request_hooks(instance)
    for name in method_names:
        endpoint = f"{instance.endpoint}.{name}"
        if endpoint not in current_app.view_functions:
            raise PlaidRlsGuardError(
                f"No registered route for {endpoint} -- the plaid_rls rule "
                "guard cannot attach to it."
            )
        current_app.view_functions[endpoint] = wrap_route_handler_with_hooks(
            name, getattr(instance, name), hooks
        )


def install() -> None:
    """Monkeypatch `RLSRestApi`'s four write routes in place, then repoint the
    routes FAB already registered at the patched methods -- see
    `_rebind_registered_routes`, without which the patch never runs for an
    actual request. Idempotent -- safe to call more than once (e.g. module
    re-import under a reloader).
    """
    from superset.row_level_security.api import RLSRestApi

    if getattr(RLSRestApi, "_plaid_rls_guard_installed", False):
        return

    RLSRestApi.post = _guard_rls_rule_write(_post_names)(RLSRestApi.post)
    RLSRestApi.put = _guard_rls_rule_write(_put_names)(RLSRestApi.put)
    RLSRestApi.delete = _guard_rls_rule_write(_delete_names)(RLSRestApi.delete)
    RLSRestApi.bulk_delete = _guard_rls_rule_write(_bulk_delete_names)(
        RLSRestApi.bulk_delete
    )
    _rebind_registered_routes(RLSRestApi, ("post", "put", "delete", "bulk_delete"))
    RLSRestApi._plaid_rls_guard_installed = True
    logger.info("plaid_rls write guard installed on RLSRestApi.")


# --- ORM-level guard: the actual control -----------------------------------
#
# See the module docstring's "What this protects" section for why route
# patching alone is insufficient. These three listeners sit on the
# association-table relationships every path to "this user's effective role
# set includes a plaid_rls_* role" must write through, regardless of which
# REST route, CLI command, or future code path performs the write.


class PlaidRlsGuardError(Exception):
    """Raised from inside a SQLAlchemy collection-mutation event to veto it.
    Propagates up through whatever ORM call triggered the mutation (a route
    handler, a script, a shell command) -- there is no single HTTP layer to
    convert this to a clean status code for every caller, so it surfaces as
    whatever that caller does with an uncaught exception. For the REST routes
    this still reaches (FAB's `@safe` maps an uncaught exception to a 500),
    the write is refused either way; the per-route guards above exist to give
    the common case a clean 403 before the ORM layer is ever reached.
    """


def _group_holds_protected_role(group: "Group") -> bool:
    return any(is_protected_role_name(getattr(r, "name", None)) for r in group.roles)


def _veto_protected_role_grant(role_name: str | None) -> None:
    if is_protected_role_name(role_name) and not is_automation_principal():
        logger.warning(
            "Blocked ORM-level grant of protected role %r to user %r "
            "(automation principal required).",
            role_name,
            getattr(getattr(g, "user", None), "username", None),
        )
        raise PlaidRlsGuardError(DENIAL_MESSAGE.format(name=role_name))


def _guard_role_user_append(role: "Role", user: "User", initiator: "Event") -> None:
    """Fires on `role.user.append(...)` / `role.user = [...]` (RoleApi.
    update_role_users' shape) AND on `user.roles.append(role)` / `user.roles
    = [...]` via the backref (UserApi.put's shape) -- empirically confirmed
    both directions fire this same event; see the test suite.
    """
    del user, initiator  # unused -- SQLAlchemy's event signature is fixed
    _veto_protected_role_grant(getattr(role, "name", None))


def _guard_group_role_append(group: "Group", role: "Role", initiator: "Event") -> None:
    """Fires on `group.roles.append(...)` / `group.roles = [...]` (GroupApi's
    shape) AND on `role.groups.append(group)` / `role.groups = [...]` via the
    backref (RoleApi.update_role_groups' shape)."""
    del group, initiator  # unused -- SQLAlchemy's event signature is fixed
    _veto_protected_role_grant(getattr(role, "name", None))


def _guard_group_user_append(group: "Group", user: "User", initiator: "Event") -> None:
    """Adding a user to a group that ALREADY holds a protected role grants
    that role's entitlement without ever writing `ab_group_role` -- this is
    the third leg (GroupApi's `users` field, and UserApi.put's `groups`
    field via the backref) and needs its own check: is the GROUP protected,
    not the (irrelevant here) role name."""
    del initiator  # unused -- SQLAlchemy's event signature is fixed
    if not is_automation_principal() and _group_holds_protected_role(group):
        logger.warning(
            "Blocked ORM-level group-membership grant into %r, which holds a "
            "protected role, for user %r (automation principal required).",
            getattr(group, "name", None),
            getattr(user, "username", None),
        )
        raise PlaidRlsGuardError(
            f"{getattr(group, 'name', None)!r} holds a PlaidCloud-generated "
            "row-access role. Membership can only be written by PlaidCloud's "
            "own automation."
        )


def install_orm_listeners() -> None:
    """Attach the three association-table veto listeners. Idempotent.

    Deliberately does NOT also listen on the `remove` event -- revoking
    access is not the risk this guards against, and vetoing removal would
    make it impossible for PlaidCloud's own reconciler to ever narrow a
    grant without also being the automation principal for the remove call,
    which it always is, but there is no reason to make that a requirement
    of the model.
    """
    from flask_appbuilder.security.sqla.models import Group, Role

    if getattr(Role, "_plaid_rls_orm_guard_installed", False):
        return

    from sqlalchemy import event

    event.listen(Role.user, "append", _guard_role_user_append)
    event.listen(Group.roles, "append", _guard_group_role_append)
    event.listen(Group.users, "append", _guard_group_user_append)
    Role._plaid_rls_orm_guard_installed = True
    logger.info("plaid_rls ORM-level role/group guard installed.")
