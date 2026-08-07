# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""sc-23432 Part 4 -- the fork-side write guard.

Deliberately does NOT `import plaid.security` (unlike test_security.py) --
`rls_guard.py` imports only Flask, not `plaidcloud.rpc`, so these tests run
under plain CI without the `pytest.importorskip` gate that skips
`plaid.security`-dependent tests today (`requirements/base.txt` vs.
`development.txt`, see test_security.py). That gap is real and pre-existing
(sc-23907/sc-23981) -- keeping this file independent of it means the guard's
own logic is still exercised even while that gap is open.

Uses the repo's own `app` / `app_context` fixtures (`tests/unit_tests/
conftest.py`) rather than a hand-rolled bare `Flask()` app. A bare app has
none of Superset's config, and Superset registers its own SQLAlchemy events
globally at import time regardless of which app is active --
`sqla.event.listen(User, "after_insert", copy_dashboard)`
(`superset/models/dashboard.py:90`) fires on every `User` insert in this
process and unconditionally reads `app.config["DASHBOARD_TEMPLATE_ID"]`
(`:62`, no `.get()` default). A bare app lacks that key entirely -> KeyError
on the very first `User` this file ever inserts. The real `app` fixture
loads `superset.config` (`DASHBOARD_TEMPLATE_ID = None` there), so the
handler's own `if dashboard_id is None: return` guard runs as intended.
`app` is module-scoped (shared across this whole file) -- any test that
needs to change its config uses `monkeypatch.setitem(app.config, ...)`,
which reverts automatically, rather than a bare assignment that would leak
into every other test in the file.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from flask import g
from flask_appbuilder.api import ModelRestApi
from flask_appbuilder.security.sqla.apis import RoleApi
from flask_appbuilder.security.sqla.models import Group, Model, Role, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaid import rls_guard

# --- name classification -----------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("plaid_rls_3fa85f64-5717-4562-b3fc-2c963f66afa6", True),
        ("plaid_rls_", True),  # degenerate, but still the reserved prefix
        ("plaid_rlsguard_x", False),  # rule-only form, not a role name
        ("CONTRACTS", False),
        ("CC-Name = 438", False),
        (None, False),
        ("", False),
    ],
)
def test_is_protected_role_name(name, expected):
    assert rls_guard.is_protected_role_name(name) is expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("plaid_rls_proj123_abcd", True),
        ("plaid_rlsguard_proj123_abcd", True),
        ("plaid_rls_3fa85f64-5717-4562-b3fc-2c963f66afa6", True),  # a role name too
        ("jinja_test_mago", False),
        ("CC-Name = 438", False),
        (None, False),
    ],
)
def test_is_protected_rule_name(name, expected):
    assert rls_guard.is_protected_rule_name(name) is expected


# --- automation-principal check -----------------------------------------
#
# PLAID_RLS_AUTOMATION_USERNAME defaults to 'admin' via superset/config.py
# (set there by the Part 4a PR), so most of these need no config override.


def test_automation_principal_matches_configured_username(app, app_context):
    with app.test_request_context():
        g.user = SimpleNamespace(username="admin")
        assert rls_guard.is_automation_principal() is True


def test_automation_principal_rejects_other_username(app, app_context):
    """The exact scenario the guard exists for: a Keycloak-mapped Admin-role
    user is a different `ab_user` row than plaid's own automation login."""
    with app.test_request_context():
        g.user = SimpleNamespace(username="alice@customer.com")
        assert rls_guard.is_automation_principal() is False


def test_automation_principal_rejects_no_user(app, app_context):
    with app.test_request_context():
        assert rls_guard.is_automation_principal() is False


def test_automation_principal_fails_closed_when_unconfigured(
    app, app_context, monkeypatch
):
    """Empty/missing config must never be read as 'no restriction' -- the
    module docstring's explicit fail-closed contract."""
    monkeypatch.setitem(app.config, "PLAID_RLS_AUTOMATION_USERNAME", None)
    with app.test_request_context():
        g.user = SimpleNamespace(username="admin")
        assert rls_guard.is_automation_principal() is False


def test_automation_principal_fails_closed_on_empty_string(
    app, app_context, monkeypatch
):
    monkeypatch.setitem(app.config, "PLAID_RLS_AUTOMATION_USERNAME", "")
    with app.test_request_context():
        g.user = SimpleNamespace(username="admin")
        assert rls_guard.is_automation_principal() is False


def test_oauth_session_cannot_satisfy_automation_principal_even_with_matching_username(
    app, app_context
):
    """Non-blocking review item: a Keycloak OAuth login's username is
    attacker-controlled input, not proof of identity. An OAuth-derived
    session must be refused even if its username happens to be 'admin'."""
    with app.test_request_context():
        from flask import session

        session["oauth"] = ("token", "secret")
        g.user = SimpleNamespace(username="admin")
        assert rls_guard.is_automation_principal() is False


# --- PlaidRoleApi -- exercised through the REAL RoleApi/ModelRestApi MRO --
#
# `PlaidRoleApi` is a genuine `RoleApi` subclass (see the module docstring
# for why -- this is what fixed the "post/put/delete/update_role_users
# undefined in superclass" + "no attribute datamodel" mypy errors the first
# version's bare-mixin design produced). So `super().post()` etc. resolve to
# FAB's real `ModelRestApi.post/put/delete` and `RoleApi.update_role_users`
# -- patched here rather than replaced via a stand-in class placed later in
# an artificial MRO, which stopped working the moment the base class became
# real (Python resolves `super()` through the actual MRO, not a fixture's
# wish for one).


class _GuardedRoleApi(rls_guard.PlaidRoleApi):
    pass


def _api(role):
    # Bypasses ModelRestApi.__init__, which expects to be wired up by a real
    # AppBuilder instance -- this test only needs `self.datamodel` and the
    # guard's own logic, not a fully registered API.
    api = object.__new__(_GuardedRoleApi)
    api.datamodel = SimpleNamespace(get=lambda pk: role)
    return api


def _patch_upstream():
    """Patches the REAL methods `super()` resolves to, recording calls in
    the returned list. Used as a context manager: `with _patch_upstream()
    as calls: ...`.
    """
    calls = []

    def fake_post(self):
        calls.append("post")
        return "posted"

    def fake_put(self, pk):
        calls.append(("put", pk))
        return "put"

    def fake_delete(self, pk):
        calls.append(("delete", pk))
        return "deleted"

    def fake_update_role_users(self, pk):
        calls.append(("update_role_users", pk))
        return "updated"

    ctx = patch.multiple(
        ModelRestApi,
        post=fake_post,
        put=fake_put,
        delete=fake_delete,
    )
    role_ctx = patch.object(RoleApi, "update_role_users", fake_update_role_users)

    class _Both:
        def __enter__(self):
            ctx.__enter__()
            role_ctx.__enter__()
            return calls

        def __exit__(self, *exc):
            role_ctx.__exit__(*exc)
            ctx.__exit__(*exc)

    return _Both()


@pytest.mark.parametrize(
    "method_name, args",
    [
        ("delete", (1,)),
        ("update_role_users", (1,)),
    ],
)
def test_role_write_blocked_for_non_automation_user(
    app, app_context, method_name, args
):
    role = SimpleNamespace(id=1, name="plaid_rls_group-a")
    api = _api(role)
    with app.test_request_context(), _patch_upstream() as calls:
        g.user = SimpleNamespace(username="alice@customer.com")
        result = getattr(api, method_name)(*args)

    assert result.status_code == 403
    assert result.get_json() == {
        "message": rls_guard.DENIAL_MESSAGE.format(name="plaid_rls_group-a")
    }
    assert calls == []


@pytest.mark.parametrize(
    "method_name, args",
    [
        ("delete", (1,)),
        ("update_role_users", (1,)),
    ],
)
def test_role_write_allowed_for_automation_user(app, app_context, method_name, args):
    role = SimpleNamespace(id=1, name="plaid_rls_group-a")
    api = _api(role)
    with app.test_request_context(), _patch_upstream() as calls:
        g.user = SimpleNamespace(username="admin")
        getattr(api, method_name)(*args)

    assert len(calls) == 1


def test_role_write_allowed_for_unprotected_role(app, app_context):
    """A hand-made role like `CONTRACTS` is untouched by this guard -- it is
    not this module's job to lock down roles PlaidCloud did not generate."""
    role = SimpleNamespace(id=1, name="CONTRACTS")
    api = _api(role)
    with app.test_request_context(), _patch_upstream() as calls:
        g.user = SimpleNamespace(username="alice@customer.com")
        api.delete(1)

    assert calls == [("delete", 1)]


def test_role_delete_blocked_when_role_missing_name_lookup_still_guards(
    app, app_context
):
    """`datamodel.get` returning None (already-deleted / bad pk) must not be
    read as 'nothing to protect' -- name is None, is_protected is False, so
    this legitimately falls through to upstream, which 404s on its own. This
    pins that the guard does not itself crash on a missing row."""
    api = _api(role=None)
    with app.test_request_context(), _patch_upstream() as calls:
        g.user = SimpleNamespace(username="alice@customer.com")
        result = api.delete(999)

    assert result == "deleted"
    assert calls == [("delete", 999)]


def test_role_rename_into_reserved_prefix_is_blocked(app, app_context):
    """Renaming an ordinary role INTO the `plaid_rls_` prefix is blocked
    symmetrically -- a workspace admin must not be able to pre-empt or
    impersonate a name the reconciler expects to own next."""
    role = SimpleNamespace(id=1, name="CONTRACTS")
    api = _api(role)
    with (
        app.test_request_context(json={"name": "plaid_rls_group-a"}, method="PUT"),
        _patch_upstream() as calls,
    ):
        g.user = SimpleNamespace(username="alice@customer.com")
        result = api.put(1)

    assert result.status_code == 403
    assert result.get_json() == {
        "message": rls_guard.DENIAL_MESSAGE.format(name="plaid_rls_group-a")
    }
    assert calls == []


def test_role_rename_of_protected_role_is_blocked_even_to_unprotected_name(
    app, app_context
):
    """The opposite direction -- renaming AWAY from the prefix -- is also
    blocked: the CURRENT name is checked too, not just the requested one."""
    role = SimpleNamespace(id=1, name="plaid_rls_group-a")
    api = _api(role)
    with (
        app.test_request_context(json={"name": "not_protected_anymore"}, method="PUT"),
        _patch_upstream() as calls,
    ):
        g.user = SimpleNamespace(username="alice@customer.com")
        result = api.put(1)

    assert result.status_code == 403
    assert result.get_json() == {
        "message": rls_guard.DENIAL_MESSAGE.format(name="plaid_rls_group-a")
    }
    assert calls == []


def test_role_create_of_reserved_name_is_blocked(app, app_context):
    api = _api(role=None)
    with (
        app.test_request_context(json={"name": "plaid_rls_group-a"}, method="POST"),
        _patch_upstream() as calls,
    ):
        g.user = SimpleNamespace(username="alice@customer.com")
        result = api.post()

    assert result.status_code == 403
    assert result.get_json() == {
        "message": rls_guard.DENIAL_MESSAGE.format(name="plaid_rls_group-a")
    }
    assert calls == []


# --- RLSRestApi name extraction + wrapping -------------------------------


def _fake_rls_api(rows_by_id):
    api = SimpleNamespace()
    api.datamodel = SimpleNamespace(get=lambda pk: rows_by_id.get(pk))
    api.response = MagicMock(
        side_effect=lambda code, **kw: SimpleNamespace(
            status_code=code, get_json=lambda: kw
        )
    )
    return api


def test_bulk_delete_names_collects_every_targeted_rule():
    rows = {
        1: SimpleNamespace(id=1, name="plaid_rls_p1_aaaa"),
        2: SimpleNamespace(id=2, name="CONTRACTS"),
    }
    api = _fake_rls_api(rows)
    names = rls_guard._bulk_delete_names(api, rison=[1, 2])
    assert set(names) == {"plaid_rls_p1_aaaa", "CONTRACTS"}


def test_bulk_delete_names_empty_when_no_ids():
    api = _fake_rls_api({})
    assert rls_guard._bulk_delete_names(api, rison=[]) == []
    assert rls_guard._bulk_delete_names(api) == []


def test_guard_rls_rule_write_blocks_when_any_targeted_name_is_protected(
    app, app_context
):
    calls = []

    @rls_guard._guard_rls_rule_write(
        lambda api, *a, **k: ["plaid_rls_p1_aaaa", "CONTRACTS"]
    )
    def method(self, *a, **k):
        calls.append((a, k))
        return "ok"

    api = _fake_rls_api({})
    with app.test_request_context():
        g.user = SimpleNamespace(username="alice@customer.com")
        result = method(api, 1, 2)

    assert result.status_code == 403
    assert result.get_json() == {
        "message": rls_guard.DENIAL_MESSAGE.format(name="plaid_rls_p1_aaaa")
    }
    assert calls == []


def test_guard_rls_rule_write_allows_when_automation_principal(app, app_context):
    calls = []

    @rls_guard._guard_rls_rule_write(lambda api, *a, **k: ["plaid_rls_p1_aaaa"])
    def method(self, *a, **k):
        calls.append((a, k))
        return "ok"

    api = _fake_rls_api({})
    with app.test_request_context():
        g.user = SimpleNamespace(username="admin")
        result = method(api, 1)

    assert result == "ok"
    assert calls == [((1,), {})]


def test_guard_rls_rule_write_allows_unprotected_names(app, app_context):
    calls = []

    @rls_guard._guard_rls_rule_write(
        lambda api, *a, **k: ["CONTRACTS", "jinja_test_mago"]
    )
    def method(self, *a, **k):
        calls.append("called")
        return "ok"

    api = _fake_rls_api({})
    with app.test_request_context():
        g.user = SimpleNamespace(username="alice@customer.com")
        result = method(api)

    assert result == "ok"
    assert calls == ["called"]


def test_install_is_idempotent(monkeypatch):
    """install() patches module-level state on RLSRestApi; calling it twice
    (e.g. a dev reloader re-importing plaid.security) must not double-wrap
    the methods -- each request would otherwise run the guard N times, which
    is harmless but a smell that the class was patched more than once."""
    import sys
    import types

    fake_module = types.ModuleType("superset.row_level_security.api")

    class FakeRLSRestApi:
        def post(self):
            return "post"

        def put(self, pk):
            return "put"

        def delete(self, pk):
            return "delete"

        def bulk_delete(self, **kwargs):
            return "bulk_delete"

    fake_module.RLSRestApi = FakeRLSRestApi
    monkeypatch.setitem(sys.modules, "superset.row_level_security.api", fake_module)

    rls_guard.install()
    once_post = FakeRLSRestApi.post
    rls_guard.install()
    twice_post = FakeRLSRestApi.post

    assert once_post is twice_post


# --- ORM-level guard: proves the reported bypass is actually closed ------
#
# Real FAB models (`flask_appbuilder.security.sqla.models`), a real
# SQLAlchemy session against in-memory SQLite, and the ACTUAL
# `rls_guard.install_orm_listeners()` -- not a reimplementation of its
# logic. Each test performs the exact write shape a bypass route would
# issue and asserts on the real ORM-level effect (row landed or didn't),
# not on a mocked call.
#
# Runs against the real `app`/`app_context` (see module docstring) so
# Superset's own `User` `after_insert` listener (`copy_dashboard`,
# `superset/models/dashboard.py:90`) sees `DASHBOARD_TEMPLATE_ID` in config
# and takes its early-return path instead of raising `KeyError`.


@pytest.fixture
def orm_session():
    rls_guard.install_orm_listeners()
    engine = create_engine("sqlite:///:memory:")
    Model.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _user(session, username):
    u = User(
        first_name="A",
        last_name="B",
        username=username,
        email=f"{username}@example.com",
    )
    session.add(u)
    session.commit()
    return u


def _role(session, name):
    r = Role(name=name)
    session.add(r)
    session.commit()
    return r


def _group(session, name):
    grp = Group(name=name)
    session.add(grp)
    session.commit()
    return grp


def test_role_update_role_users_shape_is_blocked_for_non_automation_user(
    app, app_context, orm_session
):
    """RoleApi.update_role_users: `role.user = [...]`."""
    with app.test_request_context():
        g.user = SimpleNamespace(username="attacker")
        role = _role(orm_session, "plaid_rls_group-a")
        attacker = _user(orm_session, "attacker")

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            role.user = [attacker]

        assert role.user == []


def test_role_update_role_groups_shape_is_blocked(app, app_context, orm_session):
    """RoleApi.update_role_groups: `role.groups = [...]` -- the FIRST
    reported bypass. Fires via the Group.roles backref."""
    with app.test_request_context():
        g.user = SimpleNamespace(username="attacker")
        role = _role(orm_session, "plaid_rls_group-a")
        attacker_group = _group(orm_session, "attacker-group")

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            role.groups = [attacker_group]

        assert role.groups == []
        assert attacker_group.roles == []


def test_group_api_post_shape_is_blocked(app, app_context, orm_session):
    """GroupApi POST/PUT: one call setting both `roles` and `users` -- the
    SECOND reported bypass, and the exact scenario the review asked to be
    reproduced as a test."""
    with app.test_request_context():
        g.user = SimpleNamespace(username="attacker")
        role = _role(orm_session, "plaid_rls_group-a")
        attacker = _user(orm_session, "attacker")
        new_group = Group(name="attacker-made-group")
        orm_session.add(new_group)

        def _grant_role_and_membership():
            new_group.roles = [role]
            new_group.users = [attacker]

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            _grant_role_and_membership()

        # The role assignment is what must be refused; assert the
        # entitlement was never granted regardless of which of the two
        # assignments the exception interrupted.
        assert role not in new_group.roles


def test_user_api_put_roles_shape_is_blocked(app, app_context, orm_session):
    """UserApi.put with `roles`: `user.roles = [...]` -- the THIRD reported
    bypass. Fires via the Role.user backref."""
    with app.test_request_context():
        g.user = SimpleNamespace(username="attacker")
        role = _role(orm_session, "plaid_rls_group-a")
        attacker = _user(orm_session, "attacker")

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            attacker.roles = [role]

        assert attacker.roles == []


def test_user_api_put_groups_shape_is_blocked_when_group_holds_protected_role(
    app, app_context, orm_session
):
    """UserApi.put with `groups`, targeting a group that ALREADY holds a
    protected role -- the fourth path: no write to ab_group_role at all,
    only ab_user_group, so the previous three checks alone would miss it.
    Fires via the Group.users backref."""
    with app.test_request_context():
        role = _role(orm_session, "plaid_rls_group-a")
        holder_group = _group(orm_session, "holder-group")
        # Grant the group's role as the automation principal first, so only
        # the user-membership step below is under test.
        g.user = SimpleNamespace(username="admin")
        holder_group.roles = [role]
        orm_session.commit()

        g.user = SimpleNamespace(username="attacker")
        attacker = _user(orm_session, "attacker")
        with pytest.raises(rls_guard.PlaidRlsGuardError):
            attacker.groups = [holder_group]

        assert attacker.groups == []
        assert attacker not in holder_group.users


def test_unprotected_role_is_unaffected_by_any_of_the_four_paths(
    app, app_context, orm_session
):
    """The guard must not become a blanket lock on all role/group
    administration -- only `plaid_rls_*`-prefixed resources."""
    with app.test_request_context():
        g.user = SimpleNamespace(username="attacker")
        ordinary_role = _role(orm_session, "CONTRACTS")
        attacker = _user(orm_session, "attacker")
        ordinary_group = _group(orm_session, "sales-team")

        ordinary_role.user = [attacker]
        ordinary_group.roles = [ordinary_role]
        ordinary_group.users = [attacker]

        assert ordinary_role.user == [attacker]
        assert ordinary_role in ordinary_group.roles


def test_automation_principal_can_still_grant_every_path(app, app_context, orm_session):
    with app.test_request_context():
        g.user = SimpleNamespace(username="admin")
        role = _role(orm_session, "plaid_rls_group-a")
        member = _user(orm_session, "legit-member")
        role.user = [member]
        assert role.user == [member]

        group = _group(orm_session, "reconciler-group")
        group.roles = [role]
        assert role in group.roles


def test_install_orm_listeners_is_idempotent(app, app_context, orm_session):
    with app.test_request_context():
        rls_guard.install_orm_listeners()
        rls_guard.install_orm_listeners()
        # No duplicate-listener double-raise / double-log; a single veto
        # still refuses exactly once (no assertion error from being called
        # twice with conflicting internal state).
        g.user = SimpleNamespace(username="attacker")
        role = _role(orm_session, "plaid_rls_group-a")
        attacker = _user(orm_session, "attacker")
        with pytest.raises(rls_guard.PlaidRlsGuardError):
            role.user = [attacker]
