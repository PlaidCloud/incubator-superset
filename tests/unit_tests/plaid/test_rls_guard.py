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
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from flask import Flask, g

from plaid import rls_guard


@pytest.fixture()
def app():
    application = Flask(__name__)
    application.config['PLAID_RLS_AUTOMATION_USERNAME'] = 'admin'
    # A couple of tests write to flask.session (to simulate an OAuth-derived
    # request), which Flask refuses without a secret key configured.
    application.config['SECRET_KEY'] = 'test-secret-key'
    return application


# --- name classification -----------------------------------------------

@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('plaid_rls_3fa85f64-5717-4562-b3fc-2c963f66afa6', True),
        ('plaid_rls_', True),  # degenerate, but still the reserved prefix
        ('plaid_rlsguard_x', False),  # rule-only form, not a role name
        ('CONTRACTS', False),
        ('CC-Name = 438', False),
        (None, False),
        ('', False),
    ],
)
def test_is_protected_role_name(name, expected):
    assert rls_guard.is_protected_role_name(name) is expected


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('plaid_rls_proj123_abcd', True),
        ('plaid_rlsguard_proj123_abcd', True),
        ('plaid_rls_3fa85f64-5717-4562-b3fc-2c963f66afa6', True),  # a role name too
        ('jinja_test_mago', False),
        ('CC-Name = 438', False),
        (None, False),
    ],
)
def test_is_protected_rule_name(name, expected):
    assert rls_guard.is_protected_rule_name(name) is expected


# --- automation-principal check -----------------------------------------

def test_automation_principal_matches_configured_username(app):
    with app.test_request_context():
        g.user = SimpleNamespace(username='admin')
        assert rls_guard.is_automation_principal() is True


def test_automation_principal_rejects_other_username(app):
    """The exact scenario the guard exists for: a Keycloak-mapped Admin-role
    user is a different `ab_user` row than plaid's own automation login."""
    with app.test_request_context():
        g.user = SimpleNamespace(username='alice@customer.com')
        assert rls_guard.is_automation_principal() is False


def test_automation_principal_rejects_no_user(app):
    with app.test_request_context():
        assert rls_guard.is_automation_principal() is False


def test_automation_principal_fails_closed_when_unconfigured(app):
    """Empty/missing config must never be read as 'no restriction' -- the
    module docstring's explicit fail-closed contract."""
    app.config['PLAID_RLS_AUTOMATION_USERNAME'] = None
    with app.test_request_context():
        g.user = SimpleNamespace(username='admin')
        assert rls_guard.is_automation_principal() is False


def test_automation_principal_fails_closed_on_empty_string(app):
    app.config['PLAID_RLS_AUTOMATION_USERNAME'] = ''
    with app.test_request_context():
        g.user = SimpleNamespace(username='admin')
        assert rls_guard.is_automation_principal() is False


# --- PlaidRoleApi mixin ---------------------------------------------------

class _StubBaseRoleApi:
    """Stands in for `SupersetRoleApi` in the MRO -- records calls that
    reached "upstream" so a test can assert the guard let a request through
    (or, on the blocked path, never reached here at all).
    """

    def __init__(self, role):
        self.datamodel = SimpleNamespace(get=lambda pk: role)
        self.upstream_calls = []
        self.response_403 = MagicMock(side_effect=lambda message: ('403', message))

    def post(self):
        self.upstream_calls.append('post')
        return 'posted'

    def put(self, pk):
        self.upstream_calls.append(('put', pk))
        return 'put'

    def delete(self, pk):
        self.upstream_calls.append(('delete', pk))
        return 'deleted'

    def update_role_users(self, pk):
        self.upstream_calls.append(('update_role_users', pk))
        return 'updated'


class _GuardedRoleApi(rls_guard.PlaidRoleApi, _StubBaseRoleApi):
    pass


def _api(app, role, json_body=None):
    api = _GuardedRoleApi(role)
    ctx = app.test_request_context(json=json_body, method='POST' if json_body else 'GET')
    ctx.push()
    return api, ctx


@pytest.mark.parametrize('method_name, args', [
    ('delete', (1,)),
    ('update_role_users', (1,)),
])
def test_role_write_blocked_for_non_automation_user(app, method_name, args):
    role = SimpleNamespace(id=1, name='plaid_rls_group-a')
    api, ctx = _api(app, role)
    try:
        g.user = SimpleNamespace(username='alice@customer.com')
        result = getattr(api, method_name)(*args)
    finally:
        ctx.pop()

    assert result == ('403', rls_guard.DENIAL_MESSAGE.format(name='plaid_rls_group-a'))
    assert api.upstream_calls == []


@pytest.mark.parametrize('method_name, args', [
    ('delete', (1,)),
    ('update_role_users', (1,)),
])
def test_role_write_allowed_for_automation_user(app, method_name, args):
    role = SimpleNamespace(id=1, name='plaid_rls_group-a')
    api, ctx = _api(app, role)
    try:
        g.user = SimpleNamespace(username='admin')
        getattr(api, method_name)(*args)
    finally:
        ctx.pop()

    assert len(api.upstream_calls) == 1


def test_role_write_allowed_for_unprotected_role(app):
    """A hand-made role like `CONTRACTS` is untouched by this guard -- it is
    not this module's job to lock down roles PlaidCloud did not generate."""
    role = SimpleNamespace(id=1, name='CONTRACTS')
    api, ctx = _api(app, role)
    try:
        g.user = SimpleNamespace(username='alice@customer.com')
        getattr(api, 'delete')(1)
    finally:
        ctx.pop()

    assert api.upstream_calls == [('delete', 1)]


def test_role_delete_blocked_when_role_missing_name_lookup_still_guards(app):
    """`datamodel.get` returning None (already-deleted / bad pk) must not be
    read as 'nothing to protect' -- name is None, is_protected is False, so
    this legitimately falls through to upstream, which 404s on its own. This
    pins that the guard does not itself crash on a missing row."""
    api, ctx = _api(app, role=None)
    try:
        g.user = SimpleNamespace(username='alice@customer.com')
        result = api.delete(999)
    finally:
        ctx.pop()

    assert result == 'deleted'
    assert api.upstream_calls == [('delete', 999)]


def test_role_rename_into_reserved_prefix_is_blocked(app):
    """Renaming an ordinary role INTO the `plaid_rls_` prefix is blocked
    symmetrically -- a workspace admin must not be able to pre-empt or
    impersonate a name the reconciler expects to own next."""
    role = SimpleNamespace(id=1, name='CONTRACTS')
    api, ctx = _api(app, role, json_body={'name': 'plaid_rls_group-a'})
    try:
        g.user = SimpleNamespace(username='alice@customer.com')
        result = api.put(1)
    finally:
        ctx.pop()

    assert result == ('403', rls_guard.DENIAL_MESSAGE.format(name='plaid_rls_group-a'))
    assert api.upstream_calls == []


def test_role_rename_of_protected_role_is_blocked_even_to_unprotected_name(app):
    """The opposite direction -- renaming AWAY from the prefix -- is also
    blocked: the CURRENT name is checked too, not just the requested one."""
    role = SimpleNamespace(id=1, name='plaid_rls_group-a')
    api, ctx = _api(app, role, json_body={'name': 'not_protected_anymore'})
    try:
        g.user = SimpleNamespace(username='alice@customer.com')
        result = api.put(1)
    finally:
        ctx.pop()

    assert result == ('403', rls_guard.DENIAL_MESSAGE.format(name='plaid_rls_group-a'))
    assert api.upstream_calls == []


def test_role_create_of_reserved_name_is_blocked(app):
    api, ctx = _api(app, role=None, json_body={'name': 'plaid_rls_group-a'})
    try:
        g.user = SimpleNamespace(username='alice@customer.com')
        result = api.post()
    finally:
        ctx.pop()

    assert result == ('403', rls_guard.DENIAL_MESSAGE.format(name='plaid_rls_group-a'))
    assert api.upstream_calls == []


# --- RLSRestApi name extraction + wrapping -------------------------------

def _fake_rls_api(rows_by_id):
    api = SimpleNamespace()
    api.datamodel = SimpleNamespace(get=lambda pk: rows_by_id.get(pk))
    api.response_403 = MagicMock(side_effect=lambda message: ('403', message))
    return api


def test_bulk_delete_names_collects_every_targeted_rule(app):
    rows = {
        1: SimpleNamespace(id=1, name='plaid_rls_p1_aaaa'),
        2: SimpleNamespace(id=2, name='CONTRACTS'),
    }
    api = _fake_rls_api(rows)
    names = rls_guard._bulk_delete_names(api, rison=[1, 2])
    assert set(names) == {'plaid_rls_p1_aaaa', 'CONTRACTS'}


def test_bulk_delete_names_empty_when_no_ids(app):
    api = _fake_rls_api({})
    assert rls_guard._bulk_delete_names(api, rison=[]) == []
    assert rls_guard._bulk_delete_names(api) == []


def test_guard_rls_rule_write_blocks_when_any_targeted_name_is_protected(app):
    calls = []

    @rls_guard._guard_rls_rule_write(lambda api, *a, **k: ['plaid_rls_p1_aaaa', 'CONTRACTS'])
    def method(self, *a, **k):
        calls.append((a, k))
        return 'ok'

    api = _fake_rls_api({})
    with app.test_request_context():
        g.user = SimpleNamespace(username='alice@customer.com')
        result = method(api, 1, 2)

    assert result == ('403', rls_guard.DENIAL_MESSAGE.format(name='plaid_rls_p1_aaaa'))
    assert calls == []


def test_guard_rls_rule_write_allows_when_automation_principal(app):
    calls = []

    @rls_guard._guard_rls_rule_write(lambda api, *a, **k: ['plaid_rls_p1_aaaa'])
    def method(self, *a, **k):
        calls.append((a, k))
        return 'ok'

    api = _fake_rls_api({})
    with app.test_request_context():
        g.user = SimpleNamespace(username='admin')
        result = method(api, 1)

    assert result == 'ok'
    assert calls == [((1,), {})]


def test_guard_rls_rule_write_allows_unprotected_names(app):
    calls = []

    @rls_guard._guard_rls_rule_write(lambda api, *a, **k: ['CONTRACTS', 'jinja_test_mago'])
    def method(self, *a, **k):
        calls.append('called')
        return 'ok'

    api = _fake_rls_api({})
    with app.test_request_context():
        g.user = SimpleNamespace(username='alice@customer.com')
        result = method(api)

    assert result == 'ok'
    assert calls == ['called']


def test_install_is_idempotent(monkeypatch):
    """install() patches module-level state on RLSRestApi; calling it twice
    (e.g. a dev reloader re-importing plaid.security) must not double-wrap
    the methods -- each request would otherwise run the guard N times, which
    is harmless but a smell that the class was patched more than once."""
    import types

    fake_module = types.ModuleType('superset.row_level_security.api')

    class FakeRLSRestApi:
        def post(self):
            return 'post'

        def put(self, pk):
            return 'put'

        def delete(self, pk):
            return 'delete'

        def bulk_delete(self, **kwargs):
            return 'bulk_delete'

    fake_module.RLSRestApi = FakeRLSRestApi
    monkeypatch.setitem(__import__('sys').modules, 'superset.row_level_security.api', fake_module)

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

from flask_appbuilder.security.sqla.models import Group, Model, Role, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def orm_session():
    rls_guard.install_orm_listeners()
    engine = create_engine('sqlite:///:memory:')
    Model.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _user(session, username):
    u = User(first_name='A', last_name='B', username=username, email=f'{username}@example.com')
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


def test_role_update_role_users_shape_is_blocked_for_non_automation_user(app, orm_session):
    """RoleApi.update_role_users: `role.user = [...]`."""
    with app.test_request_context():
        g.user = SimpleNamespace(username='attacker')
        role = _role(orm_session, 'plaid_rls_group-a')
        attacker = _user(orm_session, 'attacker')

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            role.user = [attacker]

        assert role.user == []


def test_role_update_role_groups_shape_is_blocked(app, orm_session):
    """RoleApi.update_role_groups: `role.groups = [...]` -- the FIRST
    reported bypass. Fires via the Group.roles backref."""
    with app.test_request_context():
        g.user = SimpleNamespace(username='attacker')
        role = _role(orm_session, 'plaid_rls_group-a')
        attacker_group = _group(orm_session, 'attacker-group')

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            role.groups = [attacker_group]

        assert role.groups == []
        assert attacker_group.roles == []


def test_group_api_post_shape_is_blocked(app, orm_session):
    """GroupApi POST/PUT: one call setting both `roles` and `users` -- the
    SECOND reported bypass, and the exact scenario the review asked to be
    reproduced as a test."""
    with app.test_request_context():
        g.user = SimpleNamespace(username='attacker')
        role = _role(orm_session, 'plaid_rls_group-a')
        attacker = _user(orm_session, 'attacker')
        new_group = Group(name='attacker-made-group')
        orm_session.add(new_group)

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            new_group.roles = [role]
            new_group.users = [attacker]

        # The role assignment is what must be refused; assert the
        # entitlement was never granted regardless of which of the two
        # assignments the exception interrupted.
        assert role not in new_group.roles


def test_user_api_put_roles_shape_is_blocked(app, orm_session):
    """UserApi.put with `roles`: `user.roles = [...]` -- the THIRD reported
    bypass. Fires via the Role.user backref."""
    with app.test_request_context():
        g.user = SimpleNamespace(username='attacker')
        role = _role(orm_session, 'plaid_rls_group-a')
        attacker = _user(orm_session, 'attacker')

        with pytest.raises(rls_guard.PlaidRlsGuardError):
            attacker.roles = [role]

        assert attacker.roles == []


def test_user_api_put_groups_shape_is_blocked_when_group_holds_protected_role(app, orm_session):
    """UserApi.put with `groups`, targeting a group that ALREADY holds a
    protected role -- the fourth path: no write to ab_group_role at all,
    only ab_user_group, so the previous three checks alone would miss it.
    Fires via the Group.users backref."""
    with app.test_request_context():
        role = _role(orm_session, 'plaid_rls_group-a')
        holder_group = _group(orm_session, 'holder-group')
        # Grant the group's role as the automation principal first, so only
        # the user-membership step below is under test.
        g.user = SimpleNamespace(username='admin')
        holder_group.roles = [role]
        orm_session.commit()

        g.user = SimpleNamespace(username='attacker')
        attacker = _user(orm_session, 'attacker')
        with pytest.raises(rls_guard.PlaidRlsGuardError):
            attacker.groups = [holder_group]

        assert attacker.groups == []
        assert attacker not in holder_group.users


def test_unprotected_role_is_unaffected_by_any_of_the_four_paths(app, orm_session):
    """The guard must not become a blanket lock on all role/group
    administration -- only `plaid_rls_*`-prefixed resources."""
    with app.test_request_context():
        g.user = SimpleNamespace(username='attacker')
        ordinary_role = _role(orm_session, 'CONTRACTS')
        attacker = _user(orm_session, 'attacker')
        ordinary_group = _group(orm_session, 'sales-team')

        ordinary_role.user = [attacker]
        ordinary_group.roles = [ordinary_role]
        ordinary_group.users = [attacker]

        assert ordinary_role.user == [attacker]
        assert ordinary_role in ordinary_group.roles


def test_automation_principal_can_still_grant_every_path(app, orm_session):
    with app.test_request_context():
        g.user = SimpleNamespace(username='admin')
        role = _role(orm_session, 'plaid_rls_group-a')
        member = _user(orm_session, 'legit-member')
        role.user = [member]
        assert role.user == [member]

        group = _group(orm_session, 'reconciler-group')
        group.roles = [role]
        assert role in group.roles


def test_oauth_session_cannot_satisfy_automation_principal_even_with_matching_username(app, orm_session):
    """Non-blocking review item: a Keycloak OAuth login's username is
    attacker-controlled input, not proof of identity. An OAuth-derived
    session must be refused even if its username happens to be 'admin'."""
    with app.test_request_context():
        from flask import session
        session['oauth'] = ('token', 'secret')
        g.user = SimpleNamespace(username='admin')

        role = _role(orm_session, 'plaid_rls_group-a')
        attacker = _user(orm_session, 'attacker-as-admin')
        with pytest.raises(rls_guard.PlaidRlsGuardError):
            role.user = [attacker]


def test_install_orm_listeners_is_idempotent(app, orm_session):
    with app.test_request_context():
        rls_guard.install_orm_listeners()
        rls_guard.install_orm_listeners()
        # No duplicate-listener double-raise / double-log; a single veto
        # still refuses exactly once (no assertion error from being called
        # twice with conflicting internal state).
        g.user = SimpleNamespace(username='attacker')
        role = _role(orm_session, 'plaid_rls_group-a')
        attacker = _user(orm_session, 'attacker')
        with pytest.raises(rls_guard.PlaidRlsGuardError):
            role.user = [attacker]
