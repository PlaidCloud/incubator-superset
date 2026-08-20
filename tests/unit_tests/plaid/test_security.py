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

import uuid
from types import SimpleNamespace
from unittest.mock import patch

import flask
import pytest
from flask_appbuilder.security.sqla.models import User
from sqlalchemy.orm.exc import MultipleResultsFound

# plaid/ imports plaidcloud-rpc, which is in requirements/base.txt but not in the
# development.txt that CI installs, so this module is only importable where the
# runtime dependencies are present (the superset image). Skipping loudly beats a
# collection error that aborts the whole unit-test run.
pytest.importorskip("plaidcloud.rpc.connection.jsonrpc")

from plaid.security import PlaidSecurityManager, PROJECT_ACCESS  # noqa: E402
from superset.security import SupersetSecurityManager  # noqa: E402


class FakeQuery:
    """Stand-in for a SQLAlchemy Query, recording the criteria it is filtered on."""

    def __init__(self, rows, criteria):
        self.rows = rows
        self.criteria = criteria

    def filter(self, criterion):
        self.criteria.append(criterion)
        return self

    def order_by(self, *args):
        return FakeQuery(sorted(self.rows, key=lambda row: row.id), self.criteria)

    def all(self):
        return list(self.rows)

    def one_or_none(self):
        if len(self.rows) > 1:
            raise MultipleResultsFound(
                f"Multiple rows were found for one_or_none(): {len(self.rows)}"
            )
        return self.rows[0] if self.rows else None


class StubSecurityManager(PlaidSecurityManager):
    # Plain class attributes shadow the properties the real manager reads off
    # the Flask app, so no app or appbuilder is needed.
    user_model = User
    auth_username_ci = True
    session = None


def make_manager(rows, auth_username_ci=True):
    manager = StubSecurityManager.__new__(StubSecurityManager)
    manager.criteria = []
    manager.session = SimpleNamespace(
        query=lambda model: FakeQuery(rows, manager.criteria)
    )
    manager.auth_username_ci = auth_username_ci
    return manager


def user(user_id, name, active=True):
    return SimpleNamespace(id=user_id, username=name, email=name, active=active)


def compiled(criterion):
    return str(criterion.compile(compile_kwargs={"literal_binds": True}))


@pytest.mark.parametrize(
    ("field", "auth_username_ci", "expected"),
    [
        ("email", True, "lower(ab_user.email) = lower('Bob@Example.com')"),
        ("email", False, "lower(ab_user.email) = lower('Bob@Example.com')"),
        ("username", True, "lower(ab_user.username) = lower('Bob@Example.com')"),
        ("username", False, "ab_user.username = 'Bob@Example.com'"),
    ],
)
def test_find_user_filters_on_expected_column(field, auth_username_ci, expected):
    manager = make_manager([], auth_username_ci=auth_username_ci)

    manager.find_user(**{field: "Bob@Example.com"})

    assert [compiled(criterion) for criterion in manager.criteria] == [expected]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_prefers_exact_case_match(field):
    rows = [user(7, "Bob@Example.com"), user(3, "bob@example.com")]
    manager = make_manager(rows)

    found = manager.find_user(**{field: "Bob@Example.com"})

    assert found is rows[0]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_falls_back_to_lowest_id(field):
    rows = [user(7, "BOB@example.com"), user(3, "bob@example.com")]
    manager = make_manager(rows)

    found = manager.find_user(**{field: "Bob@Example.com"})

    assert found is rows[1]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_lowest_id_wins_among_several_duplicates(field):
    rows = [
        user(9, "BOB@example.com"),
        user(5, "bob@EXAMPLE.com"),
        user(4, "bob@example.com"),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[2]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_exact_match_beats_lower_ids(field):
    rows = [
        user(2, "BOB@example.com"),
        user(4, "bob@example.com"),
        user(9, "Bob@Example.com"),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[2]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_skips_inactive_lowest_id(field):
    rows = [
        user(3, "bob@example.com", active=False),
        user(7, "BOB@example.com"),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[1]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_active_beats_inactive_exact_case_match(field):
    rows = [
        user(3, "Bob@Example.com", active=False),
        user(7, "bob@example.com"),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[1]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_exact_case_wins_among_active_rows(field):
    rows = [
        user(2, "bob@example.com", active=False),
        user(4, "BOB@example.com"),
        user(9, "Bob@Example.com"),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[2]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_returns_inactive_exact_case_match_when_all_inactive(field):
    rows = [
        user(3, "bob@example.com", active=False),
        user(7, "Bob@Example.com", active=False),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[1]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_returns_inactive_lowest_id_when_all_inactive(field):
    rows = [
        user(7, "BOB@example.com", active=False),
        user(3, "bob@example.com", active=False),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[1]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_single_inactive_match(field):
    rows = [user(3, "bob@example.com", active=False)]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "BOB@EXAMPLE.COM"}) is rows[0]


# FakeQuery.order_by sorts by id like the real ORDER BY does, which would let a
# resolver that only relied on a stable sort look correct. Feeding the resolver
# rows in another order pins its own id tie-break.
@pytest.mark.parametrize("field", ["email", "username"])
def test_resolve_single_user_lowest_id_wins_on_unordered_rows(field):
    rows = [user(9, "BOB@example.com"), user(3, "bob@EXAMPLE.com")]
    unordered = SimpleNamespace(
        order_by=lambda *args: SimpleNamespace(all=lambda: list(rows))
    )
    manager = make_manager(rows)

    found = manager._resolve_single_user(unordered, field, "Bob@Example.com")

    assert found is rows[1]


# active is Optional[bool] with a Python-side default, so a row written by raw
# SQL can hold NULL. auth_user_oauth rejects those too, so de-preferring them
# keeps this resolution in lockstep with the login gate.
@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_prefers_active_over_null_active(field):
    rows = [
        user(3, "bob@example.com", active=None),
        user(7, "BOB@example.com"),
    ]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "Bob@Example.com"}) is rows[1]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_single_null_active_match(field):
    rows = [user(3, "bob@example.com", active=None)]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "BOB@EXAMPLE.COM"}) is rows[0]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_single_match(field):
    rows = [user(3, "bob@example.com")]
    manager = make_manager(rows)

    assert manager.find_user(**{field: "BOB@EXAMPLE.COM"}) is rows[0]


@pytest.mark.parametrize("field", ["email", "username"])
def test_find_user_no_match(field):
    manager = make_manager([])

    assert manager.find_user(**{field: "nobody@example.com"}) is None


def test_find_user_case_sensitive_username_lookup():
    rows = [user(3, "bob")]
    manager = make_manager(rows, auth_username_ci=False)

    assert manager.find_user(username="bob") is rows[0]


# The case-sensitive branch still resolves duplicates: on a database with a
# case-insensitive collation an equality filter matches case variants anyway.
def test_find_user_case_sensitive_username_prefers_exact_case_match():
    rows = [user(7, "Bob"), user(3, "bob")]
    manager = make_manager(rows, auth_username_ci=False)

    assert manager.find_user(username="Bob") is rows[0]


def test_find_user_case_sensitive_username_falls_back_to_lowest_id():
    rows = [user(7, "BOB"), user(3, "bob")]
    manager = make_manager(rows, auth_username_ci=False)

    assert manager.find_user(username="Bob") is rows[1]


def test_find_user_logs_duplicate_ids(caplog):
    rows = [user(7, "BOB@example.com"), user(3, "bob@example.com")]
    manager = make_manager(rows)

    manager.find_user(email="bob@example.com")

    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert "[3, 7]" in warnings[0].getMessage()


def pvm(permission_name, view_menu_name):
    return SimpleNamespace(
        permission=SimpleNamespace(name=permission_name),
        view_menu=SimpleNamespace(name=view_menu_name),
    )


REGISTRATION_PERMISSIONS = ["can_list", "can_show", "can_add", "can_edit", "can_delete"]


@pytest.mark.parametrize("permission_name", REGISTRATION_PERMISSIONS)
def test_user_registrations_api_is_admin_only(permission_name):
    manager = PlaidSecurityManager.__new__(PlaidSecurityManager)
    permission_view = pvm(permission_name, "UserRegistrationsRestAPI")

    assert manager._is_admin_only(permission_view)
    assert not manager._is_alpha_pvm(permission_view)
    assert not manager._is_gamma_pvm(permission_view)


@pytest.mark.parametrize("permission_name", REGISTRATION_PERMISSIONS)
def test_upstream_grants_user_registrations_api_to_alpha_and_gamma(permission_name):
    """Pins the upstream gap the override exists to close."""
    manager = SupersetSecurityManager.__new__(SupersetSecurityManager)
    permission_view = pvm(permission_name, "UserRegistrationsRestAPI")

    assert manager._is_alpha_pvm(permission_view)
    assert manager._is_gamma_pvm(permission_view)


class TestProjectAccessResolution:
    """Project access must resolve without a Flask session.

    PlaidCloud is authoritative for which databases a user may see, and the
    answer used to live only in the Flask session, populated at login. Any
    caller without a session -- an MCP tool call, a background task -- either
    crashed on the session proxy or silently saw no projects at all.
    """

    @staticmethod
    def _manager() -> PlaidSecurityManager:
        return PlaidSecurityManager.__new__(PlaidSecurityManager)

    def test_session_answer_wins_when_a_request_is_active(self, app) -> None:
        """A browser request keeps using the value cached at login."""
        sm = self._manager()
        with app.test_request_context():
            flask.session[PROJECT_ACCESS] = ["11111111-1111-1111-1111-111111111111"]
            with patch.object(sm, "_fetch_project_access_ids") as fetch:
                assert sm._project_access_ids() == [
                    "11111111-1111-1111-1111-111111111111"
                ]
            fetch.assert_not_called()

    def test_falls_back_to_rpc_without_a_session(self, app) -> None:
        """An app context alone resolves via PlaidCloud instead of raising."""
        sm = self._manager()
        with app.app_context():
            with patch.object(
                sm, "_fetch_project_access_ids", return_value=["abc"]
            ) as fetch:
                assert sm._project_access_ids() == ["abc"]
                fetch.assert_called_once()

    def test_rpc_answer_is_memoised_for_the_call(self, app) -> None:
        """Access checks run per object, so the RPC must not run per check."""
        sm = self._manager()
        with app.app_context():
            with patch.object(
                sm, "_fetch_project_access_ids", return_value=["abc"]
            ) as fetch:
                sm._project_access_ids()
                sm._project_access_ids()
                sm._project_access_ids()
                assert fetch.call_count == 1

    def test_unresolvable_access_fails_closed(self, app) -> None:
        """No answer must not read as "allowed" for a non-admin."""
        sm = self._manager()
        with app.app_context():
            with (
                patch.object(sm, "_fetch_project_access_ids", return_value=None),
                patch.object(sm, "is_admin", return_value=False),
            ):
                assert sm._can_access_project(str(uuid.uuid4())) is False

    def test_unresolvable_access_still_allows_admin(self, app) -> None:
        """Preserves the previous behaviour when the answer is unknown."""
        sm = self._manager()
        with app.app_context():
            with (
                patch.object(sm, "_fetch_project_access_ids", return_value=None),
                patch.object(sm, "is_admin", return_value=True),
            ):
                assert sm._can_access_project(str(uuid.uuid4())) is True

    def test_mcp_token_used_when_there_is_no_session(self, app) -> None:
        """The MCP request's upstream Keycloak token is a valid credential."""
        sm = self._manager()
        with app.app_context():
            with patch.object(
                PlaidSecurityManager, "_mcp_access_token", return_value="mcp-token"
            ):
                assert sm._rpc_token() == "mcp-token"
