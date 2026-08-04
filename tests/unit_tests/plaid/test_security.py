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

from types import SimpleNamespace

import pytest
from flask_appbuilder.security.sqla.models import User
from sqlalchemy.orm.exc import MultipleResultsFound

# plaid/ imports plaidcloud-rpc, which is in requirements/base.txt but not in the
# development.txt that CI installs, so this module is only importable where the
# runtime dependencies are present (the superset image). Skipping loudly beats a
# collection error that aborts the whole unit-test run.
pytest.importorskip("plaidcloud.rpc.connection.jsonrpc")

from plaid.security import PlaidSecurityManager  # noqa: E402


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


def user(user_id, name):
    return SimpleNamespace(id=user_id, username=name, email=name)


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
