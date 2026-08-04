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

from plaid.security import PlaidSecurityManager


class FakeQuery:
    """Stand-in for a SQLAlchemy Query over case-insensitively matched rows."""

    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args):
        return FakeQuery(sorted(self.rows, key=lambda row: row.id))

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
    manager.session = SimpleNamespace(query=lambda model: FakeQuery(rows))
    manager.auth_username_ci = auth_username_ci
    return manager


def user(user_id, name):
    return SimpleNamespace(id=user_id, username=name, email=name)


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


def test_find_user_logs_duplicate_ids(caplog):
    rows = [user(7, "BOB@example.com"), user(3, "bob@example.com")]
    manager = make_manager(rows)

    manager.find_user(email="bob@example.com")

    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert "[3, 7]" in warnings[0].getMessage()
