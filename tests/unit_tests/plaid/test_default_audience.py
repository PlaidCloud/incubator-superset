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
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from plaid.security import _has_explicit_audience, PlaidSecurityManager
from superset.commands.dashboard.exceptions import DashboardDefaultAudienceError
from superset.security import SupersetSecurityManager

FINANCE = {
    "state": "groups",
    "published": True,
    "group_ids": ["fin"],
    "group_names": ["Finance Leads"],
    "roles": [{"id": 7, "name": "plaid_rls_fin"}],
}
OWNERS = {
    "state": "owners",
    "published": False,
    "group_ids": [],
    "group_names": [],
    "roles": [{"id": 9, "name": "plaid_dashboard_owners_only"}],
}
EVERYONE = {
    "state": "everyone",
    "published": True,
    "group_ids": [],
    "group_names": [],
    "roles": [],
}


class Manager(PlaidSecurityManager):
    def _rpc_token(self):
        return "tok"


class NoTokenManager(Manager):
    def _rpc_token(self):
        return None


def dashboard(roles=(), db_uuids=("db-1",), published=False):
    return SimpleNamespace(
        uuid="d-1",
        roles=list(roles),
        published=published,
        datasources=[
            SimpleNamespace(database=SimpleNamespace(uuid=u)) for u in db_uuids
        ],
    )


@pytest.fixture
def env():
    """RBAC on, regular caller, no explicit choice, roles resolve to their ids."""
    with (
        patch("superset.is_feature_enabled", return_value=True),
        patch("plaid.security.rls_guard.is_automation_principal", return_value=False),
        patch("plaid.security._has_explicit_audience", return_value=False),
        patch(
            "superset.commands.utils.populate_roles",
            side_effect=lambda ids: [
                SimpleNamespace(id=i, name=f"role-{i}") for i in ids or []
            ],
        ),
        patch("plaid.security.call_plaid_rpc") as rpc,
    ):
        yield rpc


def test_first_publish_applies_the_project_default(env):
    env.return_value = FINANCE
    properties = {"published": True, "roles": []}

    applied = Manager.__new__(Manager).apply_default_dashboard_audience(
        properties, dashboard()
    )

    assert [role.id for role in properties.pop("roles")] == [7]
    assert properties == {"published": True}
    assert applied == {
        "state": "groups",
        "published": True,
        "group_names": ["Finance Leads"],
        "roles": [{"id": 7, "name": "role-7"}],
    }
    env.assert_called_once_with(
        "dashboard/dashboard/default_audience", {"database_uuids": ["db-1"]}, "tok"
    )


def test_owners_default_publishes_as_draft_with_the_sentinel(env):
    env.return_value = OWNERS
    properties = {"published": True, "roles": []}

    Manager.__new__(Manager).apply_default_dashboard_audience(properties, dashboard())

    assert properties["published"] is False
    assert [role.id for role in properties["roles"]] == [9]


def test_everyone_default_leaves_the_dashboard_published_without_roles(env):
    env.return_value = EVERYONE
    properties = {"published": True, "roles": []}

    Manager.__new__(Manager).apply_default_dashboard_audience(properties, dashboard())

    assert properties == {"published": True, "roles": []}


def test_rpc_sends_every_distinct_database_uuid(env):
    env.return_value = EVERYONE

    Manager.__new__(Manager).apply_default_dashboard_audience(
        {"published": True, "roles": []}, dashboard(db_uuids=("b", "a", "b"))
    )

    assert env.call_args.args[1] == {"database_uuids": ["a", "b"]}


def test_rpc_failure_refuses_the_publish(env):
    env.side_effect = RuntimeError("plaid down")
    properties = {"published": True, "roles": []}

    with pytest.raises(DashboardDefaultAudienceError) as excinfo:
        Manager.__new__(Manager).apply_default_dashboard_audience(
            properties, dashboard()
        )

    assert str(excinfo.value) == (
        "Couldn't apply this project's default audience — try again"
    )
    assert properties == {"published": True, "roles": []}


def test_unknown_role_id_refuses_the_publish(env):
    env.return_value = FINANCE
    with patch(
        "superset.commands.utils.populate_roles", side_effect=ValueError("no role")
    ):
        with pytest.raises(DashboardDefaultAudienceError):
            Manager.__new__(Manager).apply_default_dashboard_audience(
                {"published": True, "roles": []}, dashboard()
            )


def test_missing_credential_refuses_the_publish(env):
    with pytest.raises(DashboardDefaultAudienceError):
        NoTokenManager.__new__(NoTokenManager).apply_default_dashboard_audience(
            {"published": True, "roles": []}, dashboard()
        )
    env.assert_not_called()


def test_explicit_choice_survives_the_default(env):
    with patch("plaid.security._has_explicit_audience", return_value=True):
        properties = {"published": True, "roles": []}
        applied = Manager.__new__(Manager).apply_default_dashboard_audience(
            properties, dashboard()
        )

    assert applied is None
    assert properties == {"published": True, "roles": []}
    env.assert_not_called()


def test_automation_principal_skips_the_hook(env):
    with patch("plaid.security.rls_guard.is_automation_principal", return_value=True):
        applied = Manager.__new__(Manager).apply_default_dashboard_audience(
            {"published": True, "roles": []}, dashboard()
        )

    assert applied is None
    env.assert_not_called()


def test_explicit_empty_roles_on_a_draft_with_roles_get_the_default(env):
    env.return_value = FINANCE
    properties = {"published": True, "roles": []}

    applied = Manager.__new__(Manager).apply_default_dashboard_audience(
        properties, dashboard(roles=["plaid_rls_old"])
    )

    assert applied is not None
    assert [role.id for role in properties["roles"]] == [7]


def test_existing_roles_are_kept(env):
    properties = {"published": True, "roles": ["role-3"]}

    applied = Manager.__new__(Manager).apply_default_dashboard_audience(
        properties, dashboard()
    )

    assert applied is None
    assert properties["roles"] == ["role-3"]
    env.assert_not_called()


def test_chartless_publish_is_allowed_and_left_to_the_plaid_sweep(env):
    applied = Manager.__new__(Manager).apply_default_dashboard_audience(
        {"published": True, "roles": []}, dashboard(db_uuids=())
    )

    assert applied is None
    env.assert_not_called()


def test_stock_rbac_off_changes_nothing(env):
    with patch("superset.is_feature_enabled", return_value=False):
        properties = {"published": True, "roles": []}
        applied = Manager.__new__(Manager).apply_default_dashboard_audience(
            properties, dashboard()
        )

    assert applied is None
    env.assert_not_called()


def test_stock_security_manager_hooks_are_no_ops():
    manager = SupersetSecurityManager.__new__(SupersetSecurityManager)
    properties = {"published": True, "roles": []}
    config = {"published": True}

    assert manager.apply_default_dashboard_audience(properties, dashboard()) is None
    manager.restrict_imported_dashboard(config, None)

    assert properties == {"published": True, "roles": []}
    assert config == {"published": True}


@pytest.mark.parametrize(
    ("existing", "expected"),
    [
        (None, False),
        (dashboard(published=False), False),
        (dashboard(published=True), True),
    ],
)
def test_import_lands_unpublished(env, existing, expected):
    config = {"published": True}

    Manager.__new__(Manager).restrict_imported_dashboard(config, existing)

    assert config == {"published": expected}


def test_import_by_the_automation_principal_is_untouched(env):
    with patch("plaid.security.rls_guard.is_automation_principal", return_value=True):
        config = {"published": True}
        Manager.__new__(Manager).restrict_imported_dashboard(config, None)

    assert config == {"published": True}


def test_explicit_choice_is_read_from_plaid_table():
    session = Session(sa.create_engine("sqlite://"))
    assert _has_explicit_audience(session, "d-1") is False  # table missing

    session.execute(
        sa.text(
            "CREATE TABLE dashboard_audience_explicit "
            "(dashboard_uuid TEXT, set_by TEXT, set_at TEXT)"
        )
    )
    assert _has_explicit_audience(session, "d-1") is False

    session.execute(
        sa.text("INSERT INTO dashboard_audience_explicit VALUES ('d-1', 'u', 'now')")
    )
    assert _has_explicit_audience(session, "d-1") is True
    assert _has_explicit_audience(session, "d-2") is False

    session.execute(
        sa.text(
            "INSERT INTO dashboard_audience_explicit "
            "VALUES ('d-3', 'plaid:default', 'now')"
        )
    )
    assert _has_explicit_audience(session, "d-3") is False


def test_plaid_default_row_does_not_block_a_republish(env):
    session = Session(sa.create_engine("sqlite://"))
    session.execute(
        sa.text(
            "CREATE TABLE dashboard_audience_explicit "
            "(dashboard_uuid TEXT, set_by TEXT, set_at TEXT)"
        )
    )
    session.execute(
        sa.text(
            "INSERT INTO dashboard_audience_explicit "
            "VALUES ('d-1', 'plaid:default', 'now')"
        )
    )
    env.return_value = FINANCE
    properties = {"published": True, "roles": []}

    with (
        patch("plaid.security._has_explicit_audience", new=_has_explicit_audience),
        patch("superset.db", SimpleNamespace(session=session)),
    ):
        applied = Manager.__new__(Manager).apply_default_dashboard_audience(
            properties, dashboard()
        )

    assert applied is not None
    assert [role.id for role in properties["roles"]] == [7]
