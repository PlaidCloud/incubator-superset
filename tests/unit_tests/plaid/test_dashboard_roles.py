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
from pytest_mock import MockerFixture

pytest.importorskip("plaidcloud.rpc")

from plaid.security import PlaidSecurityManager  # noqa: E402
from superset.commands.dashboard.create import CreateDashboardCommand  # noqa: E402
from superset.commands.dashboard.exceptions import (  # noqa: E402
    DashboardForbiddenError,
)
from superset.commands.dashboard.update import UpdateDashboardCommand  # noqa: E402
from superset.security import SupersetSecurityManager  # noqa: E402


def manager(
    mocker: MockerFixture, *, rbac=True, admin=False, automation=False
) -> PlaidSecurityManager:
    sm = PlaidSecurityManager.__new__(PlaidSecurityManager)
    mocker.patch("superset.is_feature_enabled", return_value=rbac)
    mocker.patch.object(sm, "is_admin", return_value=admin)
    mocker.patch("plaid.rls_guard.is_automation_principal", return_value=automation)
    return sm


@pytest.mark.parametrize(
    ("kwargs", "current", "requested", "allowed"),
    [
        ({}, [1], [2], False),
        ({}, [1], [], False),
        ({}, [], [3], False),
        ({}, [1, 2], [2, 1], True),
        ({}, [], [], True),
        ({"admin": True}, [1], [2], True),
        ({"automation": True}, [1], [2], True),
        ({"rbac": False}, [1], [2], True),
    ],
)
def test_can_set_dashboard_roles(mocker, kwargs, current, requested, allowed):
    sm = manager(mocker, **kwargs)

    assert sm.can_set_dashboard_roles(current, requested) is allowed


def test_stock_superset_allows_any_roles():
    sm = SupersetSecurityManager.__new__(SupersetSecurityManager)

    assert sm.can_set_dashboard_roles([1], [2]) is True


def update_command(mocker: MockerFixture, sm, data):
    mocker.patch("superset.commands.dashboard.update.security_manager", sm)
    model = SimpleNamespace(id=5, owners=[], tags=[], roles=[SimpleNamespace(id=1)])
    mocker.patch(
        "superset.commands.dashboard.update.DashboardDAO.find_by_id",
        return_value=model,
    )
    mocker.patch(
        "superset.commands.dashboard.update.DashboardDAO."
        "validate_update_slug_uniqueness",
        return_value=True,
    )
    mocker.patch("superset.commands.dashboard.update.validate_tags")
    mocker.patch(
        "superset.commands.dashboard.update.populate_roles",
        side_effect=lambda ids: [f"role-{i}" for i in ids or []],
    )
    mocker.patch.object(UpdateDashboardCommand, "compute_owners", return_value=[])
    mocker.patch.object(sm, "raise_for_ownership")
    return UpdateDashboardCommand(5, data)


def test_owner_put_with_changed_roles_is_forbidden(mocker):
    sm = manager(mocker)
    command = update_command(mocker, sm, {"roles": [2], "dashboard_title": "t"})

    with pytest.raises(DashboardForbiddenError) as ex:
        command.validate()

    assert ex.value.status == 403
    assert str(ex.value.message) == "Dashboard audience is managed in PlaidCloud"


def test_owner_put_with_unchanged_roles_and_title_is_applied(mocker):
    sm = manager(mocker)
    command = update_command(mocker, sm, {"roles": [1], "dashboard_title": "new"})

    command.validate()

    assert command._properties["dashboard_title"] == "new"
    assert command._properties["roles"] == ["role-1"]


def test_owner_put_without_roles_is_applied(mocker):
    sm = manager(mocker)
    command = update_command(mocker, sm, {"dashboard_title": "new"})

    command.validate()

    assert command._properties["roles"] == ["role-1"]


@pytest.mark.parametrize("kwargs", [{"admin": True}, {"automation": True}])
def test_admin_and_automation_put_applies_roles(mocker, kwargs):
    sm = manager(mocker, **kwargs)
    command = update_command(mocker, sm, {"roles": [2]})

    command.validate()

    assert command._properties["roles"] == ["role-2"]


def test_stock_superset_put_applies_roles(mocker):
    sm = SupersetSecurityManager.__new__(SupersetSecurityManager)
    command = update_command(mocker, sm, {"roles": [2]})

    command.validate()

    assert command._properties["roles"] == ["role-2"]


def create_command(mocker: MockerFixture, sm, data):
    mocker.patch("superset.commands.dashboard.create.security_manager", sm)
    mocker.patch(
        "superset.commands.dashboard.create.DashboardDAO.validate_slug_uniqueness",
        return_value=True,
    )
    mocker.patch.object(CreateDashboardCommand, "populate_owners", return_value=[])
    mocker.patch(
        "superset.commands.dashboard.create.populate_roles",
        side_effect=lambda ids: [f"role-{i}" for i in ids or []],
    )
    return CreateDashboardCommand(data)


def test_owner_post_with_roles_is_forbidden(mocker):
    command = create_command(mocker, manager(mocker), {"roles": [2]})

    with pytest.raises(DashboardForbiddenError):
        command.validate()


def test_owner_post_without_roles_is_applied(mocker):
    command = create_command(mocker, manager(mocker), {"dashboard_title": "t"})

    command.validate()


def test_automation_post_applies_roles(mocker):
    command = create_command(mocker, manager(mocker, automation=True), {"roles": [2]})

    command.validate()

    assert command._properties["roles"] == ["role-2"]
