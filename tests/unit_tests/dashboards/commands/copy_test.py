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

from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from superset.commands.dashboard.exceptions import DashboardForbiddenError

DATA = {"dashboard_title": "Copy", "json_metadata": "{}"}


def _dashboard(roles: list[object]) -> MagicMock:
    dash = MagicMock()
    dash.roles = roles
    dash.slices = []
    return dash


@pytest.mark.parametrize(
    "roles, is_owner, allowed",
    [
        ([], False, True),
        (["Gamma"], False, False),
        (["Gamma"], True, True),
        ([], True, True),
    ],
)
def test_copy_command_validate_rbac(
    mocker: MockerFixture, roles: list[object], is_owner: bool, allowed: bool
) -> None:
    from superset.commands.dashboard.copy import CopyDashboardCommand

    mocker.patch(
        "superset.commands.dashboard.copy.is_feature_enabled", return_value=True
    )
    mocker.patch(
        "superset.commands.dashboard.copy.security_manager.is_owner",
        return_value=is_owner,
    )
    command = CopyDashboardCommand(_dashboard(roles), DATA)

    if allowed:
        command.validate()
    else:
        with pytest.raises(DashboardForbiddenError):
            command.validate()


@pytest.mark.parametrize(
    "roles, is_owner, allowed",
    [
        ([], False, True),
        (["Gamma"], False, False),
        (["Gamma"], True, True),
        ([], True, True),
    ],
)
def test_copy_dao_rbac(
    mocker: MockerFixture, roles: list[object], is_owner: bool, allowed: bool
) -> None:
    from superset.daos.dashboard import DashboardDAO

    mocker.patch("superset.daos.dashboard.is_feature_enabled", return_value=True)
    mocker.patch(
        "superset.daos.dashboard.security_manager.is_owner", return_value=is_owner
    )
    mocker.patch("superset.daos.dashboard.db")
    mocker.patch("superset.daos.dashboard.g", user=None)
    mocker.patch("superset.daos.dashboard.Dashboard")
    mocker.patch.object(DashboardDAO, "set_dash_metadata")

    if allowed:
        DashboardDAO.copy_dashboard(_dashboard(roles), DATA)
    else:
        with pytest.raises(DashboardForbiddenError):
            DashboardDAO.copy_dashboard(_dashboard(roles), DATA)
