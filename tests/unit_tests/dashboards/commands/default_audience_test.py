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
from typing import Any

import pytest
from pytest_mock import MockerFixture

from superset.commands.dashboard.create import CreateDashboardCommand
from superset.commands.dashboard.exceptions import DashboardDefaultAudienceError
from superset.commands.dashboard.update import UpdateDashboardCommand

APPLIED = {"state": "groups", "published": True, "group_names": ["Finance Leads"]}


def _update(mocker: MockerFixture, data: dict[str, Any], published: bool):
    model = SimpleNamespace(id=1, published=published, roles=[], owners=[], tags=[])
    mocker.patch(
        "superset.commands.dashboard.update.DashboardDAO.find_by_id",
        return_value=model,
    )
    mocker.patch(
        "superset.commands.dashboard.update.DashboardDAO.validate_update_slug_uniqueness",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.dashboard.update.security_manager.raise_for_ownership"
    )
    mocker.patch("superset.commands.dashboard.update.validate_tags")
    mocker.patch("superset.commands.dashboard.update.populate_roles", return_value=[])
    mocker.patch.object(UpdateDashboardCommand, "compute_owners", return_value=[])
    return UpdateDashboardCommand(1, data), model


def test_update_applies_default_on_unpublished_to_published(mocker: MockerFixture):
    hook = mocker.patch(
        "superset.commands.dashboard.update.security_manager"
        ".apply_default_dashboard_audience",
        return_value=APPLIED,
    )
    command, model = _update(mocker, {"published": True}, published=False)

    command.validate()

    hook.assert_called_once_with(command._properties, model)
    assert command.default_audience == APPLIED


@pytest.mark.parametrize(
    ("data", "published"),
    [({"published": True}, True), ({"published": False}, True), ({}, False)],
)
def test_update_skips_default_unless_first_publish(
    mocker: MockerFixture, data: dict[str, Any], published: bool
):
    hook = mocker.patch(
        "superset.commands.dashboard.update.security_manager"
        ".apply_default_dashboard_audience"
    )
    command, _ = _update(mocker, data, published=published)

    command.validate()

    hook.assert_not_called()
    assert command.default_audience is None


def test_update_refused_when_default_cannot_be_applied(mocker: MockerFixture):
    mocker.patch(
        "superset.commands.dashboard.update.security_manager"
        ".apply_default_dashboard_audience",
        side_effect=DashboardDefaultAudienceError(),
    )
    command, _ = _update(mocker, {"published": True}, published=False)

    with pytest.raises(DashboardDefaultAudienceError):
        command.validate()


def test_create_never_applies_default(mocker: MockerFixture):
    # A new dashboard has no charts, so there is no project to ask. The plaid
    # sweep applies the default once a published, role-less dashboard gains
    # datasources.
    hook = mocker.patch("superset.security_manager.apply_default_dashboard_audience")
    mocker.patch(
        "superset.commands.dashboard.create.DashboardDAO.validate_slug_uniqueness",
        return_value=True,
    )
    mocker.patch.object(CreateDashboardCommand, "populate_owners", return_value=[])
    mocker.patch("superset.commands.dashboard.create.populate_roles", return_value=[])
    command = CreateDashboardCommand({"published": True})

    command.validate()

    hook.assert_not_called()
    assert command._properties["published"] is True
