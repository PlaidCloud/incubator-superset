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

from superset.daos.dashboard import DashboardDAO
from superset.models.dashboard import Dashboard


def _dashboard() -> SimpleNamespace:
    mine = SimpleNamespace(id=1, data_for_slices=lambda slices: {"id": 1, "sql": "a"})
    other = SimpleNamespace(id=2, data_for_slices=lambda slices: {"id": 2, "sql": "b"})
    return SimpleNamespace(
        slices=[
            SimpleNamespace(id=10, datasource_id=1, datasource=mine),
            SimpleNamespace(id=20, datasource_id=2, datasource=other),
        ]
    )


@pytest.fixture
def sm(mocker: MockerFixture) -> SimpleNamespace:
    manager = SimpleNamespace(
        is_admin=lambda: False,
        can_access_datasource=lambda ds: ds.id == 1,
        can_drill_dataset_via_dashboard_access=lambda ds, dash: False,
    )
    mocker.patch("superset.models.dashboard.security_manager", manager)
    mocker.patch("superset.daos.dashboard.security_manager", manager)
    return manager


def test_datasets_drop_inaccessible_datasource(sm: SimpleNamespace) -> None:
    result = Dashboard.datasets_trimmed_for_slices(_dashboard())
    assert result == [{"id": 1, "sql": "a"}]


def test_datasets_keep_via_dashboard_grant(sm: SimpleNamespace) -> None:
    sm.can_access_datasource = lambda ds: False
    sm.can_drill_dataset_via_dashboard_access = lambda ds, dash: ds.id == 2
    result = Dashboard.datasets_trimmed_for_slices(_dashboard())
    assert result == [{"id": 2, "sql": "b"}]


def test_datasets_admin_sees_all(sm: SimpleNamespace) -> None:
    sm.is_admin = lambda: True
    sm.can_access_datasource = lambda ds: False
    result = Dashboard.datasets_trimmed_for_slices(_dashboard())
    assert [d["id"] for d in result] == [1, 2]


def test_charts_drop_inaccessible_chart(
    mocker: MockerFixture, sm: SimpleNamespace
) -> None:
    dashboard = _dashboard()
    mocker.patch.object(DashboardDAO, "get_by_id_or_slug", return_value=dashboard)
    charts = DashboardDAO.get_charts_for_dashboard("1")
    assert [c.id for c in charts] == [10]


def test_charts_keep_via_dashboard_grant(
    mocker: MockerFixture, sm: SimpleNamespace
) -> None:
    sm.can_access_datasource = lambda ds: False
    sm.can_drill_dataset_via_dashboard_access = lambda ds, dash: ds.id == 2
    mocker.patch.object(DashboardDAO, "get_by_id_or_slug", return_value=_dashboard())
    charts = DashboardDAO.get_charts_for_dashboard("1")
    assert [c.id for c in charts] == [20]


def test_charts_drop_chart_owned_via_copied_dashboard(
    mocker: MockerFixture, sm: SimpleNamespace
) -> None:
    """Ownership of a chart (through a copied dashboard) must not reveal it."""
    sm.is_owner = lambda obj: True
    mocker.patch.object(DashboardDAO, "get_by_id_or_slug", return_value=_dashboard())
    charts = DashboardDAO.get_charts_for_dashboard("1")
    assert [c.id for c in charts] == [10]
