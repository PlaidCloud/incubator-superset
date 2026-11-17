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
from typing import Any, cast

import pytest
from pytest_mock import MockerFixture

from superset.daos.dashboard import DashboardDAO
from superset.models.dashboard import Dashboard


class _Slice(SimpleNamespace):
    __hash__ = object.__hash__


def _dashboard() -> Any:
    mine = SimpleNamespace(id=1, data_for_slices=lambda slices: {"id": 1, "sql": "a"})
    other = SimpleNamespace(id=2, data_for_slices=lambda slices: {"id": 2, "sql": "b"})
    return SimpleNamespace(
        slices=[
            _Slice(id=10, datasource_id=1, datasource=mine),
            _Slice(id=20, datasource_id=2, datasource=other),
        ]
    )


@pytest.fixture
def sm(mocker: MockerFixture) -> Any:
    manager: Any = SimpleNamespace(
        is_admin=lambda: False,
        can_access_datasource=lambda ds: ds.id == 1,
        can_drill_dataset_via_dashboard_access=lambda ds, dash: False,
    )
    mocker.patch("superset.models.dashboard.security_manager", manager)
    mocker.patch("superset.daos.dashboard.security_manager", manager)
    return manager


def test_datasets_drop_inaccessible_datasource(sm: Any) -> None:
    result = Dashboard.datasets_trimmed_for_slices(cast(Any, _dashboard()))
    assert result == [{"id": 1, "sql": "a"}]


def test_datasets_keep_via_dashboard_grant(sm: Any) -> None:
    sm.can_access_datasource = lambda ds: False
    sm.can_drill_dataset_via_dashboard_access = lambda ds, dash: ds.id == 2
    result = Dashboard.datasets_trimmed_for_slices(cast(Any, _dashboard()))
    assert result == [{"id": 2, "sql": "b"}]


def test_datasets_admin_sees_all(sm: Any) -> None:
    sm.is_admin = lambda: True
    sm.can_access_datasource = lambda ds: False
    result = Dashboard.datasets_trimmed_for_slices(cast(Any, _dashboard()))
    assert [d["id"] for d in result] == [1, 2]


def test_charts_drop_inaccessible_chart(mocker: MockerFixture, sm: Any) -> None:
    dashboard = _dashboard()
    mocker.patch.object(DashboardDAO, "get_by_id_or_slug", return_value=dashboard)
    charts = DashboardDAO.get_charts_for_dashboard("1")
    assert [c.id for c in charts] == [10]


def test_charts_keep_via_dashboard_grant(mocker: MockerFixture, sm: Any) -> None:
    sm.can_access_datasource = lambda ds: False
    sm.can_drill_dataset_via_dashboard_access = lambda ds, dash: ds.id == 2
    mocker.patch.object(DashboardDAO, "get_by_id_or_slug", return_value=_dashboard())
    charts = DashboardDAO.get_charts_for_dashboard("1")
    assert [c.id for c in charts] == [20]


def test_charts_drop_chart_owned_via_copied_dashboard(
    mocker: MockerFixture, sm: Any
) -> None:
    """Ownership of a chart (through a copied dashboard) must not reveal it."""
    sm.is_owner = lambda obj: True
    mocker.patch.object(DashboardDAO, "get_by_id_or_slug", return_value=_dashboard())
    charts = DashboardDAO.get_charts_for_dashboard("1")
    assert [c.id for c in charts] == [10]


def test_mcp_dashboard_serializer_drops_inaccessible_chart(
    mocker: MockerFixture, sm: Any
) -> None:
    from superset.mcp_service.dashboard.schemas import serialize_dashboard_object

    mocker.patch(
        "superset.mcp_service.utils.url_utils.get_superset_base_url",
        return_value="http://localhost",
    )
    dashboard = _dashboard()
    for chart in dashboard.slices:
        chart.slice_name = f"chart{chart.id}"
        chart.viz_type = "table"
        chart.datasource_name = "t"
        chart.description = None
    dashboard.id = 1
    dashboard.slug = "d"
    info = serialize_dashboard_object(dashboard)
    assert [c.id for c in info.charts] == [10]
    assert info.chart_count == 1
