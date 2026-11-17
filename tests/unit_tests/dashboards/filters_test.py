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

from pytest_mock import MockerFixture
from sqlalchemy import false, true
from sqlalchemy.orm.session import Session

from superset.connectors.sqla.models import SqlaTable
from superset.dashboards.filters import DashboardAccessFilter
from superset.models.core import Database
from superset.models.dashboard import Dashboard
from superset.models.slice import Slice


def _listed(
    session: Session, mocker: MockerFixture, database_filter: object
) -> set[str]:
    Dashboard.metadata.create_all(session.get_bind())
    dbs = {
        name: Database(database_name=name, sqlalchemy_uri="sqlite://") for name in "AB"
    }
    session.add_all(dbs.values())
    session.flush()
    dashboards = {}
    for name, database in [("A", dbs["A"]), ("B", dbs["B"]), ("empty", None)]:
        slices = []
        if database:
            table = SqlaTable(table_name=name, database=database)
            session.add(table)
            session.flush()
            slices = [
                Slice(
                    slice_name=name,
                    datasource_id=table.id,
                    datasource_type="table",
                    datasource_name=name,
                )
            ]
        dashboards[name] = Dashboard(
            dashboard_title=name, slug=name, published=True, slices=slices
        )
    session.add_all(dashboards.values())
    session.flush()
    role = _role(session)
    for dashboard in dashboards.values():
        dashboard.roles = [role]
    session.flush()

    manager = mocker.patch("superset.dashboards.filters.security_manager")
    manager.is_admin.return_value = False
    manager.get_user_roles.return_value = [role]
    manager.can_access_all_datasources.return_value = False
    manager.get_dashboard_rbac_database_filter.return_value = database_filter(dbs)
    mocker.patch("superset.dashboards.filters.is_feature_enabled", return_value=True)
    mocker.patch("superset.dashboards.filters.get_user_id", return_value=0)
    mocker.patch(
        "superset.dashboards.filters.get_dataset_access_filters",
        return_value=false(),
    )
    query = session.query(Dashboard)
    return {d.slug for d in DashboardAccessFilter("id", None).apply(query, None)}


def _role(session: Session):
    from flask_appbuilder.security.sqla.models import Role

    role = Role(name="viewer")
    session.add(role)
    session.flush()
    return role


def test_dashboard_rbac_list_bounded_by_database_filter(
    session: Session, mocker: MockerFixture
) -> None:
    listed = _listed(session, mocker, lambda dbs: Database.id == dbs["A"].id)
    assert listed == {"A", "empty"}


def test_dashboard_rbac_list_default_unbounded(
    session: Session, mocker: MockerFixture
) -> None:
    listed = _listed(session, mocker, lambda dbs: true())
    assert listed == {"A", "B", "empty"}
