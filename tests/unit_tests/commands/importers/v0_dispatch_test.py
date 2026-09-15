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
"""sc-24050: the UI/API import dispatchers must not fall through to the
unversioned v0 importers, which overwrite datasets and create database
connections with no ownership or access check."""

import pytest
import yaml
from sqlalchemy.orm.session import Session

from superset import db
from superset.commands.dashboard.importers.dispatcher import ImportDashboardsCommand
from superset.commands.dataset.importers.dispatcher import ImportDatasetsCommand
from superset.commands.exceptions import CommandInvalidError
from superset.connectors.sqla.models import SqlaTable
from superset.models.core import Database
from superset.utils import json


def _seed_dataset() -> SqlaTable:
    SqlaTable.metadata.create_all(db.session.get_bind())  # pylint: disable=no-member
    database = Database(database_name="examples", sqlalchemy_uri="sqlite://")
    dataset = SqlaTable(
        database=database, schema="main", table_name="t", sql="select 1"
    )
    db.session.add(dataset)
    # Commit, not flush: the v1 command's @transaction rolls back when it
    # raises IncorrectVersionError, which would erase flushed seed rows.
    db.session.commit()
    return dataset


def test_dataset_dispatcher_rejects_unversioned_yaml_list(session: Session) -> None:
    dataset = _seed_dataset()
    contents = {
        "datasets.yaml": yaml.safe_dump(
            [
                {
                    "table_name": "t",
                    "schema": "main",
                    "sql": "select 2",
                    "params": json.dumps({"database_name": "examples"}),
                }
            ]
        )
    }

    with pytest.raises(CommandInvalidError):
        ImportDatasetsCommand(contents, overwrite=True).run()

    assert db.session.query(SqlaTable).get(dataset.id).sql == "select 1"


def test_dataset_dispatcher_rejects_databases_dict(session: Session) -> None:
    _seed_dataset()
    before = db.session.query(Database).count()
    contents = {
        "databases.yaml": yaml.safe_dump(
            {"databases": [{"database_name": "new", "sqlalchemy_uri": "sqlite://"}]}
        )
    }

    with pytest.raises(CommandInvalidError):
        ImportDatasetsCommand(contents, overwrite=True).run()

    assert db.session.query(Database).count() == before


def test_dashboard_dispatcher_rejects_legacy_json(session: Session) -> None:
    dataset = _seed_dataset()
    contents = {
        "dashboards.json": json.dumps(
            {
                "dashboards": [],
                "datasources": [
                    {
                        "__SqlaTable__": {
                            "table_name": "t",
                            "schema": "main",
                            "sql": "select 2",
                            "params": json.dumps(
                                {"database_name": "examples", "remote_id": 1}
                            ),
                        }
                    }
                ],
            }
        )
    }

    with pytest.raises(CommandInvalidError):
        ImportDashboardsCommand(contents, overwrite=True).run()

    assert db.session.query(SqlaTable).get(dataset.id).sql == "select 1"
