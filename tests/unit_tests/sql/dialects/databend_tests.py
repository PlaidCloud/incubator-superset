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

import pytest
import sqlglot
from sqlglot import exp

from superset.sql.dialects.databend import Databend


def test_databend_dialect_registered() -> None:
    from superset.sql.parse import SQLGLOT_DIALECTS

    assert "databend" in SQLGLOT_DIALECTS
    assert SQLGLOT_DIALECTS["databend"] is Databend


def test_leading_settings_round_trips_unchanged() -> None:
    """
    A leading ``SETTINGS (...)`` timeout wrapper parses to a SELECT and is
    re-emitted verbatim.
    """
    sql = 'SETTINGS (max_execute_time_in_seconds=300) SELECT "col" FROM t'
    ast = sqlglot.parse_one(sql, Databend)

    assert isinstance(ast, exp.Select)
    assert ast.sql(dialect=Databend) == sql
    assert [table.name for table in ast.find_all(exp.Table)] == ["t"]


def test_leading_settings_multiple_values() -> None:
    sql = "SETTINGS (a=1, b=2) SELECT 1"
    assert sqlglot.parse_one(sql, Databend).sql(dialect=Databend) == sql


@pytest.mark.parametrize(
    "sql",
    [
        "SETTINGS (a=1) SELECT 1 UNION ALL SELECT 2",
        "SETTINGS (a=1) SELECT * FROM (SELECT id FROM u) AS sub",
        "SETTINGS (a=1) WITH s AS (SELECT 1 AS one) SELECT * FROM s",
    ],
)
def test_leading_settings_preserved_across_root_types(sql: str) -> None:
    """
    The wrapper must survive generation whatever the statement root is — not
    only a bare SELECT. A UNION or a parenthesized subquery is re-emitted from
    a generator hook other than ``select_sql``; emitting the settings only in
    ``select_sql`` silently dropped the timeout guard on those.
    """
    assert sqlglot.parse_one(sql, Databend).sql(dialect=Databend) == sql


def test_leading_settings_via_sqlscript_is_select() -> None:
    from superset.sql.parse import SQLScript

    sql = "SETTINGS (max_execute_time_in_seconds=300) SELECT col FROM t"
    script = SQLScript(sql, "databend")

    assert len(script.statements) == 1
    assert not script.has_mutation()


def test_leading_settings_survives_rls_regeneration() -> None:
    """
    User-visible path: when RLS is applied, virtual-dataset SQL is re-emitted
    via ``SQLStatement.format`` (``superset/models/helpers.py``). The leading
    ``SETTINGS`` must not be dropped there — for a UNION dataset too.
    """
    from superset.sql.parse import SQLStatement

    sql = "SETTINGS (max_execute_time_in_seconds=300) SELECT 1 UNION ALL SELECT 2"
    assert (
        SQLStatement(sql, "databend")
        .format()
        .startswith("SETTINGS (max_execute_time_in_seconds=300)")
    )


def test_leading_settings_transparent_to_table_extraction() -> None:
    """RLS depends on table extraction; the wrapper must not perturb it."""
    from superset.sql.parse import SQLStatement

    wrapped = SQLStatement("SETTINGS (a=1) SELECT c FROM myschema.t", "databend")
    plain = SQLStatement("SELECT c FROM myschema.t", "databend")
    extracted = {str(table) for table in wrapped.tables}
    assert extracted == {str(table) for table in plain.tables} == {"myschema.t"}


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "SELECT a, b FROM t WHERE c > 1",
        'SELECT COUNT(*) FROM "events" WHERE "type" = \'click\'',
        "SELECT * FROM t SETTINGS max_threads = 1",
        "SELECT `col` FROM `tbl`",
        "SELECT * FROM a JOIN b ON a.id = b.id",
        "SELECT DISTINCT x FROM t",
        "SELECT x FROM t GROUP BY x HAVING COUNT(*) > 1",
        "SELECT x FROM t ORDER BY x DESC LIMIT 10",
        "WITH source AS (SELECT 1 AS one) SELECT * FROM source",
        "SELECT * FROM (SELECT id FROM u) AS sub",
        "SELECT CAST(a AS String) FROM t",
        "INSERT INTO t VALUES (1)",
        "ALTER TABLE foo ADD COLUMN bar INT",
        "SELECT * FROM t WHERE name = 'O''Hara'",
    ],
)
def test_no_regression_on_known_good_statements(sql: str) -> None:
    """Statements that already parse under the generic dialect still parse."""
    assert sqlglot.parse_one(sql, Databend) is not None
