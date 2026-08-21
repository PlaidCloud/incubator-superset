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
"""
RLS on virtual datasets must fail closed.

``get_from_clause()`` wrapped its RLS application block in a bare
``except Exception: logger.warning(...)``. Anything raising inside it left the
SQL unfiltered and returned every row to a user entitled to a subset, with only
a log line to show for it. Reproduced against Databend: an RLS clause containing
an apostrophe (``"col" = 'O'Brien'``) is unparseable, and the query returned
70,421 rows to a user entitled to 52,145.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from jinja2 import TemplateError
from sqlalchemy.sql.elements import TextClause

from superset.exceptions import (
    QueryObjectValidationError,
    SupersetParseError,
    SupersetSecurityException,
)
from superset.models.helpers import ExploreMixin


@pytest.fixture
def virtual_datasource() -> MagicMock:
    datasource = MagicMock(spec=ExploreMixin)
    datasource.get_from_clause = ExploreMixin.get_from_clause.__get__(datasource)
    datasource.text = lambda sql: TextClause(sql)
    datasource.db_engine_spec.engine = "postgresql"
    datasource.db_engine_spec.get_cte_query.return_value = None
    datasource.db_engine_spec.cte_alias = "__cte"
    datasource.database.get_default_schema.return_value = "public"
    datasource.catalog = None
    datasource.schema = "public"
    datasource.get_rendered_sql.return_value = "SELECT pen_id FROM public.pens"
    return datasource


class TestVirtualDatasetRLSFailsClosed:
    @pytest.mark.parametrize(
        "error",
        [
            ValueError("Error tokenizing '(\"col\" = 'O'Brien''"),
            RuntimeError("boom"),
        ],
    )
    def test_apply_rls_failure_raises_instead_of_returning_unfiltered_sql(
        self,
        virtual_datasource: MagicMock,
        app: Flask,
        error: Exception,
    ) -> None:
        """A raise inside the RLS block must block the query, not drop the filter."""
        with patch("superset.models.helpers.apply_rls", side_effect=error):
            with pytest.raises(SupersetSecurityException):
                virtual_datasource.get_from_clause(template_processor=None)

    def test_format_failure_raises(
        self,
        virtual_datasource: MagicMock,
        app: Flask,
    ) -> None:
        """A failure re-rendering the SQL must not fall back to unfiltered SQL."""
        with (
            patch("superset.models.helpers.apply_rls", return_value=True),
            patch(
                "superset.sql.parse.SQLScript.format",
                side_effect=ValueError("cannot format"),
            ),
            pytest.raises(SupersetSecurityException),
        ):
            virtual_datasource.get_from_clause(template_processor=None)

    def test_successful_rls_still_returns_from_clause(
        self,
        virtual_datasource: MagicMock,
        app: Flask,
    ) -> None:
        """The happy path is unchanged."""
        with patch("superset.models.helpers.apply_rls", return_value=False):
            from_clause, cte = virtual_datasource.get_from_clause(
                template_processor=None
            )
        assert cte is None
        assert "SELECT pen_id FROM public.pens" in str(from_clause.element)


class TestDuplicateDatasetsAreDeterministic:
    def test_predicates_collected_from_every_matching_dataset(
        self,
        mocker: MagicMock,
    ) -> None:
        """
        Two datasets over one physical table must not raise
        ``MultipleResultsFound``; their predicates are combined.

        The physical uniqueness constraint is only
        ``(database_id, schema, table_name)`` - the four-column constraint
        declared on the model does not exist in the migrations - and Postgres
        treats NULL schemas as distinct, so duplicates are permitted.
        """
        from superset.sql.parse import Table
        from superset.utils.rls import get_predicates_for_table

        database = mocker.MagicMock()

        def _dataset(compiled: str) -> MagicMock:
            predicate = mocker.MagicMock()
            predicate.compile.return_value = compiled
            dataset = mocker.MagicMock()
            dataset.get_sqla_row_level_filters.return_value = [predicate]
            return dataset

        db = mocker.patch("superset.utils.rls.db")
        db.session.query().filter().order_by().all.return_value = [
            _dataset("c1 = 1"),
            _dataset("c2 = 2"),
        ]

        table = Table("t1", "public", "examples")
        assert get_predicates_for_table(table, database, "examples") == [
            "c1 = 1",
            "c2 = 2",
        ]

    def test_no_matching_dataset_returns_empty(
        self,
        mocker: MagicMock,
    ) -> None:
        """
        A physical table with no dataset carries no RLS: return ``[]`` rather
        than raise. This is not a fail-open path - a table nothing points at
        has no rules to apply - and it must stay covered so the empty branch
        does not regress into an exception.
        """
        from superset.sql.parse import Table
        from superset.utils.rls import get_predicates_for_table

        database = mocker.MagicMock()
        db = mocker.patch("superset.utils.rls.db")
        db.session.query().filter().order_by().all.return_value = []

        table = Table("t1", "public", "examples")
        assert get_predicates_for_table(table, database, "examples") == []


class TestCacheKeyDoesNotDegrade:
    def test_predicate_collection_failure_propagates(
        self,
        mocker: MagicMock,
    ) -> None:
        """
        Returning ``[]`` on failure produced the same cache key as a user with no
        RLS, letting a restricted user hit an unrestricted user's cached rows.
        """
        from superset.utils.rls import collect_rls_predicates_for_sql

        database = mocker.MagicMock()
        database.db_engine_spec.engine = "postgresql"
        mocker.patch(
            "superset.sql.parse.SQLScript.__init__",
            side_effect=ValueError("unparseable"),
        )

        with pytest.raises(ValueError, match="unparseable"):
            collect_rls_predicates_for_sql("SELECT 1", database, "examples", "public")


class TestVirtualDatasetCacheKeyRendersTemplate:
    """
    The cache-key path must render Jinja before parsing, like the execution path.

    ``get_from_clause()`` calls ``get_rendered_sql()`` before handing SQL to
    ``SQLScript``. ``get_extra_cache_keys()`` passed ``self.sql`` raw, so a
    virtual dataset whose SQL opens with ``{% set %}`` reached sqlglot as
    template text and raised, taking every chart on that dataset down with it.

    The *context* matters as much as the render. The processor is
    ``SandboxedEnvironment(undefined=DebugUndefined)``, which renders an
    unresolved tag back as the tag rather than as an empty string, so a dataset
    whose ``template_params`` name the schema or table stays broken unless those
    params are forwarded.

    These tests therefore build the real ``JinjaTemplateProcessor`` and let
    production supply the context. A stub on a bare ``jinja2.Template`` renders
    unresolved names *empty* and would pass whether or not the context is
    forwarded - hiding the very defect being pinned.
    """

    JINJA_SQL = (
        "{% set terms = filter_values('ServiceCodeLabelName') or [] %}\n"
        "SELECT hours FROM public.time_billing"
    )

    @staticmethod
    def _table(
        sql: str | None = None,
        template_params: dict[str, Any] | None = None,
    ) -> MagicMock:
        from superset.connectors.sqla.models import SqlaTable
        from superset.jinja_context import JinjaTemplateProcessor

        cls = TestVirtualDatasetCacheKeyRendersTemplate
        table = MagicMock(spec=SqlaTable)
        table.get_extra_cache_keys = SqlaTable.get_extra_cache_keys.__get__(table)
        table.get_rendered_sql = ExploreMixin.get_rendered_sql.__get__(table)
        table.is_virtual = True
        table.sql = cls.JINJA_SQL if sql is None else sql
        table.catalog = None
        table.schema = "public"
        table.template_params_dict = template_params or {}
        table.has_extra_cache_key_calls.return_value = False
        table.database.get_default_schema.return_value = "public"
        table.db_engine_spec.engine = "postgresql"
        table.database.db_engine_spec.engine = "postgresql"
        table.database.get_default_catalog.return_value = None

        # Forward whatever context production passes instead of injecting one
        # here: what reaches the processor is exactly what is under test.
        table.get_template_processor.side_effect = lambda **kwargs: (
            JinjaTemplateProcessor(database=table.database, table=table, **kwargs)
        )
        return table

    @patch("superset.utils.rls.get_predicates_for_table", return_value=[])
    def test_jinja_virtual_dataset_yields_cache_keys_instead_of_raising(
        self,
        mock_get_predicates: MagicMock,
        app_context: None,
    ) -> None:
        """The reported outage: ``{% set %}`` must not reach sqlglot."""
        assert self._table().get_extra_cache_keys({"extras": {}}) == []

    @patch("superset.utils.rls.get_predicates_for_table", return_value=["dept = 'x'"])
    def test_rls_predicate_still_reaches_the_cache_key(
        self,
        mock_get_predicates: MagicMock,
        app_context: None,
    ) -> None:
        keys = self._table().get_extra_cache_keys({"extras": {}})

        assert sorted(keys) == ["dept = 'x'"]

    @patch("superset.utils.rls.get_predicates_for_table", return_value=["dept = 'x'"])
    def test_template_params_resolve_the_table_they_name(
        self,
        mock_get_predicates: MagicMock,
        app_context: None,
    ) -> None:
        """
        ``template_params`` must reach the processor.

        Under ``DebugUndefined`` an unresolved ``{{ schema }}`` renders back as
        ``{{ schema }}``, sqlglot fails on the brace, and the chart 422s - the
        same outage in a shape the ``filter_values`` case never exercises,
        because that macro reads the request rather than the context.
        ``get_virtual_table_metadata()`` already forwards the params this way.
        """
        table = self._table(
            sql="SELECT hours FROM {{ schema }}.time_billing",
            template_params={"schema": "reporting"},
        )

        keys = table.get_extra_cache_keys({"extras": {}})

        assert sorted(keys) == ["dept = 'x'"]
        collected = mock_get_predicates.call_args[0][0]
        assert (collected.schema, collected.table) == ("reporting", "time_billing")

    @patch("superset.utils.rls.get_predicates_for_table", return_value=[])
    def test_unresolved_tag_in_table_position_still_raises(
        self,
        mock_get_predicates: MagicMock,
        app_context: None,
    ) -> None:
        """
        The residual stays fail-closed *by construction*.

        Context this path genuinely cannot supply - ``{{ from_dttm }}``,
        ``{{ row_limit }}`` and friends - survives the render as a tag and dies
        at the parser. That is deliberate: swallowing it would return ``[]`` and
        hand a restricted user the cache key of an unrestricted one, which is
        the hazard ``superset/utils/rls.py`` documents. Do not wrap this in a
        ``try/except``.
        """
        table = self._table(sql="SELECT hours FROM {{ from_dttm }}.time_billing")

        with pytest.raises(SupersetParseError):
            table.get_extra_cache_keys({"extras": {}})

    def test_render_failure_propagates_instead_of_degrading_the_key(
        self,
        app_context: None,
    ) -> None:
        """
        A template that cannot render must block the request, not yield ``[]``.

        This is the guarantee the whole module exists to pin, and it was the
        load-bearing claim of the fix while going untested.
        """
        table = self._table()
        processor = MagicMock()
        processor.process_template.side_effect = TemplateError("boom")
        table.get_template_processor.side_effect = None
        table.get_template_processor.return_value = processor

        with pytest.raises(QueryObjectValidationError):
            table.get_extra_cache_keys({"extras": {}})

    @patch("superset.utils.rls.get_predicates_for_table", return_value=["dept = 'x'"])
    def test_plain_virtual_dataset_is_unaffected(
        self,
        mock_get_predicates: MagicMock,
        app_context: None,
    ) -> None:
        """Every virtual dataset now pays a render; the keys must not move."""
        table = self._table(sql="SELECT hours FROM public.time_billing")

        keys = table.get_extra_cache_keys({"extras": {}})

        assert sorted(keys) == ["dept = 'x'"]
