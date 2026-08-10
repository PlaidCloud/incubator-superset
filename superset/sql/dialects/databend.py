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
Databend dialect.

Databend's SQL is close to ClickHouse, but it also accepts a *leading*
``SETTINGS (...)`` clause before the statement — e.g.
``SETTINGS (max_execute_time_in_seconds=300) SELECT ...``, which PlaidCloud
emits as a query-timeout wrapper. No built-in sqlglot dialect parses that form,
so it is absorbed here and re-emitted verbatim on generation.
"""

from __future__ import annotations

from sqlglot import exp
from sqlglot.dialects.clickhouse import ClickHouse
from sqlglot.tokens import TokenType


class Databend(ClickHouse):
    class Parser(ClickHouse.Parser):
        # ClickHouse reserves GLOBAL / SAMPLE / PREWHERE as keywords, but Databend
        # accepts them as ordinary identifiers (verified against a live Databend:
        # bare ``SELECT sample FROM t`` runs there, while bare ``union`` is
        # rejected by Databend too, so it stays reserved). Restoring these keeps
        # datasets whose columns are named after them parseable — they parsed
        # under the generic dialect Databend previously fell back to.
        ID_VAR_TOKENS = {
            *ClickHouse.Parser.ID_VAR_TOKENS,
            TokenType.GLOBAL,
            TokenType.PREWHERE,
            TokenType.TABLE_SAMPLE,
        }

        def _parse_statement(self) -> exp.Expression | None:
            settings = None
            if self._curr and self._curr.token_type == TokenType.SETTINGS:
                index = self._index
                start = self._curr
                self._advance()
                if self._curr and self._curr.token_type == TokenType.L_PAREN:
                    self._parse_wrapped_csv(self._parse_assignment)
                    settings = self._find_sql(start, self._prev)
                else:
                    self._retreat(index)

            statement = super()._parse_statement()
            if settings and statement:
                statement.set("leading_settings", settings)
            return statement

    class Generator(ClickHouse.Generator):
        def generate(self, expression: exp.Expression, copy: bool = True) -> str:
            # Re-emit the absorbed leading ``SETTINGS (...)`` at the statement
            # root, so it survives regardless of the root's type — a bare
            # SELECT, a UNION, a parenthesized subquery, or a non-query
            # statement. ``select_sql`` alone would drop it on anything but a
            # plain SELECT.
            settings = (
                expression.args.get("leading_settings")
                if isinstance(expression, exp.Expression)
                else None
            )
            sql = super().generate(expression, copy=copy)
            return f"{settings} {sql}" if settings else sql
