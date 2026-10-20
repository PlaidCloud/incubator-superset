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

from superset.sql.parse import SQLStatement


@pytest.mark.parametrize(
    "sql, expected",
    [
        ("SELECT COUNT(*)", False),
        ("SELECT CONCAT('US-', region)", False),
        ("SELECT CURRENT_DATE", False),
        ("SELECT LPAD(code, 5, '0')", False),
        # a Jinja comment is invisible to the parser; callers reject templates
        ("SELECT amount /* {{ url_param('x') }} */", False),
        ("SHOW TABLES", True),
        ("SELECT (SELECT 1 FROM t)", True),
        ("SELECT other.t.col", True),
        ("SELECT IDENTIFIER('db.s.t')", True),
        ("SELECT read_csv('x')", True),
        ("SELECT CURRENT_ROLE()", True),
        ("SELECT repeat('a', 3)", True),
        ("SELECT LPAD(code, 100000, '0')", True),
        ("SELECT LPAD(code, n, '0')", True),
        ("SELECT 1 ORDER BY (SELECT 1)", True),
    ],
)
def test_reaches_beyond_row(sql: str, expected: bool) -> None:
    """
    Test the `reaches_beyond_row` method used for ad-hoc SQL on external lakehouses.
    """
    assert SQLStatement(sql, "snowflake").reaches_beyond_row() is expected
