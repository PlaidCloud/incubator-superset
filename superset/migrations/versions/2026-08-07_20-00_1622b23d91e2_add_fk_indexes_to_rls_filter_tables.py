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
"""Add indexes on the FK columns of rls_filter_roles / rls_filter_tables

Revision ID: 1622b23d91e2
Revises: b7c1d94f0a52
Create Date: 2026-08-07 20:00:00.000000

sc-23432 (PlaidCloud row-level security) Part 5's rule + roster reconciler generates one
Regular rule per (dataset, attribute, granted group) plus a conditional Base guard per
(dataset, deny attribute) -- both `rls_filter_roles` and `rls_filter_tables` are read on
every RLS-governed query (`SecurityManager.get_rls_filters`, which filters
`RLSFilterRoles.c.role_id.in_(user_roles)` /
`RLSFilterTables.c.table_id == table.id`), and both association tables carry only
their own surrogate-key primary key today -- no index on either FK column. At the
row counts a single project's worth of granted groups already produces (a
200-dataset tenant with a few dozen groups reaches five figures of rows across the
two tables), every one of those lookups is a full table scan.
"""

# revision identifiers, used by Alembic.
revision = "1622b23d91e2"
down_revision = "b7c1d94f0a52"


from superset.migrations.shared.utils import create_index, drop_index  # noqa: E402


def upgrade():
    create_index(
        "rls_filter_roles",
        "ix_rls_filter_roles_role_id",
        ["role_id"],
        unique=False,
    )
    create_index(
        "rls_filter_roles",
        "ix_rls_filter_roles_rls_filter_id",
        ["rls_filter_id"],
        unique=False,
    )
    create_index(
        "rls_filter_tables",
        "ix_rls_filter_tables_table_id",
        ["table_id"],
        unique=False,
    )
    create_index(
        "rls_filter_tables",
        "ix_rls_filter_tables_rls_filter_id",
        ["rls_filter_id"],
        unique=False,
    )


def downgrade():
    drop_index(
        table_name="rls_filter_tables",
        index_name="ix_rls_filter_tables_rls_filter_id",
    )
    drop_index(
        table_name="rls_filter_tables",
        index_name="ix_rls_filter_tables_table_id",
    )
    drop_index(
        table_name="rls_filter_roles",
        index_name="ix_rls_filter_roles_rls_filter_id",
    )
    drop_index(
        table_name="rls_filter_roles",
        index_name="ix_rls_filter_roles_role_id",
    )
