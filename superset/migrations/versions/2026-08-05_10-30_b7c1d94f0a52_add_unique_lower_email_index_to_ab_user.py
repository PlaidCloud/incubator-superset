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
"""Add a case-insensitive unique index on ab_user.email

Revision ID: b7c1d94f0a52
Revises: 4b2a8c9d3e1f
Create Date: 2026-08-05 10:30:00.000000

"""

import logging

import sqlalchemy as sa
from alembic import op

logger = logging.getLogger("alembic.env")

# revision identifiers, used by Alembic.
revision = "b7c1d94f0a52"
down_revision = "4b2a8c9d3e1f"

TABLE_NAME = "ab_user"
INDEX_NAME = "ix_ab_user_email_lower"

# Dialects whose CREATE INDEX accepts a bare ``lower(col)`` expression.
#
# PostgreSQL is the only backend used by the fleet; SQLite is included because the
# integration test suite runs `superset db upgrade` against it. MySQL is excluded
# deliberately: its functional-index syntax differs (it requires the expression to
# be double-parenthesised) and its default collations (utf8mb4_*_ci) are already
# case-insensitive, so the pre-existing UNIQUE (email) constraint enforces this
# invariant there without help.
SUPPORTED_DIALECTS = {"postgresql", "sqlite"}

# Bounds on how much detail the failure message prints, so a pathological amount
# of bad data cannot turn the error into an unreadable wall of text.
MAX_REPORTED_GROUPS = 20
MAX_REPORTED_IDS = 20

# The DDL is emitted directly rather than through
# superset.migrations.shared.utils.create_index / drop_index. Those helpers gate on
# `table_has_index`, which reflects via the SQLAlchemy inspector -- and the SQLite
# inspector silently omits expression-based indexes. That makes the helpers unable
# to see this index on SQLite, which turns `drop_index` into a no-op and leaves
# downgrade() as a non-inverse. `IF NOT EXISTS` / `IF EXISTS` give the same
# idempotency on both supported backends without any reflection.
CREATE_INDEX_DDL = (
    f"CREATE UNIQUE INDEX IF NOT EXISTS {INDEX_NAME} ON {TABLE_NAME} (lower(email))"
)
DROP_INDEX_DDL = f"DROP INDEX IF EXISTS {INDEX_NAME}"


def _find_duplicates(bind: sa.engine.Connection) -> list[tuple[str, int, list[int]]]:
    """
    Find email addresses that collide once lowercased.

    NULL emails are excluded because a unique index does not constrain NULLs; the
    empty string is *not* excluded because it is a real value the index will
    constrain. The predicate is exactly ``lower(email)`` -- no ``btrim`` -- so that
    the index matches the case-insensitive lookup the application performs. Adding
    whitespace trimming here would make the index stricter than the queries it
    backs, and could block a deploy over rows the application treats as distinct.

    :param bind: An open connection to the metadata database
    :returns: ``(lowercased_email, row_count, row_ids)`` per colliding group
    """

    groups = bind.execute(
        sa.text(
            """
            SELECT lower(email) AS lowered, COUNT(*) AS row_count
              FROM ab_user
             WHERE email IS NOT NULL
             GROUP BY lower(email)
            HAVING COUNT(*) > 1
             ORDER BY lower(email)
            """
        )
    ).all()

    duplicates = []
    for lowered, row_count in groups[:MAX_REPORTED_GROUPS]:
        ids = bind.execute(
            sa.text(
                """
                SELECT id
                  FROM ab_user
                 WHERE lower(email) = :lowered
                 ORDER BY id
                """
            ),
            {"lowered": lowered},
        ).scalars()
        duplicates.append((lowered, row_count, list(ids)))

    if len(groups) > MAX_REPORTED_GROUPS:
        logger.warning(
            "Found %s duplicate lower(email) groups; reporting the first %s.",
            len(groups),
            MAX_REPORTED_GROUPS,
        )

    return duplicates


def _format_failure(duplicates: list[tuple[str, int, list[int]]]) -> str:
    lines = [
        f"Cannot create {INDEX_NAME}: {len(duplicates)} email address(es) in "
        f"{TABLE_NAME} are duplicated when compared case-insensitively.",
        "",
    ]
    for lowered, row_count, ids in duplicates:
        shown = ", ".join(str(row_id) for row_id in ids[:MAX_REPORTED_IDS])
        if len(ids) > MAX_REPORTED_IDS:
            shown += f", ... ({len(ids) - MAX_REPORTED_IDS} more)"
        lines.append(f"  {lowered!r}: {row_count} rows, ab_user.id in [{shown}]")
    lines += [
        "",
        "This migration does not de-duplicate automatically: it cannot know which "
        "row is canonical, and silently deleting user rows mid-deploy is worse "
        "than a blocked deploy.",
        "",
        "Remedy -- for each address listed above:",
        "  1. Inspect the rows, e.g.",
        "     SELECT id, username, email, active, last_login, login_count",
        "       FROM ab_user WHERE lower(email) = '<address>' ORDER BY id;",
        "  2. Keep the canonical row: prefer active=true, then the most recent "
        "last_login, then the highest login_count, then the lowest id.",
        "  3. Re-point anything owned by the losing rows at the canonical id "
        "(created_by_fk / changed_by_fk / owners tables), then delete or rename "
        "the losing rows' emails.",
        "  4. Re-run `superset db upgrade`.",
    ]
    return "\n".join(lines)


def upgrade():
    """
    Enforce case-insensitive uniqueness of ab_user.email.

    ``ab_user.email`` carries a case-sensitive UNIQUE constraint
    (``ab_user_email_key``), so rows differing only in case legally coexist. That
    lets a case-insensitive user lookup match multiple rows and fail, which broke
    OAuth login (sc-23689). This index makes those rows impossible to create.

    The existing ``ab_user_email_key`` is intentionally left in place; the two
    coexist and a byte-identical duplicate still fails against it.
    """

    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect not in SUPPORTED_DIALECTS:
        logger.warning(
            "Dialect %s does not support a bare lower(email) index expression. "
            "Skipping creation of %s.",
            dialect,
            INDEX_NAME,
        )
        return

    if duplicates := _find_duplicates(bind):
        raise RuntimeError(_format_failure(duplicates))

    logger.info("Creating unique index %s on %s.", INDEX_NAME, TABLE_NAME)
    op.execute(sa.text(CREATE_INDEX_DDL))


def downgrade():
    """Drop the case-insensitive unique index on ab_user.email."""

    if op.get_bind().dialect.name not in SUPPORTED_DIALECTS:
        return

    logger.info("Dropping index %s from %s.", INDEX_NAME, TABLE_NAME)
    op.execute(sa.text(DROP_INDEX_DDL))
