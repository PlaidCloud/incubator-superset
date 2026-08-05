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
import re

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

# The index expression this migration requires, in its unnormalised form.
EXPECTED_EXPRESSION = "lower(email)"


def _normalize_expression(expression: str) -> str:
    """
    Reduce an index expression to a form comparable across backends.

    Postgres reports the expression with its own casts and parenthesisation
    (``lower((email)::text)``) while SQLite echoes back the literal text we wrote
    (``lower(email)``). Stripping casts, quoting, whitespace and parentheses makes
    both collapse to ``loweremail``, while a genuinely different expression such as
    ``lower(btrim(email))`` still compares unequal.
    """

    return re.sub(r"::text|[\s()\"`\[\]]", "", expression).lower()


def _describe_conflicting_index(bind: sa.engine.Connection) -> str | None:
    """
    Describe the existing index of our name if it is not the one we require.

    ``CREATE UNIQUE INDEX IF NOT EXISTS`` matches on *name* only. An index of this
    name that is not unique, or not on ``lower(email)``, or not even on
    ``ab_user`` -- for instance a non-unique ``lower(email)`` index hand-created
    while hot-fixing sc-23689 -- would turn this migration into a silent no-op that
    reports success while the invariant goes unenforced.

    :param bind: An open connection to the metadata database
    :returns: A human-readable description of the offending index, or None when the
        index is absent or already exactly what this migration would create
    """

    if bind.dialect.name == "postgresql":
        # Deliberately not filtered by table: Postgres index names are unique per
        # schema, so an index of this name on another table also blocks creation
        # (silently, under IF NOT EXISTS).
        row = bind.execute(
            sa.text(
                """
                SELECT t.relname AS table_name,
                       i.indisunique AS is_unique,
                       pg_get_expr(i.indexprs, i.indrelid) AS expression
                  FROM pg_index i
                  JOIN pg_class c ON c.oid = i.indexrelid
                  JOIN pg_class t ON t.oid = i.indrelid
                 WHERE c.relname = :index_name
                """
            ),
            {"index_name": INDEX_NAME},
        ).first()

        if row is None:
            return None
        if (
            row.table_name == TABLE_NAME
            and row.is_unique
            and _normalize_expression(row.expression or "")
            == _normalize_expression(EXPECTED_EXPRESSION)
        ):
            return None
        return (
            f"table={row.table_name}, unique={row.is_unique}, "
            f"expression={row.expression}"
        )

    existing_ddl = bind.execute(
        sa.text(
            """
            SELECT sql
              FROM sqlite_master
             WHERE type = 'index' AND name = :index_name
            """
        ),
        {"index_name": INDEX_NAME},
    ).scalar()

    if existing_ddl is None:
        return None
    if _normalize_expression(existing_ddl) == _normalize_expression(
        CREATE_INDEX_DDL.replace(" IF NOT EXISTS", "")
    ):
        return None
    return existing_ddl


def _format_conflict_failure(found: str) -> str:
    return "\n".join(
        [
            f"Cannot create {INDEX_NAME}: an index of that name already exists but "
            "is not a unique index on lower(email), so it does not enforce "
            "case-insensitive uniqueness.",
            "",
            f"  found:    {found}",
            f"  expected: table={TABLE_NAME}, unique=True, "
            f"expression={EXPECTED_EXPRESSION}",
            "",
            "`CREATE UNIQUE INDEX IF NOT EXISTS` matches on the index name alone, so "
            "leaving this in place would let the migration report success while "
            "case-variant duplicates remained possible.",
            "",
            "Remedy:",
            "  1. Confirm nothing depends on the existing index.",
            f"  2. DROP INDEX {INDEX_NAME};",
            "  3. Re-run `superset db upgrade`.",
        ]
    )


def _find_duplicates(
    bind: sa.engine.Connection,
) -> tuple[int, list[tuple[str, int, list[int]]]]:
    """
    Find email addresses that collide once lowercased.

    NULL emails are excluded because a unique index does not constrain NULLs. The
    predicate is exactly ``lower(email)`` -- no ``btrim`` -- so that the index
    matches the case-insensitive lookup the application performs. Adding whitespace
    trimming here would make the index stricter than the queries it backs, and
    could block a deploy over rows the application treats as distinct.

    :param bind: An open connection to the metadata database
    :returns: the total number of colliding groups, and ``(lowercased_email,
        row_count, row_ids)`` for at most ``MAX_REPORTED_GROUPS`` of them
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

    return len(groups), duplicates


def _format_failure(
    total_groups: int, duplicates: list[tuple[str, int, list[int]]]
) -> str:
    lines = [
        f"Cannot create {INDEX_NAME}: {total_groups} email address(es) in "
        f"{TABLE_NAME} are duplicated when compared case-insensitively.",
        "",
    ]
    if total_groups > len(duplicates):
        lines += [
            f"Showing the first {len(duplicates)}; re-run `superset db upgrade` "
            "after fixing these to see the rest.",
            "",
        ]
    for lowered, row_count, ids in duplicates:
        shown = ", ".join(str(row_id) for row_id in ids[:MAX_REPORTED_IDS])
        if len(ids) > MAX_REPORTED_IDS:
            shown += f", ... ({len(ids) - MAX_REPORTED_IDS} more)"
        # Rendered as a SQL literal (quotes doubled) so it can be pasted straight
        # into the remedy query below; repr() would emit "o'brien@x.com", which
        # Postgres reads as an identifier.
        literal = "'" + lowered.replace("'", "''") + "'"
        lines.append(f"  {literal}: {row_count} rows, ab_user.id in [{shown}]")
    lines += [
        "",
        "This migration does not de-duplicate automatically: it cannot know which "
        "row is canonical, and silently deleting user rows mid-deploy is worse "
        "than a blocked deploy.",
        "",
        "Remedy -- for each address listed above:",
        "  1. Inspect the rows, e.g.",
        "     SELECT id, username, email, active, last_login, login_count",
        "       FROM ab_user WHERE lower(email) = <address> ORDER BY id;",
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

    if conflict := _describe_conflicting_index(bind):
        raise RuntimeError(_format_conflict_failure(conflict))

    total_groups, duplicates = _find_duplicates(bind)
    if duplicates:
        raise RuntimeError(_format_failure(total_groups, duplicates))

    logger.info("Creating unique index %s on %s.", INDEX_NAME, TABLE_NAME)
    op.execute(sa.text(CREATE_INDEX_DDL))


def downgrade():
    """Drop the case-insensitive unique index on ab_user.email."""

    if op.get_bind().dialect.name not in SUPPORTED_DIALECTS:
        return

    logger.info("Dropping index %s from %s.", INDEX_NAME, TABLE_NAME)
    op.execute(sa.text(DROP_INDEX_DDL))
