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
# pylint: disable=C,R,W
import json
import logging
import textwrap
from contextlib import closing
from copy import copy, deepcopy
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Hashable, List, NamedTuple, Optional, Set, Tuple, Type, Union

import numpy
import pandas as pd
import sqlalchemy as sa
import sqlparse
from flask import escape, g, Markup, request
from flask_appbuilder import Model
from flask_babel import lazy_gettext as _
from sqlalchemy import (
    and_,
    asc,
    Boolean,
    Column,
    create_engine,
    DateTime,
    desc,
    ForeignKey,
    Integer,
    MetaData,
    or_,
    select,
    String,
    Table,
    Text,
)
from sqlalchemy.engine import Dialect, Engine, url
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.engine.url import make_url, URL
from sqlalchemy.exc import CompileError
from sqlalchemy.orm import backref, Query, relationship, RelationshipProperty, Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.pool import NullPool
from sqlalchemy.schema import UniqueConstraint
from sqlalchemy.sql import column, ColumnElement, literal_column, table, text
from sqlalchemy.sql.expression import Label, Select, TextAsFrom
from sqlalchemy.types import TypeEngine

from superset import app, db, db_engine_specs, is_feature_enabled, security_manager
from superset.connectors.base.models import BaseColumn, BaseDatasource, BaseMetric
from superset.constants import NULL_STRING
from superset.db_engine_specs.base import TimeGrain, TimestampExpression
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
from superset.exceptions import (
    DatabaseNotFound,
    QueryObjectValidationError,
    SupersetSecurityException,
)
from superset.jinja_context import (
    BaseTemplateProcessor,
    ExtraCache,
    get_template_processor,
)
from superset.models.annotations import Annotation
from superset.models.helpers import AuditMixinNullable, QueryResult, ImportMixin
from superset.result_set import SupersetResultSet
from superset.sql_parse import ParsedQuery
from superset.typing import Metric, QueryObjectDict
from superset.utils import cache as cache_util, core as utils, import_datasource
from sqlalchemy_utils import EncryptedType


config = app.config
custom_password_store = config["SQLALCHEMY_CUSTOM_PASSWORD_STORE"]
stats_logger = config.get("STATS_LOGGER")
log_query = config.get("QUERY_LOGGER")
metadata = Model.metadata  # pylint: disable=no-member
logger = logging.getLogger(__name__)
hide_schema_names = app.config.get('HIDE_SCHEMA_NAMES', False)

PASSWORD_MASK = "X" * 10
DB_CONNECTION_MUTATOR = config["DB_CONNECTION_MUTATOR"]


class PlaidQuery(NamedTuple):
    extra_cache_keys: List[Any]
    labels_expected: List[str]
    prequeries: List[str]
    sqla_query: Select


class QueryStringExtended(NamedTuple):
    labels_expected: List[str]
    prequeries: List[str]
    sql: str


@dataclass
class MetadataResult:
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)


class PlaidProject(
    Model, AuditMixinNullable, ImportMixin
):  # pylint: disable=too-many-public-methods

    """An ORM object that stores Database related information"""

    __tablename__ = "plaid_projects"
    type = "plaid"
    __table_args__ = (UniqueConstraint("uuid"),)

    id = Column(Integer, primary_key=True)
    name = Column(String(250))
    uuid = Column(String(250), unique=True)
    workspace_id = Column(String(250))
    workspace_name = Column(String(250))
    sqlalchemy_uri = Column(String(1024), nullable=False)
    password = Column(EncryptedType(String(1024), config["SECRET_KEY"]))
    cache_timeout = Column(Integer)
    select_as_create_table_as = Column(Boolean, default=False)
    expose_in_sqllab = Column(Boolean, default=True)
    allow_run_async = Column(Boolean, default=False)
    allow_csv_upload = Column(Boolean, default=False)
    allow_ctas = Column(Boolean, default=False)
    allow_cvas = Column(Boolean, default=False)
    allow_dml = Column(Boolean, default=False)
    force_ctas_schema = Column(String(250))
    allow_multi_schema_metadata_fetch = Column(  # pylint: disable=invalid-name
        Boolean, default=False
    )
    extra = Column(
        Text,
        default=textwrap.dedent(
            """\
    {
        "metadata_params": {},
        "engine_params": {},
        "metadata_cache_timeout": {},
        "schemas_allowed_for_csv_upload": []
    }
    """
        ),
    )
    encrypted_extra = Column(EncryptedType(Text, config["SECRET_KEY"]), nullable=True)
    impersonate_user = Column(Boolean, default=False)
    server_cert = Column(EncryptedType(Text, config["SECRET_KEY"]), nullable=True)
    export_fields = [
        "uuid",
        "sqlalchemy_uri",
        "cache_timeout",
        "expose_in_sqllab",
        "allow_run_async",
        "allow_ctas",
        "allow_csv_upload",
        "extra",
    ]
    export_children = ["tables"]

    def __repr__(self) -> str:
        return self.project_name

    @property
    def project_name(self) -> str:
        return self.name if self.name else self.uuid

    @property
    def allows_subquery(self) -> bool:
        return self.db_engine_spec.allows_subqueries

    @property
    def function_names(self) -> List[str]:
        try:
            return self.db_engine_spec.get_function_names(self)
        except Exception as ex:  # pylint: disable=broad-except
            # function_names property is used in bulk APIs and should not hard crash
            # more info in: https://github.com/apache/incubator-superset/issues/9678
            logger.error(
                "Failed to fetch database function names with error: %s", str(ex)
            )
        return []

    @property
    def allows_cost_estimate(self) -> bool:
        extra = self.get_extra()

        database_version = extra.get("version")
        cost_estimate_enabled: bool = extra.get("cost_estimate_enabled")  # type: ignore

        return (
            self.db_engine_spec.get_allow_cost_estimate(database_version)
            and cost_estimate_enabled
        )

    @property
    def allows_virtual_table_explore(self) -> bool:
        extra = self.get_extra()

        return bool(extra.get("allows_virtual_table_explore", True))

    @property
    def explore_database_id(self) -> int:
        return self.get_extra().get("explore_database_id", self.id)

    @property
    def data(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "uuid": self.uuid,
            "workspace_id": self.workspace_id,
            "name": self.name,
            "backend": self.backend,
            "allow_multi_schema_metadata_fetch": self.allow_multi_schema_metadata_fetch,
            "allows_subquery": self.allows_subquery,
            "allows_cost_estimate": self.allows_cost_estimate,
            "allows_virtual_table_explore": self.allows_virtual_table_explore,
            "explore_database_id": self.explore_database_id,
        }

    @property
    def unique_name(self) -> str:
        return self.uuid

    @property
    def url_object(self) -> URL:
        return make_url(self.sqlalchemy_uri_decrypted)

    @property
    def backend(self) -> str:
        sqlalchemy_url = make_url(self.sqlalchemy_uri_decrypted)
        return sqlalchemy_url.get_backend_name()  # pylint: disable=no-member

    @property
    def metadata_cache_timeout(self) -> Dict[str, Any]:
        return self.get_extra().get("metadata_cache_timeout", {})

    @property
    def schema_cache_enabled(self) -> bool:
        return "schema_cache_timeout" in self.metadata_cache_timeout

    @property
    def schema_cache_timeout(self) -> Optional[int]:
        return self.metadata_cache_timeout.get("schema_cache_timeout")

    @property
    def table_cache_enabled(self) -> bool:
        return "table_cache_timeout" in self.metadata_cache_timeout

    @property
    def table_cache_timeout(self) -> Optional[int]:
        return self.metadata_cache_timeout.get("table_cache_timeout")

    @property
    def default_schemas(self) -> List[str]:
        return self.get_extra().get("default_schemas", [])

    @property
    def connect_args(self) -> Dict[str, Any]:
        return self.get_extra().get("engine_params", {}).get("connect_args", {})

    @classmethod
    def get_password_masked_url_from_uri(  # pylint: disable=invalid-name
        cls, uri: str
    ) -> URL:
        sqlalchemy_url = make_url(uri)
        return cls.get_password_masked_url(sqlalchemy_url)

    @classmethod
    def get_password_masked_url(cls, masked_url: URL) -> URL:
        url_copy = deepcopy(masked_url)
        if url_copy.password is not None:
            url_copy.password = PASSWORD_MASK
        return url_copy

    def set_sqlalchemy_uri(self, uri: str) -> None:
        conn = sa.engine.url.make_url(uri.strip())
        if conn.password != PASSWORD_MASK and not custom_password_store:
            # do not over-write the password with the password mask
            self.password = conn.password
        conn.password = PASSWORD_MASK if conn.password else None
        self.sqlalchemy_uri = str(conn)  # hides the password

    def get_effective_user(
        self, object_url: URL, user_name: Optional[str] = None,
    ) -> Optional[str]:
        """
        Get the effective user, especially during impersonation.
        :param object_url: SQL Alchemy URL object
        :param user_name: Default username
        :return: The effective username
        """
        effective_username = None
        if self.impersonate_user:
            effective_username = object_url.username
            if user_name:
                effective_username = user_name
            elif (
                hasattr(g, "user")
                and hasattr(g.user, "username")
                and g.user.username is not None
            ):
                effective_username = g.user.username
        return effective_username

    @utils.memoized(watch=("impersonate_user", "sqlalchemy_uri_decrypted", "extra"))
    def get_sqla_engine(
        self,
        schema: Optional[str] = None,
        nullpool: bool = True,
        user_name: Optional[str] = None,
        source: Optional[utils.QuerySource] = None,
    ) -> Engine:
        extra = self.get_extra()
        sqlalchemy_url = make_url(self.sqlalchemy_uri_decrypted)
        self.db_engine_spec.adjust_database_uri(sqlalchemy_url, schema)
        effective_username = self.get_effective_user(sqlalchemy_url, user_name)
        # If using MySQL or Presto for example, will set url.username
        # If using Hive, will not do anything yet since that relies on a
        # configuration parameter instead.
        self.db_engine_spec.modify_url_for_impersonation(
            sqlalchemy_url, self.impersonate_user, effective_username
        )

        masked_url = self.get_password_masked_url(sqlalchemy_url)
        logger.debug("Database.get_sqla_engine(). Masked URL: %s", str(masked_url))

        params = extra.get("engine_params", {})
        if nullpool:
            params["poolclass"] = NullPool

        connect_args = params.get("connect_args", {})
        configuration = connect_args.get("configuration", {})

        # If using Hive, this will set hive.server2.proxy.user=$effective_username
        configuration.update(
            self.db_engine_spec.get_configuration_for_impersonation(
                str(sqlalchemy_url), self.impersonate_user, effective_username
            )
        )
        if configuration:
            connect_args["configuration"] = configuration
        if connect_args:
            params["connect_args"] = connect_args

        params.update(self.get_encrypted_extra())

        if DB_CONNECTION_MUTATOR:
            if not source and request and request.referrer:
                if "/superset/dashboard/" in request.referrer:
                    source = utils.QuerySource.DASHBOARD
                elif "/superset/explore/" in request.referrer:
                    source = utils.QuerySource.CHART
                elif "/superset/sqllab/" in request.referrer:
                    source = utils.QuerySource.SQL_LAB

            sqlalchemy_url, params = DB_CONNECTION_MUTATOR(
                sqlalchemy_url, params, effective_username, security_manager, source
            )

        return create_engine(sqlalchemy_url, **params)

    def get_reserved_words(self) -> Set[str]:
        return self.get_dialect().preparer.reserved_words

    def get_quoter(self) -> Callable[[str, Any], str]:
        return self.get_dialect().identifier_preparer.quote

    def get_df(  # pylint: disable=too-many-locals
        self,
        sql: str,
        schema: Optional[str] = None,
        mutator: Optional[Callable[[pd.DataFrame], None]] = None,
    ) -> pd.DataFrame:
        sqls = [str(s).strip(" ;") for s in sqlparse.parse(sql)]

        engine = self.get_sqla_engine(schema=schema)
        username = utils.get_username()

        def needs_conversion(df_series: pd.Series) -> bool:
            return not df_series.empty and isinstance(df_series[0], (list, dict))

        def _log_query(sql: str) -> None:
            if log_query:
                log_query(engine.url, sql, schema, username, __name__, security_manager)

        with closing(engine.raw_connection()) as conn:
            with closing(conn.cursor()) as cursor:
                for sql_ in sqls[:-1]:
                    _log_query(sql_)
                    self.db_engine_spec.execute(cursor, sql_)
                    cursor.fetchall()

                _log_query(sqls[-1])
                self.db_engine_spec.execute(cursor, sqls[-1])

                data = self.db_engine_spec.fetch_data(cursor)
                result_set = SupersetResultSet(
                    data, cursor.description, self.db_engine_spec
                )
                df = result_set.to_pandas_df()
                if mutator:
                    mutator(df)

                for k, v in df.dtypes.items():
                    if v.type == numpy.object_ and needs_conversion(df[k]):
                        df[k] = df[k].apply(utils.json_dumps_w_dates)

                return df

    def compile_sqla_query(self, qry: Select, schema: Optional[str] = None) -> str:
        engine = self.get_sqla_engine(schema=schema)

        sql = str(qry.compile(engine, compile_kwargs={"literal_binds": True}))

        if (
            engine.dialect.identifier_preparer._double_percents  # pylint: disable=protected-access
        ):
            sql = sql.replace("%%", "%")

        return sql

    def select_star(  # pylint: disable=too-many-arguments
        self,
        table_name: str,
        schema: Optional[str] = None,
        limit: int = 100,
        show_cols: bool = False,
        indent: bool = True,
        latest_partition: bool = False,
        cols: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Generates a ``select *`` statement in the proper dialect"""
        eng = self.get_sqla_engine(schema=schema, source=utils.QuerySource.SQL_LAB)
        return self.db_engine_spec.select_star(
            self,
            table_name,
            schema=schema,
            engine=eng,
            limit=limit,
            show_cols=show_cols,
            indent=indent,
            latest_partition=latest_partition,
            cols=cols,
        )

    def apply_limit_to_sql(self, sql: str, limit: int = 1000) -> str:
        return self.db_engine_spec.apply_limit_to_sql(sql, limit, self)

    def safe_sqlalchemy_uri(self) -> str:
        return self.sqlalchemy_uri

    @property
    def inspector(self) -> Inspector:
        engine = self.get_sqla_engine()
        return sa.inspect(engine)

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: "db:{}:schema:None:table_list",
        attribute_in_key="id",
    )
    def get_all_table_names_in_database(
        self,
        cache: bool = False,
        cache_timeout: Optional[bool] = None,
        force: bool = False,
    ) -> List[utils.DatasourceName]:
        """Parameters need to be passed as keyword arguments."""
        if not self.allow_multi_schema_metadata_fetch:
            return []
        return self.db_engine_spec.get_all_datasource_names(self, "table")

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: "db:{}:schema:None:view_list", attribute_in_key="id"
    )
    def get_all_view_names_in_database(
        self,
        cache: bool = False,
        cache_timeout: Optional[bool] = None,
        force: bool = False,
    ) -> List[utils.DatasourceName]:
        """Parameters need to be passed as keyword arguments."""
        if not self.allow_multi_schema_metadata_fetch:
            return []
        return self.db_engine_spec.get_all_datasource_names(self, "view")

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: f"db:{{}}:schema:{kwargs.get('schema')}:table_list",  # type: ignore
        attribute_in_key="id",
    )
    def get_all_table_names_in_schema(
        self,
        schema: str,
        cache: bool = False,
        cache_timeout: Optional[int] = None,
        force: bool = False,
    ) -> List[utils.DatasourceName]:
        """Parameters need to be passed as keyword arguments.

        For unused parameters, they are referenced in
        cache_util.memoized_func decorator.

        :param schema: schema name
        :param cache: whether cache is enabled for the function
        :param cache_timeout: timeout in seconds for the cache
        :param force: whether to force refresh the cache
        :return: list of tables
        """
        try:
            tables = self.db_engine_spec.get_table_names(
                database=self, inspector=self.inspector, schema=schema
            )
            return [
                utils.DatasourceName(table=table, schema=schema) for table in tables
            ]
        except Exception as ex:  # pylint: disable=broad-except
            logger.warning(ex)

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: f"db:{{}}:schema:{kwargs.get('schema')}:view_list",  # type: ignore
        attribute_in_key="id",
    )
    def get_all_view_names_in_schema(
        self,
        schema: str,
        cache: bool = False,
        cache_timeout: Optional[int] = None,
        force: bool = False,
    ) -> List[utils.DatasourceName]:
        """Parameters need to be passed as keyword arguments.

        For unused parameters, they are referenced in
        cache_util.memoized_func decorator.

        :param schema: schema name
        :param cache: whether cache is enabled for the function
        :param cache_timeout: timeout in seconds for the cache
        :param force: whether to force refresh the cache
        :return: list of views
        """
        try:
            views = self.db_engine_spec.get_view_names(
                database=self, inspector=self.inspector, schema=schema
            )
            return [utils.DatasourceName(table=view, schema=schema) for view in views]
        except Exception as ex:  # pylint: disable=broad-except
            logger.warning(ex)

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: "db:{}:schema_list", attribute_in_key="id"
    )
    def get_all_schema_names(
        self,
        cache: bool = False,
        cache_timeout: Optional[int] = None,
        force: bool = False,
    ) -> List[str]:
        """Parameters need to be passed as keyword arguments.

        For unused parameters, they are referenced in
        cache_util.memoized_func decorator.

        :param cache: whether cache is enabled for the function
        :param cache_timeout: timeout in seconds for the cache
        :param force: whether to force refresh the cache
        :return: schema list
        """
        return self.db_engine_spec.get_schema_names(self.inspector)

    @property
    def db_engine_spec(self) -> Type[db_engine_specs.BaseEngineSpec]:
        return db_engine_specs.engines.get(self.backend, db_engine_specs.BaseEngineSpec)

    @classmethod
    def get_db_engine_spec_for_backend(
        cls, backend: str
    ) -> Type[db_engine_specs.BaseEngineSpec]:
        return db_engine_specs.engines.get(backend, db_engine_specs.BaseEngineSpec)

    def grains(self) -> Tuple[TimeGrain, ...]:
        """Defines time granularity database-specific expressions.

        The idea here is to make it easy for users to change the time grain
        from a datetime (maybe the source grain is arbitrary timestamps, daily
        or 5 minutes increments) to another, "truncated" datetime. Since
        each database has slightly different but similar datetime functions,
        this allows a mapping between database engines and actual functions.
        """
        return self.db_engine_spec.get_time_grains()

    def get_extra(self) -> Dict[str, Any]:
        return self.db_engine_spec.get_extra_params(self)

    def get_encrypted_extra(self) -> Dict[str, Any]:
        encrypted_extra = {}
        if self.encrypted_extra:
            try:
                encrypted_extra = json.loads(self.encrypted_extra)
            except json.JSONDecodeError as ex:
                logger.error(ex)
                raise ex
        return encrypted_extra

    def get_table(self, table_name: str, schema: Optional[str] = None) -> Table:
        extra = self.get_extra()
        meta = MetaData(**extra.get("metadata_params", {}))
        return Table(
            table_name,
            meta,
            schema=schema or None,
            autoload=True,
            autoload_with=self.get_sqla_engine(),
        )

    def get_table_comment(
        self, table_name: str, schema: Optional[str] = None
    ) -> Optional[str]:
        return self.db_engine_spec.get_table_comment(self.inspector, table_name, schema)

    def get_columns(
        self, table_name: str, schema: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.db_engine_spec.get_columns(self.inspector, table_name, schema)

    def get_indexes(
        self, table_name: str, schema: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        indexes = self.inspector.get_indexes(table_name, schema)
        return self.db_engine_spec.normalize_indexes(indexes)

    def get_pk_constraint(
        self, table_name: str, schema: Optional[str] = None
    ) -> Dict[str, Any]:
        return self.inspector.get_pk_constraint(table_name, schema)

    def get_foreign_keys(
        self, table_name: str, schema: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.inspector.get_foreign_keys(table_name, schema)

    def get_schema_access_for_csv_upload(  # pylint: disable=invalid-name
        self,
    ) -> List[str]:
        allowed_databases = self.get_extra().get("schemas_allowed_for_csv_upload", [])
        if hasattr(g, "user"):
            extra_allowed_databases = config["ALLOWED_USER_CSV_SCHEMA_FUNC"](
                self, g.user
            )
            allowed_databases += extra_allowed_databases
        return sorted(set(allowed_databases))

    @property
    def sqlalchemy_uri_decrypted(self) -> str:
        conn = sa.engine.url.make_url(self.sqlalchemy_uri)
        if custom_password_store:
            conn.password = custom_password_store(conn)
        else:
            conn.password = self.password
        return str(conn)

    @property
    def sql_url(self) -> str:
        return f"/superset/sql/{self.id}/"

    @hybrid_property
    def perm(self) -> str:
        return f"[{self.project_name}].(id:{self.id})"

    @perm.expression  # type: ignore
    def perm(cls) -> str:  # pylint: disable=no-self-argument
        return (
            "[" + cls.project_name + "].(id:" + expression.cast(cls.id, String) + ")"
        )

    def get_perm(self) -> str:
        return self.perm  # type: ignore

    def has_table(self, table: Table) -> bool:
        engine = self.get_sqla_engine()
        return engine.has_table(table.table_name, table.schema or None)

    def has_table_by_name(self, table_name: str, schema: Optional[str] = None) -> bool:
        engine = self.get_sqla_engine()
        return engine.has_table(table_name, schema)

    @utils.memoized
    def get_dialect(self) -> Dialect:
        sqla_url = url.make_url(self.sqlalchemy_uri_decrypted)
        return sqla_url.get_dialect()()  # pylint: disable=no-member

sa.event.listen(PlaidProject, "after_insert", security_manager.set_perm)
sa.event.listen(PlaidProject, "after_update", security_manager.set_perm)


class PlaidColumn(Model, BaseColumn):
    """ORM object for table columns, each table can have multiple columns"""

    __tablename__ = "plaid_columns"
    __table_args__ = (UniqueConstraint("table_id", "column_name"),)
    table_id = Column(Integer, ForeignKey("plaid_tables.id"))
    table = relationship(
        "PlaidTable",
        backref=backref("columns", cascade="all, delete-orphan"),
        foreign_keys=[table_id],
    )
    is_dttm = Column(Boolean, default=False)
    expression = Column(Text)
    python_date_format = Column(String(255))

    export_fields = [
        "table_id",
        "column_name",
        "verbose_name",
        "is_dttm",
        "is_active",
        "type",
        "groupby",
        "filterable",
        "expression",
        "description",
        "python_date_format",
    ]

    update_from_object_fields = [s for s in export_fields if s not in ("table_id",)]
    export_parent = "table"

    @property
    def is_numeric(self) -> bool:
        """
        Check if the column has a numeric datatype.
        """
        db_engine_spec = self.table.project.db_engine_spec
        return db_engine_spec.is_db_column_type_match(
            self.type, utils.DbColumnType.NUMERIC
        )

    @property
    def is_string(self) -> bool:
        """
        Check if the column has a string datatype.
        """
        db_engine_spec = self.table.project.db_engine_spec
        return db_engine_spec.is_db_column_type_match(
            self.type, utils.DbColumnType.STRING
        )

    @property
    def is_temporal(self) -> bool:
        """
        Check if the column has a temporal datatype. If column has been set as
        temporal/non-temporal (`is_dttm` is True or False respectively), return that
        value. This usually happens during initial metadata fetching or when a column
        is manually set as temporal (for this `python_date_format` needs to be set).
        """
        if self.is_dttm is not None:
            return self.is_dttm
        db_engine_spec = self.table.project.db_engine_spec
        return db_engine_spec.is_db_column_type_match(
            self.type, utils.DbColumnType.TEMPORAL
        )

    def get_sqla_col(self, label: Optional[str] = None) -> Column:
        label = label or self.column_name
        if self.expression:
            col = literal_column(self.expression)
        else:
            db_engine_spec = self.table.project.db_engine_spec
            type_ = db_engine_spec.get_sqla_column_type(self.type)
            col = column(self.column_name, type_=type_)
        col = self.table.make_sqla_column_compatible(col, label)
        return col

    @property
    def datasource(self) -> RelationshipProperty:
        return self.table

    def get_time_filter(
        self,
        start_dttm: DateTime,
        end_dttm: DateTime,
        time_range_endpoints: Optional[
            Tuple[utils.TimeRangeEndpoint, utils.TimeRangeEndpoint]
        ],
    ) -> ColumnElement:
        col = self.get_sqla_col(label="__time")
        l = []
        if start_dttm:
            l.append(
                col >= text(self.dttm_sql_literal(start_dttm, time_range_endpoints))
            )
        if end_dttm:
            if (
                time_range_endpoints
                and time_range_endpoints[1] == utils.TimeRangeEndpoint.EXCLUSIVE
            ):
                l.append(
                    col < text(self.dttm_sql_literal(end_dttm, time_range_endpoints))
                )
            else:
                l.append(col <= text(self.dttm_sql_literal(end_dttm, None)))
        return and_(*l)

    def get_timestamp_expression(
        self, time_grain: Optional[str], label: Optional[str] = None
    ) -> Union[TimestampExpression, Label]:
        """
        Return a SQLAlchemy Core element representation of self to be used in a query.

        :param time_grain: Optional time grain, e.g. P1Y
        :param label: alias/label that column is expected to have
        :return: A TimeExpression object wrapped in a Label if supported by db
        """
        label = label or utils.DTTM_ALIAS

        project = self.table.project
        pdf = self.python_date_format
        is_epoch = pdf in ("epoch_s", "epoch_ms")
        if not self.expression and not time_grain and not is_epoch:
            sqla_col = column(self.column_name, type_=DateTime)
            return self.table.make_sqla_column_compatible(sqla_col, label)
        if self.expression:
            col = literal_column(self.expression)
        else:
            col = column(self.column_name)
        time_expr = project.db_engine_spec.get_timestamp_expr(
            col, pdf, time_grain, self.type
        )
        return self.table.make_sqla_column_compatible(time_expr, label)

    @classmethod
    def import_obj(cls, i_column: "PlaidColumn") -> "PlaidColumn":
        def lookup_obj(lookup_column: PlaidColumn) -> PlaidColumn:
            return (
                db.session.query(PlaidColumn)
                .filter(
                    PlaidColumn.table_id == lookup_column.table_id,
                    PlaidColumn.column_name == lookup_column.column_name,
                )
                .first()
            )

        return import_datasource.import_simple_obj(db.session, i_column, lookup_obj)

    def dttm_sql_literal(
        self,
        dttm: DateTime,
        time_range_endpoints: Optional[
            Tuple[utils.TimeRangeEndpoint, utils.TimeRangeEndpoint]
        ],
    ) -> str:
        """Convert datetime object to a SQL expression string"""
        sql = (
            self.table.project.db_engine_spec.convert_dttm(self.type, dttm)
            if self.type
            else None
        )

        if sql:
            return sql

        tf = self.python_date_format

        # Fallback to the default format (if defined) only if the SIP-15 time range
        # endpoints, i.e., [start, end) are enabled.
        if not tf and time_range_endpoints == (
            utils.TimeRangeEndpoint.INCLUSIVE,
            utils.TimeRangeEndpoint.EXCLUSIVE,
        ):
            tf = (
                self.table.project.get_extra()
                .get("python_date_format_by_column_name", {})
                .get(self.column_name)
            )

        if tf:
            if tf in ["epoch_ms", "epoch_s"]:
                seconds_since_epoch = int(dttm.timestamp())
                if tf == "epoch_s":
                    return str(seconds_since_epoch)
                return str(seconds_since_epoch * 1000)
            return f"'{dttm.strftime(tf)}'"

        # TODO(john-bodley): SIP-15 will explicitly require a type conversion.
        return f"""'{dttm.strftime("%Y-%m-%d %H:%M:%S.%f")}'"""

    @property
    def data(self) -> Dict[str, Any]:
        attrs = (
            "id",
            "column_name",
            "verbose_name",
            "description",
            "expression",
            "filterable",
            "groupby",
            "is_dttm",
            "type",
            "python_date_format",
        )
        return {s: getattr(self, s) for s in attrs if hasattr(self, s)}


class PlaidMetric(Model, BaseMetric):
    """ORM object for metrics, each table can have multiple metrics"""

    __tablename__ = "plaid_metrics"
    __table_args__ = (UniqueConstraint("table_id", "metric_name"),)
    table_id = Column(Integer, ForeignKey("plaid_tables.id"))
    table = relationship(
        "PlaidTable",
        backref=backref("metrics", cascade="all, delete-orphan"),
        foreign_keys=[table_id],
    )
    expression = Column(Text, nullable=False)
    extra = Column(Text)

    export_fields = [
        "metric_name",
        "verbose_name",
        "metric_type",
        "table_id",
        "expression",
        "description",
        "d3format",
        "extra",
        "warning_text",
    ]
    update_from_object_fields = list(
        [s for s in export_fields if s not in ("table_id",)]
    )
    export_parent = "table"

    def get_sqla_col(self, label: Optional[str] = None) -> Column:
        label = label or self.metric_name
        sqla_col = literal_column(self.expression)
        return self.table.make_sqla_column_compatible(sqla_col, label)

    @property
    def perm(self) -> Optional[str]:
        return (
            ("{parent_name}.[{obj.metric_name}](id:{obj.id})").format(
                obj=self, parent_name=self.table.full_name
            )
            if self.table
            else None
        )

    def get_perm(self) -> Optional[str]:
        return self.perm

    @classmethod
    def import_obj(cls, i_metric: "PlaidMetric") -> "PlaidMetric":
        def lookup_obj(lookup_metric: PlaidMetric) -> PlaidMetric:
            return (
                db.session.query(PlaidMetric)
                .filter(
                    PlaidMetric.table_id == lookup_metric.table_id,
                    PlaidMetric.metric_name == lookup_metric.metric_name,
                )
                .first()
            )

        return import_datasource.import_simple_obj(db.session, i_metric, lookup_obj)

    def get_extra_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.extra)
        except (TypeError, json.JSONDecodeError):
            return {}

    @property
    def is_certified(self) -> bool:
        return bool(self.get_extra_dict().get("certification"))

    @property
    def certified_by(self) -> Optional[str]:
        return self.get_extra_dict().get("certification", {}).get("certified_by")

    @property
    def certification_details(self) -> Optional[str]:
        return self.get_extra_dict().get("certification", {}).get("details")

    @property
    def data(self) -> Dict[str, Any]:
        attrs = ("is_certified", "certified_by", "certification_details")
        attr_dict = {s: getattr(self, s) for s in attrs}

        attr_dict.update(super().data)
        return attr_dict


plaidtable_user = Table(
    "plaidtable_user",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("ab_user.id")),
    Column("table_id", Integer, ForeignKey("plaid_tables.id")),
)


class PlaidTable(  # pylint: disable=too-many-public-methods,too-many-instance-attributes
    Model, BaseDatasource
):

    """An ORM object for SqlAlchemy table references"""

    type = "plaid"
    query_language = "sql"
    is_rls_supported = True
    metric_class = PlaidMetric
    column_class = PlaidColumn
    owner_class = security_manager.user_model

    __tablename__ = "plaid_tables"
    __table_args__ = (UniqueConstraint("project_id", "table_name"),)

    table_name = Column(String(250), nullable=False)
    base_table_name = Column(String(250))
    main_dttm_col = Column(String(250))
    project_id = Column(String(250), ForeignKey("plaid_projects.uuid"), nullable=False)
    fetch_values_predicate = Column(String(1000))
    owners = relationship(owner_class, secondary=plaidtable_user, backref="plaid_tables")
    project = relationship(
        "PlaidProject",
        backref=backref("plaid_tables", cascade="all, delete-orphan"),
        foreign_keys=[project_id],
    )
    schema = Column(String(255))
    sql = Column(Text)
    is_sqllab_view = Column(Boolean, default=False)
    template_params = Column(Text)

    baselink = "plaidtablemodelview"

    export_fields = [
        "table_name",
        "base_table_name",
        "main_dttm_col",
        "description",
        "default_endpoint",
        "project_id",
        "offset",
        "cache_timeout",
        "schema",
        "sql",
        "params",
        "template_params",
        "filter_select_enabled",
        "fetch_values_predicate",
    ]
    update_from_object_fields = [f for f in export_fields if not f == "project_id"]
    export_parent = "project"
    export_children = ["metrics", "columns"]

    sqla_aggregations = {
        "COUNT_DISTINCT": lambda column_name: sa.func.COUNT(sa.distinct(column_name)),
        "COUNT": sa.func.COUNT,
        "SUM": sa.func.SUM,
        "AVG": sa.func.AVG,
        "MIN": sa.func.MIN,
        "MAX": sa.func.MAX,
    }

    def make_sqla_column_compatible(
        self, sqla_col: Column, label: Optional[str] = None
    ) -> Column:
        """Takes a sqlalchemy column object and adds label info if supported by engine.
        :param sqla_col: sqlalchemy column instance
        :param label: alias/label that column is expected to have
        :return: either a sql alchemy column or label instance if supported by engine
        """
        label_expected = label or sqla_col.name
        db_engine_spec = self.project.db_engine_spec
        if db_engine_spec.allows_column_aliases:
            label = db_engine_spec.make_label_compatible(label_expected)
            sqla_col = sqla_col.label(label)
        sqla_col._df_label_expected = label_expected  # pylint: disable=protected-access
        return sqla_col

    def __repr__(self) -> str:
        return self.name

    @property
    def database(self) -> relationship:
        return self.project

    @property
    def changed_by_name(self) -> str:
        if not self.changed_by:
            return ""
        return str(self.changed_by)

    @property
    def changed_by_url(self) -> str:
        if not self.changed_by:
            return ""
        return f"/superset/profile/{self.changed_by.username}"

    @property
    def connection(self) -> str:
        return str(self.project)

    @property
    def description_markeddown(self) -> str:
        return utils.markdown(self.description)

    @property
    def datasource_name(self) -> str:
        return self.table_name

    @property
    def datasource_type(self) -> str:
        return self.type

    @property
    def database_name(self) -> str:
        return self.project.name

    @property
    def uuid(self) -> str:
        return str(self.project)

    @classmethod
    def get_datasource_by_name(
        cls,
        session: Session,
        table_name: str,
        schema: Optional[str],
        project_name: str,
    ) -> Optional["SqlaTable"]:
        schema = schema or None
        query = (
            session.query(cls)
            .join(PlaidProject)
            .filter(cls.table_name == table_name)
            .filter(cls.schema == schema)
            .filter(PlaidProject.name == project_name)
        )
        # Handling schema being '' or None, which is easier to handle
        # in python than in the SQLA query in a multi-dialect way
        for tbl in query.all():
            if schema == (tbl.schema or None):
                return tbl
        return None

    @property
    def link(self) -> Markup:
        name = escape(self.name)
        anchor = f'<a target="_blank" href="{self.explore_url}">{name}</a>'
        return Markup(anchor)

    def get_schema_perm(self) -> Optional[str]:
        """Returns schema permission if present, project one otherwise."""
        return security_manager.get_schema_perm(self.project, self.schema)

    def get_perm(self) -> str:
        return f"[{self.project}].[{self.table_name}](id:{self.id})"

    @property
    def name(self) -> str:
        if not self.schema:
            return self.table_name
        return "{} :: {}".format(self.project, self.table_name)

    @property
    def full_name(self) -> str:
        return utils.get_datasource_full_name(
            self.project, self.table_name, schema=self.schema
        )

    @property
    def dttm_cols(self) -> List[str]:
        l = [c.column_name for c in self.columns if c.is_dttm]
        if self.main_dttm_col and self.main_dttm_col not in l:
            l.append(self.main_dttm_col)
        return l

    @property
    def num_cols(self) -> List[str]:
        return [c.column_name for c in self.columns if c.is_numeric]

    @property
    def any_dttm_col(self) -> Optional[str]:
        cols = self.dttm_cols
        return cols[0] if cols else None

    @property
    def html(self) -> str:
        df = pd.DataFrame((c.column_name, c.type) for c in self.columns)
        df.columns = ["field", "type"]
        return df.to_html(
            index=False,
            classes=("dataframe table table-striped table-bordered " "table-condensed"),
        )

    @property
    def sql_url(self) -> str:
        return self.project.sql_url + "?table_name=" + str(self.table_name)

    def external_metadata(self) -> List[Dict[str, str]]:
        db_engine_spec = self.project.db_engine_spec
        if self.sql:
            engine = self.project.get_sqla_engine(schema=self.schema)
            sql = self.get_template_processor().process_template(self.sql)
            parsed_query = ParsedQuery(sql)
            if not parsed_query.is_readonly():
                raise SupersetSecurityException(
                    SupersetError(
                        error_type=SupersetErrorType.DATASOURCE_SECURITY_ACCESS_ERROR,
                        message=_("Only `SELECT` statements are allowed"),
                        level=ErrorLevel.ERROR,
                    )
                )
            statements = parsed_query.get_statements()
            if len(statements) > 1:
                raise SupersetSecurityException(
                    SupersetError(
                        error_type=SupersetErrorType.DATASOURCE_SECURITY_ACCESS_ERROR,
                        message=_("Only single queries supported"),
                        level=ErrorLevel.ERROR,
                    )
                )
            # TODO(villebro): refactor to use same code that's used by
            #  sql_lab.py:execute_sql_statements
            with closing(engine.raw_connection()) as conn:
                with closing(conn.cursor()) as cursor:
                    query = self.project.apply_limit_to_sql(statements[0])
                    db_engine_spec.execute(cursor, query)
                    result = db_engine_spec.fetch_data(cursor, limit=1)
                    result_set = SupersetResultSet(
                        result, cursor.description, db_engine_spec
                    )
                    cols = result_set.columns
        else:
            db_dialect = self.project.get_dialect()
            cols = self.project.get_columns(
                self.table_name, schema=self.schema or None
            )
            for col in cols:
                try:
                    if isinstance(col["type"], TypeEngine):
                        col["type"] = db_engine_spec.column_datatype_to_string(
                            col["type"], db_dialect
                        )
                except CompileError:
                    col["type"] = "UNKNOWN"
        return cols

    @property
    def time_column_grains(self) -> Dict[str, Any]:
        return {
            "time_columns": self.dttm_cols,
            "time_grains": [grain.name for grain in self.project.grains()],
        }

    @property
    def select_star(self) -> Optional[str]:
        # show_cols and latest_partition set to false to avoid
        # the expensive cost of inspecting the DB
        return self.project.select_star(
            self.table_name, schema=self.schema, show_cols=False, latest_partition=False
        )

    @property
    def data(self) -> Dict[str, Any]:
        """Data representation of the datasource sent to the frontend"""
        data_ = super().data
        if self.type == "plaid":
            grains = self.project.grains() or []
            if grains:
                grains = [(g.duration, g.name) for g in grains]
            data_["granularity_sqla"] = utils.choicify(self.dttm_cols)
            data_["time_grain_sqla"] = grains
            data_["main_dttm_col"] = self.main_dttm_col
            data_["fetch_values_predicate"] = self.fetch_values_predicate
            data_["template_params"] = self.template_params
            data_["is_sqllab_view"] = self.is_sqllab_view
        return data_

    def values_for_column(self, column_name: str, limit: int = 10000) -> List[Any]:
        """Runs query against sqla to retrieve some
        sample values for the given column.
        """
        cols = {col.column_name: col for col in self.columns}
        target_col = cols[column_name]
        tp = self.get_template_processor()

        qry = (
            select([target_col.get_sqla_col()])
            .select_from(self.get_from_clause(tp))
            .distinct()
        )
        if limit:
            qry = qry.limit(limit)

        if self.fetch_values_predicate:
            tp = self.get_template_processor()
            try:
                qry = qry.where(text(tp.process_template(self.fetch_values_predicate)))
            except TemplateError as ex:
                raise QueryObjectValidationError(
                    _(
                        "Error in jinja expression in fetch values predicate: %(msg)s",
                        msg=ex.message,
                    )
                )

        engine = self.project.get_sqla_engine()
        sql = "{}".format(qry.compile(engine, compile_kwargs={"literal_binds": True}))
        sql = self.mutate_query_from_config(sql)

        df = pd.read_sql_query(sql=sql, con=engine)
        return df[column_name].to_list()

    def mutate_query_from_config(self, sql: str) -> str:
        """Apply config's SQL_QUERY_MUTATOR

        Typically adds comments to the query with context"""
        sql_query_mutator = config["SQL_QUERY_MUTATOR"]
        if sql_query_mutator:
            username = utils.get_username()
            sql = sql_query_mutator(sql, username, security_manager, self.project)
        return sql

    def get_template_processor(self, **kwargs: Any) -> BaseTemplateProcessor:
        return get_template_processor(table=self, database=self.project, **kwargs)

    def get_query_str_extended(self, query_obj: QueryObjectDict) -> QueryStringExtended:
        sqlaq = self.get_sqla_query(**query_obj)
        sql = self.project.compile_sqla_query(sqlaq.sqla_query)
        logger.info(sql)
        sql = sqlparse.format(sql, reindent=True)
        sql = self.mutate_query_from_config(sql)
        return QueryStringExtended(
            labels_expected=sqlaq.labels_expected, sql=sql, prequeries=sqlaq.prequeries
        )

    def get_query_str(self, query_obj: QueryObjectDict) -> str:
        query_str_ext = self.get_query_str_extended(query_obj)
        all_queries = query_str_ext.prequeries + [query_str_ext.sql]
        return ";\n\n".join(all_queries) + ";"

    def get_sqla_table(self) -> table:
        tbl = table(self.table_name)
        if self.schema:
            tbl.schema = self.schema
        return tbl

    def get_from_clause(
        self, template_processor: Optional[BaseTemplateProcessor] = None
    ) -> Union[table, TextAsFrom]:
        # Supporting arbitrary SQL statements in place of tables
        if self.sql:
            from_sql = self.sql
            if template_processor:
                try:
                    from_sql = template_processor.process_template(from_sql)
                except TemplateError as ex:
                    raise QueryObjectValidationError(
                        _(
                            "Error in jinja expression in FROM clause: %(msg)s",
                            msg=ex.message,
                        )
                    )

            from_sql = sqlparse.format(from_sql, strip_comments=True)
            if len(sqlparse.split(from_sql)) > 1:
                raise QueryObjectValidationError(
                    _("Virtual dataset query cannot consist of multiple statements")
                )
            parsed_query = ParsedQuery(from_sql)
            if not (parsed_query.is_unknown() or parsed_query.is_readonly()):
                raise QueryObjectValidationError(
                    _("Virtual dataset query must be read-only")
                )
            return TextAsFrom(sa.text(from_sql), []).alias("expr_qry")
        return self.get_sqla_table()

    def adhoc_metric_to_sqla(
        self, metric: Dict[str, Any], columns_by_name: Dict[str, Any]
    ) -> Optional[Column]:
        """
        Turn an adhoc metric into a sqlalchemy column.

        :param dict metric: Adhoc metric definition
        :param dict columns_by_name: Columns for the current table
        :returns: The metric defined as a sqlalchemy column
        :rtype: sqlalchemy.sql.column
        """
        expression_type = metric.get("expressionType")
        label = utils.get_metric_name(metric)

        if expression_type == utils.AdhocMetricExpressionType.SIMPLE:
            column_name = metric["column"].get("column_name")
            table_column = columns_by_name.get(column_name)
            if table_column:
                sqla_column = table_column.get_sqla_col()
            else:
                sqla_column = column(column_name)
            sqla_metric = self.sqla_aggregations[metric["aggregate"]](sqla_column)
        elif expression_type == utils.AdhocMetricExpressionType.SQL:
            sqla_metric = literal_column(metric.get("sqlExpression"))
        else:
            return None

        return self.make_sqla_column_compatible(sqla_metric, label)

    def _get_sqla_row_level_filters(
        self, template_processor: BaseTemplateProcessor
    ) -> List[str]:
        """
        Return the appropriate row level security filters for
        this table and the current user.

        :param BaseTemplateProcessor template_processor: The template
        processor to apply to the filters.
        :returns: A list of SQL clauses to be ANDed together.
        :rtype: List[str]
        """
        filters_grouped: Dict[Union[int, str], List[str]] = defaultdict(list)
        try:
            for filter_ in security_manager.get_rls_filters(self):
                clause = text(
                    f"({template_processor.process_template(filter_.clause)})"
                )
                filters_grouped[filter_.group_key or filter_.id].append(clause)
            return [or_(*clauses) for clauses in filters_grouped.values()]
        except TemplateError as ex:
            raise QueryObjectValidationError(
                _("Error in jinja expression in RLS filters: %(msg)s", msg=ex.message,)
            )

    def get_sqla_query(  # pylint: disable=too-many-arguments,too-many-locals,too-many-branches,too-many-statements
        self,
        metrics: List[Metric],
        granularity: str,
        from_dttm: Optional[datetime],
        to_dttm: Optional[datetime],
        columns: Optional[List[str]] = None,
        groupby: Optional[List[str]] = None,
        filter: Optional[  # pylint: disable=redefined-builtin
            List[Dict[str, Any]]
        ] = None,
        is_timeseries: bool = True,
        timeseries_limit: int = 15,
        timeseries_limit_metric: Optional[Metric] = None,
        row_limit: Optional[int] = None,
        row_offset: Optional[int] = None,
        inner_from_dttm: Optional[datetime] = None,
        inner_to_dttm: Optional[datetime] = None,
        orderby: Optional[List[Tuple[ColumnElement, bool]]] = None,
        extras: Optional[Dict[str, Any]] = None,
        order_desc: bool = True,
    ) -> PlaidQuery:
        """Querying any sqla table from this common interface"""
        template_kwargs = {
            "from_dttm": from_dttm,
            "groupby": groupby,
            "metrics": metrics,
            "row_limit": row_limit,
            "row_offset": row_offset,
            "to_dttm": to_dttm,
            "filter": filter,
            "columns": {col.column_name: col for col in self.columns},
        }
        is_sip_38 = is_feature_enabled("SIP_38_VIZ_REARCHITECTURE")
        template_kwargs.update(self.template_params_dict)
        extra_cache_keys: List[Any] = []
        template_kwargs["extra_cache_keys"] = extra_cache_keys
        template_processor = self.get_template_processor(**template_kwargs)
        db_engine_spec = self.project.db_engine_spec
        prequeries: List[str] = []

        orderby = orderby or []

        # For backward compatibility
        if granularity not in self.dttm_cols:
            granularity = self.main_dttm_col

        # Database spec supports join-free timeslot grouping
        time_groupby_inline = db_engine_spec.time_groupby_inline

        columns_by_name: Dict[str, PlaidColumn] = {
            col.column_name: col for col in self.columns
        }
        metrics_by_name: Dict[str, PlaidMetric] = {m.metric_name: m for m in self.metrics}

        if not granularity and is_timeseries:
            raise QueryObjectValidationError(
                _(
                    "Datetime column not provided as part table configuration "
                    "and is required by this type of chart"
                )
            )
        if (
            not metrics
            and not columns
            and (is_sip_38 or (not is_sip_38 and not groupby))
        ):
            raise QueryObjectValidationError(_("Empty query?"))
        metrics_exprs: List[ColumnElement] = []
        for metric in metrics:
            if utils.is_adhoc_metric(metric):
                assert isinstance(metric, dict)
                metrics_exprs.append(self.adhoc_metric_to_sqla(metric, columns_by_name))
            elif isinstance(metric, str) and metric in metrics_by_name:
                metrics_exprs.append(metrics_by_name[metric].get_sqla_col())
            else:
                raise QueryObjectValidationError(
                    _("Metric '%(metric)s' does not exist", metric=metric)
                )
        if metrics_exprs:
            main_metric_expr = metrics_exprs[0]
        else:
            main_metric_expr, label = literal_column("COUNT(*)"), "ccount"
            main_metric_expr = self.make_sqla_column_compatible(main_metric_expr, label)

        select_exprs: List[Column] = []
        groupby_exprs_sans_timestamp = OrderedDict()

        assert extras is not None
        if (is_sip_38 and metrics and columns) or (not is_sip_38 and groupby):
            # dedup columns while preserving order
            columns_ = columns if is_sip_38 else groupby
            assert columns_
            groupby = list(dict.fromkeys(columns_))

            select_exprs = []
            for selected in groupby:
                # if groupby field/expr equals granularity field/expr
                if selected == granularity:
                    time_grain = extras.get("time_grain_sqla")
                    sqla_col = columns_by_name[selected]
                    outer = sqla_col.get_timestamp_expression(time_grain, selected)
                # if groupby field equals a selected column
                elif selected in columns_by_name:
                    outer = columns_by_name[selected].get_sqla_col()
                else:
                    outer = literal_column(f"({selected})")
                    outer = self.make_sqla_column_compatible(outer, selected)

                groupby_exprs_sans_timestamp[outer.name] = outer
                select_exprs.append(outer)
        elif columns:
            for selected in columns:
                select_exprs.append(
                    columns_by_name[selected].get_sqla_col()
                    if selected in columns_by_name
                    else self.make_sqla_column_compatible(literal_column(selected))
                )
            metrics_exprs = []

        time_range_endpoints = extras.get("time_range_endpoints")
        groupby_exprs_with_timestamp = OrderedDict(groupby_exprs_sans_timestamp.items())
        if granularity:
            dttm_col = columns_by_name[granularity]
            time_grain = extras.get("time_grain_sqla")
            time_filters = []

            if is_timeseries:
                timestamp = dttm_col.get_timestamp_expression(time_grain)
                select_exprs += [timestamp]
                groupby_exprs_with_timestamp[timestamp.name] = timestamp

            # Use main dttm column to support index with secondary dttm columns.
            if (
                db_engine_spec.time_secondary_columns
                and self.main_dttm_col in self.dttm_cols
                and self.main_dttm_col != dttm_col.column_name
            ):
                time_filters.append(
                    columns_by_name[self.main_dttm_col].get_time_filter(
                        from_dttm, to_dttm, time_range_endpoints
                    )
                )
            time_filters.append(
                dttm_col.get_time_filter(from_dttm, to_dttm, time_range_endpoints)
            )

        select_exprs += metrics_exprs

        labels_expected = [
            c._df_label_expected  # pylint: disable=protected-access
            for c in select_exprs
        ]

        select_exprs = db_engine_spec.make_select_compatible(
            groupby_exprs_with_timestamp.values(), select_exprs
        )
        qry = sa.select(select_exprs)

        tbl = self.get_from_clause(template_processor)

        if (is_sip_38 and metrics) or (not is_sip_38 and not columns):
            qry = qry.group_by(*groupby_exprs_with_timestamp.values())

        where_clause_and = []
        having_clause_and = []

        for flt in filter:  # type: ignore
            if not all([flt.get(s) for s in ["col", "op"]]):
                continue
            col = flt["col"]
            op = flt["op"].upper()
            col_obj = columns_by_name.get(col)
            if col_obj:
                is_list_target = op in (
                    utils.FilterOperator.IN.value,
                    utils.FilterOperator.NOT_IN.value,
                )
                eq = self.filter_values_handler(
                    values=flt.get("val"),
                    target_column_is_numeric=col_obj.is_numeric,
                    is_list_target=is_list_target,
                )
                if op in (
                    utils.FilterOperator.IN.value,
                    utils.FilterOperator.NOT_IN.value,
                ):
                    cond = col_obj.get_sqla_col().in_(eq)
                    if isinstance(eq, str) and NULL_STRING in eq:
                        cond = or_(
                            cond,
                            col_obj.get_sqla_col()  # pylint: disable=singleton-comparison
                            == None,
                        )
                    if op == utils.FilterOperator.NOT_IN.value:
                        cond = ~cond
                    where_clause_and.append(cond)
                else:
                    if col_obj.is_numeric:
                        eq = utils.cast_to_num(flt["val"])
                    if op == utils.FilterOperator.EQUALS.value:
                        where_clause_and.append(col_obj.get_sqla_col() == eq)
                    elif op == utils.FilterOperator.NOT_EQUALS.value:
                        where_clause_and.append(col_obj.get_sqla_col() != eq)
                    elif op == utils.FilterOperator.GREATER_THAN.value:
                        where_clause_and.append(col_obj.get_sqla_col() > eq)
                    elif op == utils.FilterOperator.LESS_THAN.value:
                        where_clause_and.append(col_obj.get_sqla_col() < eq)
                    elif op == utils.FilterOperator.GREATER_THAN_OR_EQUALS.value:
                        where_clause_and.append(col_obj.get_sqla_col() >= eq)
                    elif op == utils.FilterOperator.LESS_THAN_OR_EQUALS.value:
                        where_clause_and.append(col_obj.get_sqla_col() <= eq)
                    elif op == utils.FilterOperator.LIKE.value:
                        where_clause_and.append(col_obj.get_sqla_col().like(eq))
                    elif op == utils.FilterOperator.IS_NULL.value:
                        where_clause_and.append(
                            col_obj.get_sqla_col()  # pylint: disable=singleton-comparison
                            == None
                        )
                    elif op == utils.FilterOperator.IS_NOT_NULL.value:
                        where_clause_and.append(
                            col_obj.get_sqla_col()  # pylint: disable=singleton-comparison
                            != None
                        )
                    else:
                        raise QueryObjectValidationError(
                            _("Invalid filter operation type: %(op)s", op=op)
                        )
        if config["ENABLE_ROW_LEVEL_SECURITY"]:
            where_clause_and += self._get_sqla_row_level_filters(template_processor)
        if extras:
            where = extras.get("where")
            if where:
                try:
                    where = template_processor.process_template(where)
                except TemplateError as ex:
                    raise QueryObjectValidationError(
                        _(
                            "Error in jinja expression in WHERE clause: %(msg)s",
                            msg=ex.message,
                        )
                    )
                where_clause_and += [sa.text("({})".format(where))]
            having = extras.get("having")
            if having:
                try:
                    having = template_processor.process_template(having)
                except TemplateError as ex:
                    raise QueryObjectValidationError(
                        _(
                            "Error in jinja expression in HAVING clause: %(msg)s",
                            msg=ex.message,
                        )
                    )
                having_clause_and += [sa.text("({})".format(having))]
        if granularity:
            qry = qry.where(and_(*(time_filters + where_clause_and)))
        else:
            qry = qry.where(and_(*where_clause_and))
        qry = qry.having(and_(*having_clause_and))

        # To ensure correct handling of the ORDER BY labeling we need to reference the
        # metric instance if defined in the SELECT clause.
        metrics_exprs_by_label = {
            m._label: m for m in metrics_exprs  # pylint: disable=protected-access
        }

        for col, ascending in orderby:
            direction = asc if ascending else desc
            if utils.is_adhoc_metric(col):
                col = self.adhoc_metric_to_sqla(col, columns_by_name)
            elif col in columns_by_name:
                col = columns_by_name[col].get_sqla_col()

            if isinstance(col, Label):
                label = col._label  # pylint: disable=protected-access
                if label in metrics_exprs_by_label:
                    col = metrics_exprs_by_label[label]

            qry = qry.order_by(direction(col))

        if row_limit:
            qry = qry.limit(row_limit)
        if row_offset:
            qry = qry.offset(row_offset)

        if (
            is_timeseries  # pylint: disable=too-many-boolean-expressions
            and timeseries_limit
            and not time_groupby_inline
            and ((is_sip_38 and columns) or (not is_sip_38 and groupby))
        ):
            if self.project.db_engine_spec.allows_joins:
                # some sql dialects require for order by expressions
                # to also be in the select clause -- others, e.g. vertica,
                # require a unique inner alias
                inner_main_metric_expr = self.make_sqla_column_compatible(
                    main_metric_expr, "mme_inner__"
                )
                inner_groupby_exprs = []
                inner_select_exprs = []
                for gby_name, gby_obj in groupby_exprs_sans_timestamp.items():
                    inner = self.make_sqla_column_compatible(gby_obj, gby_name + "__")
                    inner_groupby_exprs.append(inner)
                    inner_select_exprs.append(inner)

                inner_select_exprs += [inner_main_metric_expr]
                subq = select(inner_select_exprs).select_from(tbl)
                inner_time_filter = dttm_col.get_time_filter(
                    inner_from_dttm or from_dttm,
                    inner_to_dttm or to_dttm,
                    time_range_endpoints,
                )
                subq = subq.where(and_(*(where_clause_and + [inner_time_filter])))
                subq = subq.group_by(*inner_groupby_exprs)

                ob = inner_main_metric_expr
                if timeseries_limit_metric:
                    ob = self._get_timeseries_orderby(
                        timeseries_limit_metric, metrics_by_name, columns_by_name
                    )
                direction = desc if order_desc else asc
                subq = subq.order_by(direction(ob))
                subq = subq.limit(timeseries_limit)

                on_clause = []
                for gby_name, gby_obj in groupby_exprs_sans_timestamp.items():
                    # in this case the column name, not the alias, needs to be
                    # conditionally mutated, as it refers to the column alias in
                    # the inner query
                    col_name = db_engine_spec.make_label_compatible(gby_name + "__")
                    on_clause.append(gby_obj == column(col_name))

                tbl = tbl.join(subq.alias(), and_(*on_clause))
            else:
                if timeseries_limit_metric:
                    orderby = [
                        (
                            self._get_timeseries_orderby(
                                timeseries_limit_metric,
                                metrics_by_name,
                                columns_by_name,
                            ),
                            False,
                        )
                    ]

                # run prequery to get top groups
                prequery_obj = {
                    "is_timeseries": False,
                    "row_limit": timeseries_limit,
                    "metrics": metrics,
                    "granularity": granularity,
                    "from_dttm": inner_from_dttm or from_dttm,
                    "to_dttm": inner_to_dttm or to_dttm,
                    "filter": filter,
                    "orderby": orderby,
                    "extras": extras,
                    "columns": columns,
                    "order_desc": True,
                }
                if not is_sip_38:
                    prequery_obj["groupby"] = groupby

                result = self.query(prequery_obj)
                prequeries.append(result.query)
                dimensions = [
                    c
                    for c in result.df.columns
                    if c not in metrics and c in groupby_exprs_sans_timestamp
                ]
                top_groups = self._get_top_groups(
                    result.df, dimensions, groupby_exprs_sans_timestamp
                )
                qry = qry.where(top_groups)
        return PlaidQuery(
            extra_cache_keys=extra_cache_keys,
            labels_expected=labels_expected,
            sqla_query=qry.select_from(tbl),
            prequeries=prequeries,
        )

    def _get_timeseries_orderby(
        self,
        timeseries_limit_metric: Metric,
        metrics_by_name: Dict[str, PlaidMetric],
        columns_by_name: Dict[str, PlaidColumn],
    ) -> Optional[Column]:
        if utils.is_adhoc_metric(timeseries_limit_metric):
            assert isinstance(timeseries_limit_metric, dict)
            ob = self.adhoc_metric_to_sqla(timeseries_limit_metric, columns_by_name)
        elif (
            isinstance(timeseries_limit_metric, str)
            and timeseries_limit_metric in metrics_by_name
        ):
            ob = metrics_by_name[timeseries_limit_metric].get_sqla_col()
        else:
            raise QueryObjectValidationError(
                _("Metric '%(metric)s' does not exist", metric=timeseries_limit_metric)
            )

        return ob

    def _get_top_groups(  # pylint: disable=no-self-use
        self,
        df: pd.DataFrame,
        dimensions: List[str],
        groupby_exprs: "OrderedDict[str, Any]",
    ) -> ColumnElement:
        groups = []
        for _unused, row in df.iterrows():
            group = []
            for dimension in dimensions:
                group.append(groupby_exprs[dimension] == row[dimension])
            groups.append(and_(*group))

        return or_(*groups)

    def query(self, query_obj: QueryObjectDict) -> QueryResult:
        qry_start_dttm = datetime.now()
        query_str_ext = self.get_query_str_extended(query_obj)
        sql = query_str_ext.sql
        status = utils.QueryStatus.SUCCESS
        errors = None
        error_message = None

        def mutator(df: pd.DataFrame) -> None:
            """
            Some engines change the case or generate bespoke column names, either by
            default or due to lack of support for aliasing. This function ensures that
            the column names in the DataFrame correspond to what is expected by
            the viz components.

            :param df: Original DataFrame returned by the engine
            """

            labels_expected = query_str_ext.labels_expected
            if df is not None and not df.empty:
                if len(df.columns) != len(labels_expected):
                    raise QueryObjectValidationError(
                        f"For {sql}, df.columns: {df.columns}"
                        f" differs from {labels_expected}"
                    )
                df.columns = labels_expected

        try:
            df = self.project.get_df(sql, self.schema, mutator)
        except Exception as ex:  # pylint: disable=broad-except
            df = pd.DataFrame()
            status = utils.QueryStatus.FAILED
            logger.warning(
                "Query %s on schema %s failed", sql, self.schema, exc_info=True
            )
            db_engine_spec = self.project.db_engine_spec
            errors = db_engine_spec.extract_errors(ex)
            error_message = utils.error_msg_from_exception(ex)

        return QueryResult(
            status=status,
            df=df,
            duration=datetime.now() - qry_start_dttm,
            query=sql,
            errors=errors,
            error_message=error_message,
        )

    def get_sqla_table_object(self) -> Table:
        return self.project.get_table(self.table_name, schema=self.schema)

    def fetch_metadata(self, commit: bool = True) -> MetadataResult:
        """
        Fetches the metadata for the table and merges it in

        :param commit: should the changes be committed or not.
        :return: Tuple with lists of added, removed and modified column names.
        """
        new_columns = self.external_metadata()
        metrics = []
        any_date_col = None
        db_engine_spec = self.project.db_engine_spec
        old_columns = db.session.query(PlaidColumn).filter(PlaidColumn.table == self)

        old_columns_by_name = {col.column_name: col for col in old_columns}
        results = MetadataResult(
            removed=[
                col
                for col in old_columns_by_name
                if col not in {col["name"] for col in new_columns}
            ]
        )

        # clear old columns before adding modified columns back
        self.columns = []
        for col in new_columns:
            old_column = old_columns_by_name.get(col["name"], None)
            if not old_column:
                results.added.append(col["name"])
                new_column = PlaidColumn(
                    column_name=col["name"], type=col["type"], table=self
                )
                new_column.is_dttm = new_column.is_temporal
                db_engine_spec.alter_new_orm_column(new_column)
            else:
                new_column = old_column
                if new_column.type != col["type"]:
                    results.modified.append(col["name"])
                new_column.type = col["type"]
            new_column.groupby = True
            new_column.filterable = True
            self.columns.append(new_column)
            if not any_date_col and new_column.is_temporal:
                any_date_col = col["name"]
        metrics.append(
            PlaidMetric(
                metric_name="count",
                verbose_name="COUNT(*)",
                metric_type="count",
                expression="COUNT(*)",
            )
        )
        if not self.main_dttm_col:
            self.main_dttm_col = any_date_col
        self.add_missing_metrics(metrics)

        # Apply config supplied mutations.
        config["SQLA_TABLE_MUTATOR"](self)

        db.session.merge(self)
        if commit:
            db.session.commit()
        return results

    @classmethod
    def import_obj(
        cls,
        i_datasource: "PlaidTable",
        database_id: Optional[int] = None,
        import_time: Optional[int] = None,
    ) -> int:
        """Imports the datasource from the object to the database.

        Metrics and columns and datasource will be overrided if exists.
        This function can be used to import/export dashboards between multiple
        superset instances. Audit metadata isn't copies over.
        """

        def lookup_sqlatable(table_: "PlaidTable") -> "PlaidTable":
            return (
                db.session.query(PlaidTable)
                .join(PlaidProject)
                .filter(
                    PlaidTable.base_table_name == table_.base_table_name,
                    PlaidTable.schema == table_.schema,
                    PlaidProject.uuid == table_.project_id,
                )
                .first()
            )

        def lookup_project(table_: PlaidTable) -> PlaidProject:
            try:
                return (
                    db.session.query(PlaidProject)
                    .filter_by(uuid=table.project_id)
                    .one()
                )
            except NoResultFound:
                raise DatabaseNotFound(
                    _(
                        "Project '%(name)s' is not found",
                        name=table.params_dict["name"],
                    )
                )

        return import_datasource.import_datasource(
            db.session,
            i_datasource,
            lookup_project,
            lookup_sqlatable,
            import_time,
            database_id,
        )

    @classmethod
    def query_datasources_by_name(
        cls,
        session: Session,
        database: PlaidProject,
        datasource_name: str,
        schema: Optional[str] = None,
    ) -> List["PlaidTable"]:
        query = (
            session.query(cls)
            .filter_by(project_id=database.id)
            .filter_by(table_name=datasource_name)
        )
        if schema:
            query = query.filter_by(schema=schema)
        return query.all()

    @staticmethod
    def default_query(qry: Query) -> Query:
        return qry.filter_by(is_sqllab_view=False)

    def has_extra_cache_key_calls(self, query_obj: QueryObjectDict) -> bool:
        """
        Detects the presence of calls to `ExtraCache` methods in items in query_obj that
        can be templated. If any are present, the query must be evaluated to extract
        additional keys for the cache key. This method is needed to avoid executing the
        template code unnecessarily, as it may contain expensive calls, e.g. to extract
        the latest partition of a database.

        :param query_obj: query object to analyze
        :return: True if there are call(s) to an `ExtraCache` method, False otherwise
        """
        templatable_statements: List[str] = []
        if self.sql:
            templatable_statements.append(self.sql)
        if self.fetch_values_predicate:
            templatable_statements.append(self.fetch_values_predicate)
        extras = query_obj.get("extras", {})
        if "where" in extras:
            templatable_statements.append(extras["where"])
        if "having" in extras:
            templatable_statements.append(extras["having"])
        if config["ENABLE_ROW_LEVEL_SECURITY"] and self.is_rls_supported:
            templatable_statements += [
                f.clause for f in security_manager.get_rls_filters(self)
            ]
        for statement in templatable_statements:
            if ExtraCache.regex.search(statement):
                return True
        return False

    def get_extra_cache_keys(self, query_obj: QueryObjectDict) -> List[Hashable]:
        """
        The cache key of a SqlaTable needs to consider any keys added by the parent
        class and any keys added via `ExtraCache`.

        :param query_obj: query object to analyze
        :return: The extra cache keys
        """
        extra_cache_keys = super().get_extra_cache_keys(query_obj)
        if self.has_extra_cache_key_calls(query_obj):
            sqla_query = self.get_sqla_query(**query_obj)
            extra_cache_keys += sqla_query.extra_cache_keys
        return extra_cache_keys


sa.event.listen(PlaidTable, "after_insert", security_manager.set_perm)
sa.event.listen(PlaidTable, "after_update", security_manager.set_perm)


# RLSFilterRoles = Table(
#     "rls_filter_roles",
#     metadata,
#     Column("id", Integer, primary_key=True),
#     Column("role_id", Integer, ForeignKey("ab_role.id"), nullable=False),
#     Column("rls_filter_id", Integer, ForeignKey("row_level_security_filters.id")),
# )


# class RowLevelSecurityFilter(Model, AuditMixinNullable):
#     """
#     Custom where clauses attached to Tables and Roles.
#     """

#     __tablename__ = "row_level_security_filters"
#     id = Column(Integer, primary_key=True)
#     roles = relationship(
#         security_manager.role_model,
#         secondary=RLSFilterRoles,
#         backref="row_level_security_filters",
#     )

#     table_id = Column(Integer, ForeignKey("tables.id"), nullable=False)
#     table = relationship(SqlaTable, backref="row_level_security_filters")
#     clause = Column(Text, nullable=False)
