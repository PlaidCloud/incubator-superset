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
from collections import OrderedDict
from contextlib import closing
from copy import copy, deepcopy
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type
import json
import logging
import re
import textwrap
from typing import Any, Dict, List, NamedTuple, Optional, Union

from flask import escape, g, Markup, request
from flask_appbuilder import Model
from flask_babel import lazy_gettext as _
import numpy
import pandas as pd
import sqlalchemy as sqla
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
from sqlalchemy.orm import backref, relationship
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.pool import NullPool
from sqlalchemy.schema import UniqueConstraint
from sqlalchemy.sql import column, literal_column, table, text
from sqlalchemy.sql.expression import Label, Select, TextAsFrom
import sqlparse

from superset import app, db, db_engine_specs, is_feature_enabled, security_manager
from superset.connectors.base.models import BaseColumn, BaseDatasource, BaseMetric
from superset.db_engine_specs.base import TimeGrain, TimestampExpression
from superset.exceptions import DatabaseNotFound
from superset.jinja_context import get_template_processor
from superset.models.annotations import Annotation
from superset.models.helpers import QueryResult, AuditMixinNullable, ImportMixin
from superset.utils import cache as cache_util, core as utils, import_datasource
from sqlalchemy_utils import EncryptedType

config = app.config
custom_password_store = config["SQLALCHEMY_CUSTOM_PASSWORD_STORE"]
stats_logger = config.get("STATS_LOGGER")
log_query = config.get("QUERY_LOGGER")
metadata = Model.metadata  # pylint: disable=no-member
logger = logging.getLogger(__name__)

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


hide_schema_names = app.config.get('HIDE_SCHEMA_NAMES', False)


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

    export_fields = (
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
    )

    update_from_object_fields = [s for s in export_fields if s not in ("table_id",)]
    export_parent = "table"

    def get_sqla_col(self, label=None):
        label = label or self.column_name
        if not self.expression:
            db_engine_spec = self.table.project.db_engine_spec
            type_ = db_engine_spec.get_sqla_column_type(self.type)
            col = column(self.column_name, type_=type_)
        else:
            col = literal_column(self.expression)
        col = self.table.make_sqla_column_compatible(col, label)
        return col

    @property
    def datasource(self):
        return self.table

    def get_time_filter(self, start_dttm, end_dttm):
        col = self.get_sqla_col(label="__time")
        l = []  # noqa: E741
        if start_dttm:
            l.append(col >= text(self.dttm_sql_literal(start_dttm)))
        if end_dttm:
            l.append(col <= text(self.dttm_sql_literal(end_dttm)))
        return and_(*l)

    def get_timestamp_expression(
        self, time_grain: Optional[str]
    ) -> Union[TimestampExpression, Label]:
        """
        Return a SQLAlchemy Core element representation of self to be used in a query.

        :param time_grain: Optional time grain, e.g. P1Y
        :return: A TimeExpression object wrapped in a Label if supported by db
        """
        label = utils.DTTM_ALIAS

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
        time_expr = project.db_engine_spec.get_timestamp_expr(col, pdf, time_grain)
        return self.table.make_sqla_column_compatible(time_expr, label)

    @classmethod
    def import_obj(cls, i_column):
        def lookup_obj(lookup_column):
            return (
                db.session.query(PlaidColumn)
                .filter(
                    PlaidColumn.table_id == lookup_column.table_id,
                    PlaidColumn.column_name == lookup_column.column_name,
                )
                .first()
            )

        return import_datasource.import_simple_obj(db.session, i_column, lookup_obj)

    def dttm_sql_literal(self, dttm):
        """Convert datetime object to a SQL expression string"""
        tf = self.python_date_format
        if tf:
            seconds_since_epoch = int(dttm.timestamp())
            if tf == "epoch_s":
                return str(seconds_since_epoch)
            elif tf == "epoch_ms":
                return str(seconds_since_epoch * 1000)
            return "'{}'".format(dttm.strftime(tf))
        else:
            s = self.table.project.db_engine_spec.convert_dttm(self.type or "", dttm)
            return s or "'{}'".format(dttm.strftime("%Y-%m-%d %H:%M:%S.%f"))


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

    export_fields = (
        "metric_name",
        "verbose_name",
        "metric_type",
        "table_id",
        "expression",
        "description",
        "d3format",
        "warning_text",
    )
    update_from_object_fields = list(
        [s for s in export_fields if s not in ("table_id",)]
    )
    export_parent = "table"

    def get_sqla_col(self, label=None):
        label = label or self.metric_name
        sqla_col = literal_column(self.expression)
        return self.table.make_sqla_column_compatible(sqla_col, label)

    @property
    def perm(self):
        return (
            ("{parent_name}.[{obj.metric_name}](id:{obj.id})").format(
                obj=self, parent_name=self.table.full_name
            )
            if self.table
            else None
        )

    def get_perm(self):
        return self.perm

    @classmethod
    def import_obj(cls, i_metric):
        def lookup_obj(lookup_metric):
            return (
                db.session.query(PlaidMetric)
                .filter(
                    PlaidMetric.table_id == lookup_metric.table_id,
                    PlaidMetric.metric_name == lookup_metric.metric_name,
                )
                .first()
            )

        return import_datasource.import_simple_obj(db.session, i_metric, lookup_obj)


plaidtable_user = Table(
    "plaidtable_user",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("ab_user.id")),
    Column("table_id", Integer, ForeignKey("plaid_tables.id")),
)


class PlaidTable(Model, BaseDatasource):

    """An ORM object for SqlAlchemy table references"""

    type = "plaid"
    query_language = "sql"
    metric_class = PlaidMetric
    column_class = PlaidColumn
    owner_class = security_manager.user_model

    __tablename__ = "plaid_tables"
    __table_args__ = (UniqueConstraint("project_id", "table_name"),)

    table_name = Column(String(250))
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

    export_fields = (
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
    )
    update_from_object_fields = [
        f for f in export_fields if f not in ("table_name", "project_id")
    ]
    export_parent = "project"
    export_children = ["metrics", "columns"]

    sqla_aggregations = {
        "COUNT_DISTINCT": lambda column_name: sqla.func.COUNT(sqla.distinct(column_name)),
        "COUNT": sqla.func.COUNT,
        "SUM": sqla.func.SUM,
        "AVG": sqla.func.AVG,
        "MIN": sqla.func.MIN,
        "MAX": sqla.func.MAX,
    }

    def make_sqla_column_compatible(self, sqla_col, label=None):
        """Takes a sql alchemy column object and adds label info if supported by engine.
        :param sqla_col: sql alchemy column instance
        :param label: alias/label that column is expected to have
        :return: either a sql alchemy column or label instance if supported by engine
        """
        label_expected = label or sqla_col.name
        db_engine_spec = self.project.db_engine_spec
        if db_engine_spec.allows_column_aliases:
            label = db_engine_spec.make_label_compatible(label_expected)
            sqla_col = sqla_col.label(label)
        sqla_col._df_label_expected = label_expected
        return sqla_col

    def __repr__(self):
        return self.name

    @property
    def connection(self):
        return str(self.project)

    @property
    def description_markeddown(self):
        return utils.markdown(self.description)

    @property
    def datasource_name(self):
        return self.table_name

    @property
    def database(self):
        return self.project

    @property
    def uuid(self):
        return str(self.project)

    @classmethod
    def get_datasource_by_name(cls, session, table_name, schema, project_name):
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

    @property
    def link(self):
        name = escape(self.name)
        anchor = f'<a target="_blank" href="{self.explore_url}">{name}</a>'
        return Markup(anchor)

    def get_schema_perm(self):
        """Returns schema permission if present, project one otherwise."""
        return security_manager.get_schema_perm(self.project, self.schema)

    def get_perm(self):
        return ("[{obj.project}].[{obj.table_name}]" "(id:{obj.id})").format(obj=self)

    @property
    def name(self):
        return "{} :: {}".format(str(self.project), self.table_name)

    @property
    def full_name(self):
        return utils.get_datasource_full_name(
            str(self.project), self.table_name, schema=self.schema
        )

    @property
    def dttm_cols(self):
        l = [c.column_name for c in self.columns if c.is_dttm]  # noqa: E741
        if self.main_dttm_col and self.main_dttm_col not in l:
            l.append(self.main_dttm_col)
        return l

    @property
    def num_cols(self):
        return [c.column_name for c in self.columns if c.is_num]

    @property
    def any_dttm_col(self):
        cols = self.dttm_cols
        if cols:
            return cols[0]

    @property
    def html(self):
        t = ((c.column_name, c.type) for c in self.columns)
        df = pd.DataFrame(t)
        df.columns = ["field", "type"]
        return df.to_html(
            index=False,
            classes=("dataframe table table-striped table-bordered " "table-condensed"),
        )

    @property
    def sql_url(self):
        return self.project.sql_url + "?table_name=" + str(self.table_name)

    def external_metadata(self):
        cols = self.project.get_columns(self.table_name, schema=self.schema)
        for col in cols:
            try:
                col["type"] = str(col["type"])
            except CompileError:
                col["type"] = "UNKNOWN"
        return cols

    @property
    def time_column_grains(self):
        return {
            "time_columns": self.dttm_cols,
            "time_grains": [grain.name for grain in self.project.grains()],
        }

    @property
    def select_star(self):
        # show_cols and latest_partition set to false to avoid
        # the expensive cost of inspecting the DB
        return self.project.select_star(
            self.table_name, schema=self.schema, show_cols=False, latest_partition=False
        )

    def get_col(self, col_name):
        columns = self.columns
        for col in columns:
            if col_name == col.column_name:
                return col

    @property
    def data(self):
        d = super(PlaidTable, self).data
        # TODO: Type should probably be something other than "table" to
        # avoid conflict with sqla connector.
        if self.type == "table":
            grains = self.project.grains() or []
            if grains:
                grains = [(g.duration, g.name) for g in grains]
            d["granularity_sqla"] = utils.choicify(self.dttm_cols)
            d["time_grain_sqla"] = grains
            d["main_dttm_col"] = self.main_dttm_col
            d["fetch_values_predicate"] = self.fetch_values_predicate
            d["template_params"] = self.template_params
        return d

    def values_for_column(self, column_name, limit=10000):
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
            qry = qry.where(tp.process_template(self.fetch_values_predicate))

        engine = self.project.get_sqla_engine()
        sql = "{}".format(qry.compile(engine, compile_kwargs={"literal_binds": True}))
        sql = self.mutate_query_from_config(sql)

        df = pd.read_sql_query(sql=sql, con=engine)
        return [row[0] for row in df.to_records(index=False)]

    def mutate_query_from_config(self, sql):
        """Apply config's SQL_QUERY_MUTATOR

        Typically adds comments to the query with context"""
        SQL_QUERY_MUTATOR = config.get("SQL_QUERY_MUTATOR")
        if SQL_QUERY_MUTATOR:
            username = utils.get_username()
            sql = SQL_QUERY_MUTATOR(sql, username, security_manager, self.project)
        return sql

    def get_template_processor(self, **kwargs):
        return get_template_processor(table=self, database=self.project, **kwargs)

    def get_query_str_extended(self, query_obj) -> QueryStringExtended:
        sqlaq = self.get_sqla_query(**query_obj)
        sql = self.project.compile_sqla_query(sqlaq.sqla_query)
        logger.info(sql)
        sql = sqlparse.format(sql, reindent=True)
        sql = self.mutate_query_from_config(sql)
        return QueryStringExtended(
            labels_expected=sqlaq.labels_expected, sql=sql, prequeries=sqlaq.prequeries
        )

    def get_query_str(self, query_obj):
        query_str_ext = self.get_query_str_extended(query_obj)
        all_queries = query_str_ext.prequeries + [query_str_ext.sql]
        return ";\n\n".join(all_queries) + ";"

    def get_sqla_table(self):
        tbl = table(self.table_name)
        if self.schema:
            tbl.schema = self.schema
        return tbl

    def get_from_clause(self, template_processor=None):
        # Supporting arbitrary SQL statements in place of tables
        if self.sql:
            from_sql = self.sql
            if template_processor:
                from_sql = template_processor.process_template(from_sql)
            from_sql = sqlparse.format(from_sql, strip_comments=True)
            return TextAsFrom(sqla.text(from_sql), []).alias("expr_qry")
        return self.get_sqla_table()

    def adhoc_metric_to_sqla(self, metric, cols):
        """
        Turn an adhoc metric into a sqlalchemy column.

        :param dict metric: Adhoc metric definition
        :param dict cols: Columns for the current table
        :returns: The metric defined as a sqlalchemy column
        :rtype: sqlalchemy.sql.column
        """
        expression_type = metric.get("expressionType")
        label = utils.get_metric_name(metric)

        if expression_type == utils.ADHOC_METRIC_EXPRESSION_TYPES["SIMPLE"]:
            column_name = metric.get("column").get("column_name")
            table_column = cols.get(column_name)
            if table_column:
                sqla_column = table_column.get_sqla_col()
            else:
                sqla_column = column(column_name)
            sqla_metric = self.sqla_aggregations[metric.get("aggregate")](sqla_column)
        elif expression_type == utils.ADHOC_METRIC_EXPRESSION_TYPES["SQL"]:
            sqla_metric = literal_column(metric.get("sqlExpression"))
        else:
            return None

        return self.make_sqla_column_compatible(sqla_metric, label)

    def get_sqla_query(  # sqla
        self,
        groupby,
        metrics,
        granularity,
        from_dttm,
        to_dttm,
        filter=None,  # noqa
        is_timeseries=True,
        timeseries_limit=15,
        timeseries_limit_metric=None,
        row_limit=None,
        inner_from_dttm=None,
        inner_to_dttm=None,
        orderby=None,
        extras=None,
        columns=None,
        order_desc=True,
    ):
        """Querying any sqla table from this common interface"""
        template_kwargs = {
            "from_dttm": from_dttm,
            "groupby": groupby,
            "metrics": metrics,
            "row_limit": row_limit,
            "to_dttm": to_dttm,
            "filter": filter,
            "columns": {col.column_name: col for col in self.columns},
        }
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

        cols = {col.column_name: col for col in self.columns}
        metrics_dict = {m.metric_name: m for m in self.metrics}

        if not granularity and is_timeseries:
            raise Exception(
                _(
                    "Datetime column not provided as part table configuration "
                    "and is required by this type of chart"
                )
            )
        if not groupby and not metrics and not columns:
            raise Exception(_("Empty query?"))
        metrics_exprs = []
        for m in metrics:
            if utils.is_adhoc_metric(m):
                metrics_exprs.append(self.adhoc_metric_to_sqla(m, cols))
            elif m in metrics_dict:
                metrics_exprs.append(metrics_dict.get(m).get_sqla_col())
            else:
                raise Exception(_("Metric '%(metric)s' does not exist", metric=m))
        if metrics_exprs:
            main_metric_expr = metrics_exprs[0]
        else:
            main_metric_expr, label = literal_column("COUNT(*)"), "ccount"
            main_metric_expr = self.make_sqla_column_compatible(main_metric_expr, label)

        select_exprs = []
        groupby_exprs_sans_timestamp = OrderedDict()

        if groupby:
            select_exprs = []
            for s in groupby:
                if s in cols:
                    outer = cols[s].get_sqla_col()
                else:
                    outer = literal_column(f"({s})")
                    outer = self.make_sqla_column_compatible(outer, s)

                groupby_exprs_sans_timestamp[outer.name] = outer
                select_exprs.append(outer)
        elif columns:
            for s in columns:
                select_exprs.append(
                    cols[s].get_sqla_col()
                    if s in cols
                    else self.make_sqla_column_compatible(literal_column(s))
                )
            metrics_exprs = []

        groupby_exprs_with_timestamp = OrderedDict(groupby_exprs_sans_timestamp.items())
        if granularity:
            dttm_col = cols[granularity]
            time_grain = extras.get("time_grain_sqla")
            time_filters = []

            if is_timeseries:
                timestamp = dttm_col.get_timestamp_expression(time_grain)
                select_exprs += [timestamp]
                groupby_exprs_with_timestamp[timestamp.name] = timestamp

            # Use main dttm column to support index with secondary dttm columns
            if (
                db_engine_spec.time_secondary_columns
                and self.main_dttm_col in self.dttm_cols
                and self.main_dttm_col != dttm_col.column_name
            ):
                time_filters.append(
                    cols[self.main_dttm_col].get_time_filter(from_dttm, to_dttm)
                )
            time_filters.append(dttm_col.get_time_filter(from_dttm, to_dttm))

        select_exprs += metrics_exprs

        labels_expected = [c._df_label_expected for c in select_exprs]

        select_exprs = db_engine_spec.make_select_compatible(
            groupby_exprs_with_timestamp.values(), select_exprs
        )
        qry = sqla.select(select_exprs)

        tbl = self.get_from_clause(template_processor)

        if not columns:
            qry = qry.group_by(*groupby_exprs_with_timestamp.values())

        where_clause_and = []
        having_clause_and = []
        for flt in filter:
            if not all([flt.get(s) for s in ["col", "op"]]):
                continue
            col = flt["col"]
            op = flt["op"]
            col_obj = cols.get(col)
            if col_obj:
                is_list_target = op in ("in", "not in")
                eq = self.filter_values_handler(
                    flt.get("val"),
                    target_column_is_numeric=col_obj.is_num,
                    is_list_target=is_list_target,
                )
                if op in ("in", "not in"):
                    cond = col_obj.get_sqla_col().in_(eq)
                    if "<NULL>" in eq:
                        cond = or_(cond, col_obj.get_sqla_col() == None)  # noqa
                    if op == "not in":
                        cond = ~cond
                    where_clause_and.append(cond)
                else:
                    if col_obj.is_num:
                        eq = utils.string_to_num(flt["val"])
                    if op == "==":
                        where_clause_and.append(col_obj.get_sqla_col() == eq)
                    elif op == "!=":
                        where_clause_and.append(col_obj.get_sqla_col() != eq)
                    elif op == ">":
                        where_clause_and.append(col_obj.get_sqla_col() > eq)
                    elif op == "<":
                        where_clause_and.append(col_obj.get_sqla_col() < eq)
                    elif op == ">=":
                        where_clause_and.append(col_obj.get_sqla_col() >= eq)
                    elif op == "<=":
                        where_clause_and.append(col_obj.get_sqla_col() <= eq)
                    elif op == "LIKE":
                        where_clause_and.append(col_obj.get_sqla_col().like(eq))
                    elif op == "IS NULL":
                        where_clause_and.append(col_obj.get_sqla_col() == None)  # noqa
                    elif op == "IS NOT NULL":
                        where_clause_and.append(col_obj.get_sqla_col() != None)  # noqa
        if extras:
            where = extras.get("where")
            if where:
                where = template_processor.process_template(where)
                where_clause_and += [sqla.text("({})".format(where))]
            having = extras.get("having")
            if having:
                having = template_processor.process_template(having)
                having_clause_and += [sqla.text("({})".format(having))]
        if granularity:
            qry = qry.where(and_(*(time_filters + where_clause_and)))
        else:
            qry = qry.where(and_(*where_clause_and))
        qry = qry.having(and_(*having_clause_and))

        if not orderby and not columns:
            orderby = [(main_metric_expr, not order_desc)]

        for col, ascending in orderby:
            direction = asc if ascending else desc
            if utils.is_adhoc_metric(col):
                col = self.adhoc_metric_to_sqla(col, cols)
            elif col in cols:
                col = cols[col].get_sqla_col()
            qry = qry.order_by(direction(col))

        if row_limit:
            qry = qry.limit(row_limit)

        if is_timeseries and timeseries_limit and groupby and not time_groupby_inline:
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
                    inner_from_dttm or from_dttm, inner_to_dttm or to_dttm
                )
                subq = subq.where(and_(*(where_clause_and + [inner_time_filter])))
                subq = subq.group_by(*inner_groupby_exprs)

                ob = inner_main_metric_expr
                if timeseries_limit_metric:
                    ob = self._get_timeseries_orderby(
                        timeseries_limit_metric, metrics_dict, cols
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
                                timeseries_limit_metric, metrics_dict, cols
                            ),
                            False,
                        )
                    ]

                # run prequery to get top groups
                prequery_obj = {
                    "is_timeseries": False,
                    "row_limit": timeseries_limit,
                    "groupby": groupby,
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

    def _get_timeseries_orderby(self, timeseries_limit_metric, metrics_dict, cols):
        if utils.is_adhoc_metric(timeseries_limit_metric):
            ob = self.adhoc_metric_to_sqla(timeseries_limit_metric, cols)
        elif timeseries_limit_metric in metrics_dict:
            timeseries_limit_metric = metrics_dict.get(timeseries_limit_metric)
            ob = timeseries_limit_metric.get_sqla_col()
        else:
            raise Exception(
                _("Metric '%(metric)s' does not exist", metric=timeseries_limit_metric)
            )

        return ob

    def _get_top_groups(self, df, dimensions, groupby_exprs):
        groups = []
        for unused, row in df.iterrows():
            group = []
            for dimension in dimensions:
                group.append(groupby_exprs[dimension] == row[dimension])
            groups.append(and_(*group))

        return or_(*groups)

    def query(self, query_obj):
        qry_start_dttm = datetime.now()
        query_str_ext = self.get_query_str_extended(query_obj)
        sql = query_str_ext.sql
        status = utils.QueryStatus.SUCCESS
        error_message = None

        def mutator(df):
            labels_expected = query_str_ext.labels_expected
            if df is not None and not df.empty:
                if len(df.columns) != len(labels_expected):
                    raise Exception(
                        f"For {sql}, df.columns: {df.columns}"
                        f" differs from {labels_expected}"
                    )
                else:
                    df.columns = labels_expected
            return df

        try:
            df = self.project.get_df(sql, self.schema, mutator)
        except Exception as e:
            df = None
            status = utils.QueryStatus.FAILED
            logger.exception(f"Query {sql} on schema {self.schema} failed")
            db_engine_spec = self.project.db_engine_spec
            error_message = db_engine_spec.extract_error_message(e)

        return QueryResult(
            status=status,
            df=df,
            duration=datetime.now() - qry_start_dttm,
            query=sql,
            error_message=error_message,
        )

    def get_sqla_table_object(self):
        return self.project.get_table(self.table_name, schema=self.schema)

    def fetch_metadata(self):
        """Fetches the metadata for the table and merges it in"""
        try:
            table = self.get_sqla_table_object()
        except Exception as e:
            logger.exception(e)
            raise Exception(
                _(
                    "Table [{}] doesn't seem to exist in the specified project, "
                    "couldn't fetch column information"
                ).format(self.table_name)
            )

        M = PlaidMetric  # noqa
        metrics = []
        any_date_col = None
        db_engine_spec = self.project.db_engine_spec
        db_dialect = self.project.get_dialect()
        dbcols = (
            db.session.query(PlaidColumn)
            .filter(PlaidColumn.table == self)
        )
        dbcols = {dbcol.column_name: dbcol for dbcol in dbcols}

        for col in table.columns:
            try:
                datatype = db_engine_spec.column_datatype_to_string(
                    col.type, db_dialect
                )
            except Exception as e:
                datatype = "UNKNOWN"
                logger.error("Unrecognized data type in {}.{}".format(table, col.name))
                logger.exception(e)
            dbcol = dbcols.get(col.name, None)
            if not dbcol:
                dbcol = PlaidColumn(column_name=col.name, type=datatype)
                dbcol.sum = dbcol.is_num
                dbcol.avg = dbcol.is_num
                dbcol.is_dttm = dbcol.is_time
                db_engine_spec.alter_new_orm_column(dbcol)
            else:
                dbcol.type = datatype
            dbcol.groupby = True
            dbcol.filterable = True
            self.columns.append(dbcol)
            if not any_date_col and dbcol.is_time:
                any_date_col = col.name

        actual_cols = {col.name for col in table.columns}
        for col_name, col in dbcols.items():
            if col_name not in actual_cols:
                db.session.delete(col)
                db.session.commit()

        metrics.append(
            M(
                metric_name="count",
                verbose_name="COUNT(*)",
                metric_type="count",
                expression="COUNT(*)",
            )
        )
        if not self.main_dttm_col:
            self.main_dttm_col = any_date_col
        self.add_missing_metrics(metrics)
        db.session.merge(self)
        db.session.commit()

    @classmethod
    def import_obj(cls, i_datasource, import_time=None):
        """Imports the datasource from the object to the project.

         Metrics and columns and datasource will be overrided if exists.
         This function can be used to import/export dashboards between multiple
         superset instances. Audit metadata isn't copies over.
        """

        def lookup_sqlatable(table):
            return (
                db.session.query(PlaidTable)
                .join(PlaidProject)
                .filter(
                    PlaidTable.base_table_name == table.base_table_name,
                    PlaidTable.schema == table.schema,
                    PlaidProject.uuid == table.project_id,
                )
                .first()
            )

        def lookup_project(table):
            try:
                logger.debug(table)
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
            db.session, i_datasource, lookup_project, lookup_sqlatable, import_time
        )

    @classmethod
    def query_datasources_by_name(cls, session, database, datasource_name, schema=None):
        query = (
            session.query(cls)
            .filter_by(project_id=database.id)
            .filter_by(table_name=datasource_name)
        )
        if schema:
            query = query.filter_by(schema=schema)
        return query.all()

    @staticmethod
    def default_query(qry):
        return qry.filter_by(is_sqllab_view=False)

    def has_extra_cache_keys(self, query_obj: Dict) -> bool:
        """
        Detects the presence of calls to cache_key_wrapper in items in query_obj that can
        be templated.

        :param query_obj: query object to analyze
        :return: True if at least one item calls cache_key_wrapper, otherwise False
        """
        regex = re.compile(r"\{\{.*cache_key_wrapper\(.*\).*\}\}")
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
        for statement in templatable_statements:
            if regex.search(statement):
                return True
        return False

    def get_extra_cache_keys(self, query_obj: Dict) -> List[Any]:
        if self.has_extra_cache_keys(query_obj):
            sqla_query = self.get_sqla_query(**query_obj)
            extra_cache_keys = sqla_query.extra_cache_keys
            return extra_cache_keys
        return []


sqla.event.listen(PlaidTable, "after_insert", security_manager.set_perm)
sqla.event.listen(PlaidTable, "after_update", security_manager.set_perm)

class PlaidProject(
    Model, AuditMixinNullable, ImportMixin
):  # pylint: disable=too-many-public-methods

    """An ORM object that stores Database related information"""

    __tablename__ = "plaid_projects"
    type = "plaid"
    __table_args__ = (UniqueConstraint("uuid"),)

    id = Column(Integer, primary_key=True)  # pylint: disable=invalid-name
    name = Column(String(250))
    # short unique name, used in permissions
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
    perm = Column(String(1000))
    impersonate_user = Column(Boolean, default=False)
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

    def __repr__(self):
        return self.project_name

    @property
    def project_name(self) -> str:
        return self.name if self.name else self.uuid

    @property
    def allows_subquery(self) -> bool:
        return self.db_engine_spec.allows_subqueries

    @property
    def function_names(self) -> List[str]:
        return self.db_engine_spec.get_function_names(self)

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
        return sqlalchemy_url.get_backend_name()

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

    @classmethod
    def get_password_masked_url_from_uri(cls, uri: str):  # pylint: disable=invalid-name
        sqlalchemy_url = make_url(uri)
        return cls.get_password_masked_url(sqlalchemy_url)

    @classmethod
    def get_password_masked_url(
        cls, url: URL  # pylint: disable=redefined-outer-name
    ) -> URL:
        url_copy = deepcopy(url)
        if url_copy.password is not None:
            url_copy.password = PASSWORD_MASK
        return url_copy

    def set_sqlalchemy_uri(self, uri: str) -> None:
        conn = sqla.engine.url.make_url(uri.strip())
        if conn.password != PASSWORD_MASK and not custom_password_store:
            # do not over-write the password with the password mask
            self.password = conn.password
        conn.password = PASSWORD_MASK if conn.password else None
        self.sqlalchemy_uri = str(conn)  # hides the password

    def get_effective_user(
        self,
        url: URL,  # pylint: disable=redefined-outer-name
        user_name: Optional[str] = None,
    ) -> Optional[str]:
        """
        Get the effective user, especially during impersonation.
        :param url: SQL Alchemy URL object
        :param user_name: Default username
        :return: The effective username
        """
        effective_username = None
        if self.impersonate_user:
            effective_username = url.username
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
        source: Optional[int] = None,
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
        logger.info("Database.get_sqla_engine(). Masked URL: %s", str(masked_url))

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
            params["connect_args"] = connect_args

        params.update(self.get_encrypted_extra())

        if DB_CONNECTION_MUTATOR:
            sqlalchemy_url, params = DB_CONNECTION_MUTATOR(
                sqlalchemy_url, params, effective_username, security_manager, source
            )

        return create_engine(sqlalchemy_url, **params)

    def get_reserved_words(self) -> Set[str]:
        return self.get_dialect().preparer.reserved_words

    def get_quoter(self):
        return self.get_dialect().identifier_preparer.quote

    def get_df(  # pylint: disable=too-many-locals
        self, sql: str, schema: Optional[str] = None, mutator: Optional[Callable] = None
    ) -> pd.DataFrame:
        sqls = [str(s).strip(" ;") for s in sqlparse.parse(sql)]
        source_key = None
        if request and request.referrer:
            if "/superset/dashboard/" in request.referrer:
                source_key = "dashboard"
            elif "/superset/explore/" in request.referrer:
                source_key = "chart"
        engine = self.get_sqla_engine(
            schema=schema, source=utils.sources[source_key] if source_key else None
        )
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

                if cursor.description is not None:
                    columns = [col_desc[0] for col_desc in cursor.description]
                else:
                    columns = []

                df = pd.DataFrame.from_records(
                    data=list(cursor.fetchall()), columns=columns, coerce_float=True
                )

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
    ):
        """Generates a ``select *`` statement in the proper dialect"""
        eng = self.get_sqla_engine(
            schema=schema, source=utils.sources.get("sql_lab", None)
        )
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
        return sqla.inspect(engine)

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: "db:{}:schema:None:table_list",
        attribute_in_key="id",
    )
    def get_all_table_names_in_database(
        self, cache: bool = False, cache_timeout: Optional[bool] = None, force=False
    ) -> List[utils.DatasourceName]:
        """Parameters need to be passed as keyword arguments."""
        if not self.allow_multi_schema_metadata_fetch:
            return []
        return self.db_engine_spec.get_all_datasource_names(self, "table")

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: "db:{}:schema:None:view_list",
        attribute_in_key="id",  # type: ignore
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
        cache_timeout: int = None,
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
        except Exception as e:  # pylint: disable=broad-except
            logger.exception(e)

    @cache_util.memoized_func(
        key=lambda *args, **kwargs: f"db:{{}}:schema:{kwargs.get('schema')}:view_list",  # type: ignore
        attribute_in_key="id",
    )
    def get_all_view_names_in_schema(
        self,
        schema: str,
        cache: bool = False,
        cache_timeout: int = None,
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
        except Exception as e:  # pylint: disable=broad-except
            logger.exception(e)

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
        cls, backend
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
        extra: Dict[str, Any] = {}
        if self.extra:
            try:
                extra = json.loads(self.extra)
            except json.JSONDecodeError as e:
                logger.error(e)
                raise e
        return extra

    def get_encrypted_extra(self):
        encrypted_extra = {}
        if self.encrypted_extra:
            try:
                encrypted_extra = json.loads(self.encrypted_extra)
            except json.JSONDecodeError as e:
                logger.error(e)
                raise e
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

    def get_columns(
        self, table_name: str, schema: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.db_engine_spec.get_columns(self.inspector, table_name, schema)

    def get_indexes(
        self, table_name: str, schema: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.inspector.get_indexes(table_name, schema)

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
        return self.get_extra().get("schemas_allowed_for_csv_upload", [])

    @property
    def sqlalchemy_uri_decrypted(self) -> str:
        conn = sqla.engine.url.make_url(self.sqlalchemy_uri)
        if custom_password_store:
            conn.password = custom_password_store(conn)
        else:
            conn.password = self.password
        return str(conn)

    @property
    def sql_url(self) -> str:
        return f"/superset/sql/{self.id}/"

    def get_perm(self) -> str:
        return f"[{self.name}].(id:{self.id})"

    def has_table(self, table: Table) -> bool:
        engine = self.get_sqla_engine()
        return engine.has_table(table.table_name, table.schema or None)

    def has_table_by_name(self, table_name: str, schema: Optional[str] = None) -> bool:
        engine = self.get_sqla_engine()
        return engine.has_table(table_name, schema)

    @utils.memoized
    def get_dialect(self) -> Dialect:
        sqla_url = url.make_url(self.sqlalchemy_uri_decrypted)
        return sqla_url.get_dialect()()
