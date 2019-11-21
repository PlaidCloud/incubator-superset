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
"""Views used by the SqlAlchemy connector"""
import logging

from flask import flash, Markup, redirect, request, redirect, Response
from flask_appbuilder import CompactCRUDMixin, expose
from flask_appbuilder.actions import action
from flask_appbuilder.baseviews import expose, expose_api
from flask_appbuilder.fieldwidgets import Select2Widget
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder.security.decorators import has_access, has_access_api
from flask_babel import gettext as __
from flask_babel import lazy_gettext as _
from wtforms.ext.sqlalchemy.fields import QuerySelectField
import plaid.datasource_helpers as dh
import json

from superset import appbuilder, db, security_manager
from superset.connectors.base.views import DatasourceModelView
from superset.utils import core as utils
from superset.views.base import (
    DatasourceFilter,
    DeleteMixin,
    get_datasource_exist_error_msg,
    ListWidgetWithCheckboxes,
    SupersetModelView,
    YamlExportMixin,
)
from superset.views.core import BaseSupersetView
from . import models

logger = logging.getLogger(__name__)


class PlaidColumnInlineView(CompactCRUDMixin, SupersetModelView):  # noqa
    datamodel = SQLAInterface(models.PlaidColumn)

    list_title = _("Columns")
    show_title = _("Show Column")
    add_title = _("Add Column")
    edit_title = _("Edit Column")

    can_delete = False
    list_widget = ListWidgetWithCheckboxes
    edit_columns = [
        "column_name",
        "verbose_name",
        "description",
        "type",
        "groupby",
        "filterable",
        "table",
        "expression",
        "is_dttm",
        "python_date_format",
    ]
    add_columns = edit_columns
    list_columns = [
        "column_name",
        "verbose_name",
        "type",
        "groupby",
        "filterable",
        "is_dttm",
    ]
    page_size = 500
    description_columns = {
        "is_dttm": _(
            "Whether to make this column available as a "
            "[Time Granularity] option, column has to be DATETIME or "
            "DATETIME-like"
        ),
        "filterable": _(
            "Whether this column is exposed in the `Filters` section "
            "of the explore view."
        ),
        "type": _(
            "The data type that was inferred by the database. "
            "It may be necessary to input a type manually for "
            "expression-defined columns in some cases. In most case "
            "users should not need to alter this."
        ),
        "expression": utils.markdown(
            "a valid, *non-aggregating* SQL expression as supported by the "
            "underlying backend. Example: `substr(name, 1, 1)`",
            True,
        ),
        "python_date_format": utils.markdown(
            Markup(
                "The pattern of timestamp format, use "
                '<a href="https://docs.python.org/2/library/'
                'datetime.html#strftime-strptime-behavior">'
                "python datetime string pattern</a> "
                "expression. If time is stored in epoch "
                "format, put `epoch_s` or `epoch_ms`."
            ),
            True,
        ),
    }
    label_columns = {
        "column_name": _("Column"),
        "verbose_name": _("Verbose Name"),
        "description": _("Description"),
        "groupby": _("Groupable"),
        "filterable": _("Filterable"),
        "table": _("Table"),
        "expression": _("Expression"),
        "is_dttm": _("Is temporal"),
        "python_date_format": _("Datetime Format"),
        "type": _("Type"),
    }

    add_form_extra_fields = {
        "table": QuerySelectField(
            "Table",
            query_factory=lambda: db.session().query(models.PlaidTable),
            allow_blank=True,
            widget=Select2Widget(extra_classes="readonly"),
        )
    }

    edit_form_extra_fields = add_form_extra_fields


appbuilder.add_view_no_menu(PlaidColumnInlineView)


class PlaidMetricInlineView(CompactCRUDMixin, SupersetModelView):  # noqa
    datamodel = SQLAInterface(models.PlaidMetric)

    list_title = _("Metrics")
    show_title = _("Show Metric")
    add_title = _("Add Metric")
    edit_title = _("Edit Metric")

    list_columns = ["metric_name", "verbose_name", "metric_type"]
    edit_columns = [
        "metric_name",
        "description",
        "verbose_name",
        "metric_type",
        "expression",
        "table",
        "d3format",
        "warning_text",
    ]
    description_columns = {
        "expression": utils.markdown(
            "a valid, *aggregating* SQL expression as supported by the "
            "underlying backend. Example: `count(DISTINCT userid)`",
            True,
        ),
        "d3format": utils.markdown(
            "d3 formatting string as defined [here]"
            "(https://github.com/d3/d3-format/blob/master/README.md#format). "
            "For instance, this default formatting applies in the Table "
            "visualization and allow for different metric to use different "
            "formats",
            True,
        ),
    }
    add_columns = edit_columns
    page_size = 500
    label_columns = {
        "metric_name": _("Metric"),
        "description": _("Description"),
        "verbose_name": _("Verbose Name"),
        "metric_type": _("Type"),
        "expression": _("SQL Expression"),
        "table": _("Table"),
        "d3format": _("D3 Format"),
        "warning_text": _("Warning Message"),
    }

    add_form_extra_fields = {
        "table": QuerySelectField(
            "Table",
            query_factory=lambda: db.session().query(models.PlaidTable),
            allow_blank=True,
            widget=Select2Widget(extra_classes="readonly"),
        )
    }

    edit_form_extra_fields = add_form_extra_fields


appbuilder.add_view_no_menu(PlaidMetricInlineView)


class PlaidTableModelView(DatasourceModelView, DeleteMixin, YamlExportMixin):  # noqa
    datamodel = SQLAInterface(models.PlaidTable)

    list_title = _("Tables")
    show_title = _("Show Table")
    add_title = _("Import a table definition")
    edit_title = _("Edit Table")

    list_columns = ["link", "project_name", "changed_by_", "modified"]
    order_columns = ["modified"]
    add_columns = ["project", "schema", "table_name"]
    edit_columns = [
        "table_name",
        "sql",
        "filter_select_enabled",
        "fetch_values_predicate",
        "project",
        "schema",
        "description",
        "owners",
        "main_dttm_col",
        "default_endpoint",
        "offset",
        "cache_timeout",
        "is_sqllab_view",
        "template_params",
    ]
    base_filters = [["id", DatasourceFilter, lambda: []]]
    show_columns = edit_columns + ["perm", "slices"]
    related_views = [PlaidColumnInlineView, PlaidMetricInlineView]
    base_order = ("changed_on", "desc")
    search_columns = ("project", "schema", "table_name", "owners", "is_sqllab_view")
    description_columns = {
        "slices": _(
            "The list of charts associated with this table. By "
            "altering this datasource, you may change how these associated "
            "charts behave. "
            "Also note that charts need to point to a datasource, so "
            "this form will fail at saving if removing charts from a "
            "datasource. If you want to change the datasource for a chart, "
            "overwrite the chart from the 'explore view'"
        ),
        "offset": _("Timezone offset (in hours) for this datasource"),
        "table_name": _("Name of the table that exists in the plaid project"),
        "schema": _(
            "Schema, as used only in some databases like Postgres, Redshift " "and DB2"
        ),
        "description": Markup(
            'Supports <a href="https://daringfireball.net/projects/markdown/">'
            "markdown</a>"
        ),
        "sql": _(
            "This fields acts a Superset view, meaning that Superset will "
            "run a query against this string as a subquery."
        ),
        "fetch_values_predicate": _(
            "Predicate applied when fetching distinct value to "
            "populate the filter control component. Supports "
            "jinja template syntax. Applies only when "
            "`Enable Filter Select` is on."
        ),
        "default_endpoint": _(
            "Redirects to this endpoint when clicking on the table "
            "from the table list"
        ),
        "filter_select_enabled": _(
            "Whether to populate the filter's dropdown in the explore "
            "view's filter section with a list of distinct values fetched "
            "from the backend on the fly"
        ),
        "is_sqllab_view": _(
            "Whether the table was generated by the 'Visualize' flow " "in SQL Lab"
        ),
        "template_params": _(
            "A set of parameters that become available in the query using "
            "Jinja templating syntax"
        ),
        "cache_timeout": _(
            "Duration (in seconds) of the caching timeout for this table. "
            "A timeout of 0 indicates that the cache never expires. "
            "Note this defaults to the database timeout if undefined."
        ),
    }
    label_columns = {
        "slices": _("Associated Charts"),
        "link": _("Table"),
        "changed_by_": _("Changed By"),
        "project_name": _("Project"),
        "project": _("Project"),
        "changed_on_": _("Last Changed"),
        "filter_select_enabled": _("Enable Filter Select"),
        "schema": _("Schema"),
        "default_endpoint": _("Default Endpoint"),
        "offset": _("Offset"),
        "cache_timeout": _("Cache Timeout"),
        "table_name": _("Table Name"),
        "fetch_values_predicate": _("Fetch Values Predicate"),
        "owners": _("Owners"),
        "main_dttm_col": _("Main Datetime Column"),
        "description": _("Description"),
        "is_sqllab_view": _("SQL Lab View"),
        "template_params": _("Template parameters"),
        "modified": _("Modified"),
    }

    edit_form_extra_fields = {
        "project": QuerySelectField(
            "PlaidProject",
            query_factory=lambda: db.session().query(models.PlaidProject),
            widget=Select2Widget(extra_classes="readonly"),
        )
    }

    def pre_add(self, table):
        with db.session.no_autoflush:
            table_query = db.session.query(models.PlaidTable).filter(
                models.PlaidTable.table_name == table.table_name,
                models.PlaidTable.schema == table.schema,
                models.PlaidTable.project_id == table.project.uuid,
            )
            if db.session.query(table_query.exists()).scalar():
                raise Exception(get_datasource_exist_error_msg(table.full_name))

        # Fail before adding if the table can't be found
        try:
            table.get_sqla_table_object()
        except Exception as e:
            logger.exception(f"Got an error in pre_add for {table.name}")
            raise Exception(
                _(
                    "Table [{}] could not be found, "
                    "please double check your "
                    "database connection, schema, and "
                    "table name, error: {}"
                ).format(table.name, str(e))
            )

    def post_add(self, table, flash_message=True):
        table.fetch_metadata()
        security_manager.add_permission_view_menu("datasource_access", table.get_perm())
        if table.schema:
            security_manager.add_permission_view_menu(
                "schema_access", table.schema_perm
            )

        if flash_message:
            flash(
                _(
                    "The table was created. "
                    "As part of this two-phase configuration "
                    "process, you should now click the edit button by "
                    "the new table to configure it."
                ),
                "info",
            )

    def post_update(self, table):
        self.post_add(table, flash_message=False)

    def _delete(self, pk):
        DeleteMixin._delete(self, pk)

    @expose("/edit/<pk>", methods=["GET", "POST"])
    @has_access
    def edit(self, pk):
        """Simple hack to redirect to explore view after saving"""
        resp = super(PlaidTableModelView, self).edit(pk)
        if isinstance(resp, str):
            return resp
        return redirect("/superset/explore/table/{}/".format(pk))

    @action(
        "refresh", __("Refresh Metadata"), __("Refresh column metadata"), "fa-refresh"
    )
    def refresh(self, tables):
        if not isinstance(tables, list):
            tables = [tables]
        successes = []
        failures = []
        for t in tables:
            try:
                t.fetch_metadata()
                successes.append(t)
            except Exception:
                failures.append(t)

        if len(successes) > 0:
            success_msg = _(
                "Metadata refreshed for the following table(s): %(tables)s",
                tables=", ".join([t.table_name for t in successes]),
            )
            flash(success_msg, "info")
        if len(failures) > 0:
            failure_msg = _(
                "Unable to retrieve metadata for the following table(s): %(tables)s",
                tables=", ".join([t.table_name for t in failures]),
            )
            flash(failure_msg, "danger")

        return redirect("/tablemodelview/list/")


appbuilder.add_view_no_menu(PlaidTableModelView)
appbuilder.add_link(
    "Tables",
    label=__("Tables"),
    href="/plaidtablemodelview/list/?_flt_1_is_sqllab_view=y",
    icon="fa-table",
    category="Data",
    category_label=__("Data"),
    category_icon="fa-table",
)


class Plaid(BaseSupersetView):
    """FAB view exposing some endpoints for Plaidcloud datasource management.
    """
    def json_response(self, obj, status=200):
        return Response(
            json.dumps(obj),
            status=status,
            mimetype='application/json')

    @expose_api(name='plaid_refresh', url='/api/refresh', methods=['GET'])
    @expose_api(name='plaid_refresh', url='/api/refresh/<project_id>', methods=['GET'])
    @has_access_api
    def refresh_async(self, project_id=None):
        """Endpoint to refresh user's datasource(s) without redirect.

        All projects' datasources will be synchronized if ID is unspecified.

        Args:
            project_id (str, optional): The UID of the project to synchronize.

        Returns:
            bool: True.
        """
        project_ids = []
        if project_id:
            project_ids.append(project_id)
        appbuilder.sm.sync_datasources(project_ids=project_ids)
        return self.json_response(True)

    @expose('/refresh')
    @expose('/refresh/<project_id>')
    @has_access_api
    def refresh(self, project_id=None):
        """Endpoint to refresh user's datasource(s) with redirect.

        All projects' datasources will be synchronized if ID is unspecified.
        This function will redirect the user to the tables list once finished.

        Args:
            project_id (str, optional): The UID of the project to synchronize.

        Returns:
            redirect to '/tablemodelview/list' view.
        """
        self.refresh_async(project_id)
        return redirect('/tablemodelview/list')

# TODO: Determine if it makes sense to continue to expose a "refresh" button.
# appbuilder.add_view_no_menu(Plaid)
# appbuilder.add_link(
#     'Refresh',
#     label=__('Refresh'),
#     href='/plaid/refresh',
#     icon='fa-refresh',
#     category='Data',
#     category_label=__('Data'),
#     category_icon='fa-database')
