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
import logging
from datetime import datetime
from io import BytesIO
from urllib import parse

from flask import g, request, Response, send_file, url_for
from flask_appbuilder.api import expose, protect, safe
from marshmallow import ValidationError

from superset.commands.dashboard.exceptions import (
    DashboardAccessDeniedError,
    DashboardNotFoundError,
)
from superset.commands.dashboard.permalink.create import CreateDashboardPermalinkCommand
from superset.commands.dashboard.permalink.get import GetDashboardPermalinkCommand
from superset.constants import MODEL_API_RW_METHOD_PERMISSION_MAP
from superset.dashboards.permalink.exceptions import DashboardPermalinkInvalidStateError
from superset.dashboards.permalink.schemas import DashboardPermalinkStateSchema
from superset.extensions import event_logger
from superset.key_value.exceptions import KeyValueAccessDeniedError
from superset.utils.screenshots import DashboardScreenshot
from superset.utils.urls import headless_url
from superset.views.base_api import BaseSupersetApi, requires_json

logger = logging.getLogger(__name__)


class DashboardPermalinkRestApi(BaseSupersetApi):
    add_model_schema = DashboardPermalinkStateSchema()
    method_permission_name = MODEL_API_RW_METHOD_PERMISSION_MAP
    allow_browser_login = True
    class_permission_name = "DashboardPermalinkRestApi"
    resource_name = "dashboard"
    openapi_spec_tag = "Dashboard Permanent Link"
    openapi_spec_component_schemas = (DashboardPermalinkStateSchema,)

    @expose("/<pk>/permalink", methods=("POST",))
    @protect()
    @safe
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.post",
        log_to_statsd=False,
    )
    @requires_json
    def post(self, pk: str) -> Response:
        """Create a new dashboard's permanent link.
        ---
        post:
          summary: Create a new dashboard's permanent link
          parameters:
          - in: path
            schema:
              type: string
            name: pk
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/DashboardPermalinkStateSchema'
                examples:
                  time_grain_filter:
                    summary: "Time Grain Filter"
                    value:
                      dataMask:
                        id: NATIVE_FILTER_ID
                        extraFormData:
                          time_grain_sqla: "P1W/1970-01-03T00:00:00Z"
                        filterState:
                          label: "Week ending Saturday"
                          value:
                            - "P1W/1970-01-03T00:00:00Z"
                  timecolumn_filter:
                    summary: "Time Column Filter"
                    value:
                      dataMask:
                        id: NATIVE_FILTER_ID
                        extraFormData:
                          granularity_sqla: "order_date"
                        filterState:
                          value:
                            - "order_date"
                  time_range_filter:
                    summary: "Time Range Filter"
                    value:
                      dataMask:
                        id: NATIVE_FILTER_ID
                        extraFormData:
                          time_range: >-
                            DATEADD(DATETIME("2025-01-16T00:00:00"), -7, day)
                            : 2025-01-16T00:00:00
                        filterState:
                          value: >-
                            DATEADD(DATETIME("2025-01-16T00:00:00"), -7, day)
                            : 2025-01-16T00:00:00
                  numerical_range_filter:
                    summary: "Numerical Range Filter"
                    value:
                      dataMask:
                        id: NATIVE_FILTER_ID
                        extraFormData:
                          filters:
                            - col: "tz_offset"
                              op: ">="
                              val:
                                - 1000
                            - col: "tz_offset"
                              op: "<="
                              val:
                                - 2000
                        filterState:
                          value:
                            - 1000
                            - 2000
                          label: "1000 <= x <= 200"
                  value_filter:
                    summary: "Value Filter"
                    value:
                      dataMask:
                        id: NATIVE_FILTER_ID
                        extraFormData:
                          filters:
                            - col: "real_name"
                              op: "IN"
                              val:
                                - "John Doe"
                        filterState:
                          value:
                            - "John Doe"
          responses:
            201:
              description: The permanent link was stored successfully.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      key:
                        type: string
                        description: The key to retrieve the permanent link data.
                      url:
                        type: string
                        description: permanent link.
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            state = self.add_model_schema.load(request.json)
            key = CreateDashboardPermalinkCommand(
                dashboard_id=pk,
                state=state,
            ).run()
            url = url_for("Superset.dashboard_permalink", key=key, _external=True)
            return self.response(201, key=key, url=url)
        except (ValidationError, DashboardPermalinkInvalidStateError) as ex:
            return self.response(400, message=str(ex))
        except (
            DashboardAccessDeniedError,
            KeyValueAccessDeniedError,
        ) as ex:
            return self.response(403, message=str(ex))
        except DashboardNotFoundError as ex:
            return self.response(404, message=str(ex))

    @expose("/permalink/<string:key>", methods=("GET",))
    @protect()
    @safe
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.get",
        log_to_statsd=False,
    )
    def get(self, key: str) -> Response:
        """Get dashboard's permanent link state.
        ---
        get:
          summary: Get dashboard's permanent link state
          parameters:
          - in: path
            schema:
              type: string
            name: key
          responses:
            200:
              description: Returns the stored state.
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      state:
                        type: object
                        description: The stored state
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            value = GetDashboardPermalinkCommand(key=key).run()
            if not value:
                return self.response_404()
            return self.response(200, **value)
        except DashboardAccessDeniedError as ex:
            return self.response(403, message=str(ex))
        except DashboardNotFoundError as ex:
            return self.response(404, message=str(ex))

    @expose("/permalink/<string:key>/pdf", methods=("GET",))
    @protect()
    @safe
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.get_pdf",
        log_to_statsd=False,
    )
    def get_pdf(self, key: str) -> Response:
        """Get a dashboard's pdf from permanent link.
        ---
        get:
          summary: Get a PDF of a dashboard
          parameters:
          - in: path
            schema:
              type: string
            name: key
          responses:
            200:
              description: PDF of rendered dashboard for permanent link
              content:
                application/pdf:
                  schema:
                    type: string
                    format: binary
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            value = GetDashboardPermalinkCommand(key=key).run()
            if not value:
                return self.response_404()
            dashboard_id, state = value["dashboardId"], value.get("state", {})
            dashboard_url = headless_url(
                url_for(
                    "Superset.dashboard",
                    dashboard_id_or_slug=dashboard_id,
                    permalink_key=key,
                    _external=False,
                ),
            )
            if url_params := state.get("urlParams"):
                params = parse.urlencode(url_params)
                dashboard_url = f"{dashboard_url}&{params}"
            if original_params := request.query_string.decode():
                dashboard_url = f"{dashboard_url}&{original_params}"
            if hash_ := state.get("anchor", state.get("hash")):
                dashboard_url = f"{dashboard_url}#{hash_}"

            logger.info("Create dashboard PDF for : %s", dashboard_url)

            screenshot = DashboardScreenshot(dashboard_url, None)
            pdf = screenshot.get_pdf(user=g.user)
            if pdf is None:
                return self.response(500, message="Failed to generate dashboard PDF")
            buf = BytesIO(pdf)
            buf.seek(0)

            timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
            root = f"dashboard_pdf_{timestamp}"
            filename = f"{root}.pdf"

            response = send_file(
                buf,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=filename,
            )
            if token := request.args.get("token"):
                response.set_cookie(token, "done", max_age=600)
            return response

        except DashboardAccessDeniedError as ex:
            return self.response(403, message=str(ex))
        except DashboardNotFoundError as ex:
            return self.response(404, message=str(ex))
