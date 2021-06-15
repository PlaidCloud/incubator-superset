{{/*

 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/}}
{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "superset.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "superset.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "superset.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "superset-config" }}
import os
import ssl
from cachelib.redis import RedisCache
from collections import OrderedDict
from flask_appbuilder.security.manager import AUTH_DB, AUTH_OID
from plaid.security import PlaidSecurityManager
from plaid_permissions import PLAID_BASE_PERMISSIONS
from superset.typing import CacheConfig


ssl._create_default_https_context = ssl._create_unverified_context

basedir = os.path.abspath(os.path.dirname(__file__))
#ROW_LIMIT = 5000
#SUPERSET_WORKERS = 4

# I created a mapbox account under garrett.bates@tartansolutions.com
MAPBOX_API_KEY = '{{ .Values.mapbox.apiKey }}'

HOSTNAME = '{{ .Values.ingress.hostname }}'
PLAID_HOST = '{{ .Values.ingress.hostname }}'
PLAID_DATABASE_HOST = '{{ .Values.greenplum.host }}'
PLAID_RPC = '{{ .Values.rpc.host }}'
SCHEME = 'https'
SQLALCHEMY_DATABASE_URI = 'postgresql://{{ .Values.postgresql.postgresqlUsername }}:{{ .Values.postgresql.postgresqlPassword }}@{{ template "superset.fullname" . }}-postgresql:{{ .Values.postgresql.service.port }}/{{ .Values.postgresql.postgresqlDatabase }}'
PUBLIC_ROLE_LIKE_PLAID = False
ADMIN_ENABLED = True
SESSION_EXPIRATION = 600

SQLALCHEMY_TRACK_MODIFICATIONS = True

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True
# Add endpoints that need to be exempt from CSRF protection
WTF_CSRF_EXEMPT_LIST = []
# A CSRF token that expires in 1 year
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

{{ if .Values.configOverrides }}
# Overrides
{{- range $key, $value := .Values.configOverrides }}
# {{ $key }}
{{ tpl $value $ }}
{{- end }}
{{- end }}

ENABLE_CORS = False
PREFERRED_URL_SCHEME = 'https'

# Use our security manager for plaid user management.
CUSTOM_SECURITY_MANAGER = PlaidSecurityManager #noqa

# Uncomment to setup Your App name
APP_NAME = 'PlaidCloud'

# Uncomment to setup an App icon
APP_ICON = '/static/assets/images/plaidcloud.png'


RABBITMQ_CONNECTION_INFO = {
    'host': '{{ .Values.rabbitmq.host }}',
    'port': '{{ .Values.rabbitmq.port }}',
    'queue': '{{ .Values.rabbitmq.queue }}',
    'vhost': '{{ .Values.rabbitmq.vhost }}',
    'username': '{{ .Values.rabbitmq.username }}',
    'password': '{{ .Values.rabbitmq.password }}',
}

{{- if .Values.redis.enabled }}
CACHE_CONFIG: CacheConfig = {
    {{- if .Values.redis.group }}
    'CACHE_TYPE': 'redissentinel',
    'CACHE_REDIS_SENTINELS': [("{{ .Values.redis.host }}", {{ .Values.redis.port }})],
    'CACHE_REDIS_SENTINEL_MASTER': "{{ .Values.redis.group }}",
    {{- else }}
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_HOST': '{{ template "superset.fullname" . }}-redis-headless',
    'CACHE_REDIS_PORT': 6379,
    {{- end }}
    'CACHE_REDIS_DB': 0,
}

TABLE_NAMES_CACHE_CONFIG: CacheConfig = {
    {{- if .Values.redis.group }}
    'CACHE_TYPE': 'redissentinel',
    'CACHE_REDIS_SENTINELS': [("{{ .Values.redis.host }}", {{ .Values.redis.port }})],
    'CACHE_REDIS_SENTINEL_MASTER': "{{ .Values.redis.group }}",
    {{- else }}
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_HOST': '{{ template "superset.fullname" . }}-redis-headless',
    'CACHE_REDIS_PORT': 6379,
    {{- end }}
    'CACHE_REDIS_DB': 1,
}

DATA_CACHE_CONFIG = CACHE_CONFIG
{{- end }}

# Disable Druid. We don't use it.
DRUID_IS_ACTIVE = False

HIDE_SCHEMA_NAMES = True

# HTTP_HEADERS = {
#     'X-Frame-Options': 'SAMEORIGIN',
#     'Cache-Control': 'no-cache, no-store, must-revalidate',
# }

# ADDITIONAL_MODULE_DS_MAP = OrderedDict(
#   [
#     ("superset.connectors.plaid.models", ["PlaidTable"]),
#   ]
# )

DISABLED_CACHE_URIS = [
    '/superset/welcome',
    '/login',
    '/logout',
    '/token',
    '/oauth_authorized',
]

# Load FAB views here.
def import_stuff(app):
    from flask import request

    @app.after_request
    def after_request(response):
        location = response.headers.get('Location')
        if location and location.startswith('http://'):
            response.headers.set('Location', location.replace('http://', 'https://', 1))
        if any(request.path.startswith(u) for u in DISABLED_CACHE_URIS):
            response.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate')
        return response

FLASK_APP_MUTATOR = import_stuff

CSRF_ENABLED = True

# We don't want users to be able to register through UI. PlaidSecurityManager
# will register a user automatically if they can connect via oauth.
AUTH_USER_REGISTRATION = False

# If users can register for an account (see above setting), this would be their default role.
#AUTH_USER_REGISTRATION_ROLE = "Public"
{{- if .Values.oidc.enabled }}
AUTH_TYPE = AUTH_OID
OIDC_PARAMS = {
    "client_id": "{{ .Values.oidc.clientId }}",
    "client_secret": "{{ .Values.oidc.clientSecret }}",
    "token_url": "{{ .Values.oidc.tokenEndpoint }}",
    # token_params: {},
    "auth_url": "{{ .Values.oidc.authEndpoint }}",
    "auth_params": {
        "prompt": "none",
    },
    "base_url": "{{ .Values.oidc.baseUrl }}",
    "jwks_uri": "{{ .Values.oidc.jwksEndpoint }}",
    "client_kwargs": {
        'scope': 'openid profile',
        'token_endpoint_auth_method': 'client_secret_post',
    },
}
{{- end }}
{{- end }}

{{- define "superset-permissions" }}
PLAID_BASE_PERMISSIONS = {
    #"all_database_access": {"all_database_access"},
    #"all_datasource_access": {"all_datasource_access"},
    #"all_query_access": {"all_query_access"},
    "can_activate": {"TabStateView"},
    #"can_add": {"RoleModelView", "UserOIDModelView"},
    "can_add_slices": {"Superset"},
    "can_annotation_json": {"Superset"},
    "can_approve": {"Superset"},
    "can_available_domains": {"Superset"},
    "can_copy_dash": {"Superset"},
    "can_created_dashboards": {"Superset"},
    "can_created_slices": {"Superset"},
    "can_csrf_token": {"Superset"},
    "can_csv": {"Superset"},
    "can_dashboard": {"Superset"},
    "can_datasources": {"Superset"},
    "can_delete": {
        #"RoleModelView",
        "TableSchemaView",
        "TabStateView",
        #"UserOIDModelView",
    },
    "can_delete_query": {"TabStateView"},
    #"can_edit": {"RoleModelView", "UserOIDModelView"},
    "can_estimate_query_cost": {"Superset"},
    "can_expanded": {"TableSchemaView"},
    "can_explore": {"Superset"},
    "can_explore_json": {"Superset"},
    "can_external_metadata": {"Datasource"},
    "can_extra_table_metadata": {"Superset"},
    "can_fave_dashboards": {"Superset"},
    "can_fave_dashboards_by_username": {"Superset"},
    "can_fave_slices": {"Superset"},
    "can_favstar": {"Superset"},
    "can_fetch_datasource_metadata": {"Superset"},
    "can_filter": {"Superset"},
    "can_get": {
		"Datasource",
		"MenuApi",
		"OpenApi",
		"TabStateView",
	},
    "can_import_dashboards": {"Superset"},
    "can_invalidate": {"CacheRestApi"},
    #"can_list": {"RoleModelView", "UserOIDModelView"},
    "can_log": {"Superset"},
    "can_migrate_query": {"TabStateView"},
    "can_my_queries": {"SqlLab"},
    #"can_override_role_permissions": {"Superset"},
    "can_post": {"TableSchemaView", "TabStateView"},
    #"can_profile": {"Superset"},
    "can_publish": {"Superset"},
    "can_put": {"TabStateView"},
    "can_queries": {"Superset"},
    #"can_query": {"Api"},
    #"can_query_form_data": {"Api"},
    "can_read": {
        "Annotation",
        "Chart",
        "CssTemplate",
        "Dashboard",
        "Database",
        "Dataset",
        "Log",
        "Query",
        "ReportSchedule",
        "SavedQuery",
    },
    "can_recent_activity": {"Superset"},
    #"can_request_access": {"Superset"},
    "can_results": {"Superset"},
    "can_save": {"Datasource"},
    "can_save_dash": {"Superset"},
    "can_schemas": {"Superset"},
    "can_schemas_access_for_csv_upload": {"Superset"},
    "can_search_queries": {"Superset"},
    "can_select_star": {"Superset"},
    "can_shortner": {"R"},
    #"can_show": {"RoleModelView", "SwaggerView", "UserOIDModelView"},
    "can_slice": {"Superset"},
    "can_slice_json": {"Superset"},
    "can_sql_json": {"Superset"},
    "can_sqllab": {"Superset"},
    "can_sqllab_table_viz": {"Superset"},
    "can_sqllab_viz": {"Superset"},
    "can_stop_query": {"Superset"},
    #"can_sync_druid_source": {"Superset"},
    "can_tables": {"Superset"},
    "can_testconn": {"Superset"},
    "can_this_form_get": {
        "CsvToDatabaseView",
        "ExcelToDatabaseView",
        "ResetMyPasswordView",
        "ResetPasswordView",
        "UserInfoEditView",
    },
    "can_this_form_post": {
        "CsvToDatabaseView",
        "ExcelToDatabaseView",
        "ResetMyPasswordView",
        "ResetPasswordView",
        "UserInfoEditView",
    },
    #"can_userinfo": {"UserOIDModelView"},
    "can_user_slices": {"Superset"},
    "can_validate_sql_json": {"Superset"},
    "can_warm_up_cache": {"Superset"},
    "can_write": {
        "Annotation",
        "Chart",
        "CssTemplate",
        "Dashboard",
        #"Database",
        "Dataset",
        "Log",
        "ReportSchedule",
        "SavedQuery",
    },
    #"copyrole": {"RoleModelView"},
    "database_access": {"[examples].(id:1)"},
    "datasource_access": {
        "[examples].[bart_lines](id:12)",
        "[examples].[birth_france_by_region](id:7)",
        "[examples].[birth_names](id:3)",
        "[examples].[energy_usage](id:1)",
        "[examples].[flights](id:11)",
        "[examples].[long_lat](id:6)",
        "[examples].[multiformat_time_series](id:8)",
        "[examples].[paris_iris_mapping](id:9)",
        "[examples].[random_time_series](id:5)",
        "[examples].[sf_population_polygons](id:10)",
        "[examples].[unicode_test](id:4)",
        "[examples].[wb_health_population](id:2)",
    },
    "menu_access": {
        #"Action Log",
        "Annotation Layers",
        "Charts",
        "CSS Templates",
        "Dashboards",
        "Data",
        #"Databases",
        "Datasets",
        "Import Dashboards",
        #"List Roles",
        #"List Users",
        "Manage",
        "Query Search",
        "Saved Queries",
        "Security",
        "SQL Editor",
        "SQL Lab",
        #"Upload a CSV",
        #"Upload Excel",
    },
    #"userinfoedit": {"UserOIDModelView"},
}

{{- end }}
