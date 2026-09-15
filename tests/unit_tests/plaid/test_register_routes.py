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
"""sc-24025: no unauthenticated self-registration route may be served on a
tenant-shaped app (AUTH_OAUTH with AUTH_USER_REGISTRATION on, which OAuth
first-login provisioning needs). Both Superset's own register view and FAB's
RegisterUserOAuthView expose /register/* without an auth decorator.

Builds the app in a fresh process, like test_app_boot.py, so the route table
reflects this config rather than whatever app another test module built."""

import os
import subprocess
import sys
import textwrap

import pytest

from superset.utils import json

# plaid/ needs plaidcloud-rpc; see test_app_boot.py.
pytest.importorskip("plaidcloud.rpc.connection.jsonrpc")

OAUTH_CONFIG = """
from flask_appbuilder.security.manager import AUTH_OAUTH
from plaid.security import PlaidSecurityManager

CUSTOM_SECURITY_MANAGER = PlaidSecurityManager
AUTH_TYPE = AUTH_OAUTH
AUTH_USER_REGISTRATION = True
AUTH_ROLES_SYNC_AT_LOGIN = False
OAUTH_PROVIDERS = [
    {
        "name": "plaidkeycloak",
        "icon": "fa-key",
        "token_key": "access_token",
        "remote_app": {
            "client_id": "superset",
            "client_secret": "not-a-secret",
            "api_base_url": "http://keycloak.invalid/realms/t/protocol/openid-connect",
            "client_kwargs": {"scope": "openid profile email roles"},
            "request_token_url": None,
            "access_token_url": "http://keycloak.invalid/token",
            "authorize_url": "http://keycloak.invalid/auth",
            "authorize_params": {},
            "jwks_uri": "http://keycloak.invalid/certs",
        },
    }
]
"""

DB_CONFIG = """
from flask_appbuilder.security.manager import AUTH_DB
from plaid.security import PlaidSecurityManager

CUSTOM_SECURITY_MANAGER = PlaidSecurityManager
AUTH_TYPE = AUTH_DB
AUTH_USER_REGISTRATION = True
"""

CHILD = """
import json
from flask_appbuilder.security.registerviews import BaseRegisterUser
from superset.app import create_app

app = create_app()
from superset.views.auth import SupersetRegisterUserView
rules = sorted(r.rule for r in app.url_map.iter_rules())
print(json.dumps({
    # FAB's admin RegisterUserModelView (/registeruser/*, @has_access) is the one
    # legitimate "register" match. The class check catches a registration view
    # even if a FAB upgrade renames it or moves its route_base.
    "register": sorted(
        f"{r.rule} {r.endpoint}"
        for r in app.url_map.iter_rules()
        if (
            "register" in (r.rule + r.endpoint).lower()
            and not r.endpoint.startswith("RegisterUserModelView.")
        )
        or isinstance(
            getattr(app.view_functions[r.endpoint], "__self__", None),
            (BaseRegisterUser, SupersetRegisterUserView),
        )
    ),
    "login": [r for r in rules if r.startswith(("/login/", "/oauth-authorized/"))],
}))
"""


# FAB mounts RegisterUserOAuthView under AUTH_OAUTH and RegisterUserDBView under
# AUTH_DB; each needs its own stub.
@pytest.mark.parametrize(
    ("config", "login_rule"),
    [(OAUTH_CONFIG, "/oauth-authorized/<provider>"), (DB_CONFIG, "/login/")],
    ids=["oauth", "db"],
)
def test_no_self_registration_route_is_served(tmp_path, config, login_rule):
    home = tmp_path / "superset_home"
    home.mkdir()
    config_path = tmp_path / "superset_config.py"
    config_path.write_text(textwrap.dedent(config))
    env = {
        **os.environ,
        "SUPERSET_HOME": str(home),
        "SUPERSET_CONFIG_PATH": str(config_path),
        "SUPERSET_TESTENV": "true",
        "SUPERSET_SECRET_KEY": "not-a-secret",
    }

    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell, no untrusted input
        [sys.executable, "-c", CHILD],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert result.returncode == 0, result.stderr[-4000:]
    routes = json.loads(result.stdout.strip().splitlines()[-1])
    assert routes["register"] == []
    # Login itself must still be routed.
    assert login_rule in routes["login"]
