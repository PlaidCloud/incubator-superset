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
"""
Dashboards on a warehouse attached by sign-in (sc-32678) query as each viewer: their
own access token, asked of plaid with their own PlaidCloud credential; a viewer with no
sign-in, the automation principal and background work are refused, never connected as
anyone else.
"""

import uuid
from types import SimpleNamespace
from unittest.mock import patch

import flask
import pytest
from sqlalchemy.engine.url import make_url

import superset
from plaid import security as plaid_security
from plaid.security import PlaidSecurityManager
from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec
from superset.db_engine_specs.snowflake import SnowflakeEngineSpec
from superset.exceptions import OAuth2RedirectError, WarehouseSignInRequiredError

DATABASE = SimpleNamespace(uuid=uuid.UUID("3f1c2b4a-0000-4000-8000-000000000001"))
TOKEN = {"access_token": "ann-access", "expires_in": 600, "username": "ANN"}


@pytest.fixture(autouse=True)
def plaid_rpc(app):
    app.config["PLAID_RPC"] = "plaid-rpc:8080"
    yield
    app.config.pop("PLAID_RPC", None)


@pytest.fixture(autouse=True)
def _fresh_cache():
    plaid_security._VIEWER_TOKENS.clear()
    yield
    plaid_security._VIEWER_TOKENS.clear()


class _Plaid:
    """plaid's viewer-token route."""

    def __init__(self, status=200, body=None):
        self.calls = []
        self.status, self.body = status, body if body is not None else TOKEN

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return SimpleNamespace(
            status_code=self.status,
            json=lambda: self.body,
            raise_for_status=lambda: None,
        )


class _Manager(PlaidSecurityManager):
    auth_type = plaid_security.AUTH_OAUTH  # a browser login, as every viewer's is


def _viewer_token(
    plaid,
    session_token="viewer-session",  # noqa: S107
    automation=False,
    clock=1000.0,
):
    manager = _Manager.__new__(_Manager)
    with (
        flask.current_app.test_request_context(),
        patch("plaid.security.requests.post", plaid),
        patch(
            "plaid.security.rls_guard.is_automation_principal", return_value=automation
        ),
        patch("plaid.security.time.monotonic", return_value=clock),
    ):
        if session_token:
            flask.session["oauth"] = (session_token, "")
        return manager.warehouse_viewer_token(DATABASE)


def test_the_viewers_own_credential_asks_plaid_for_the_viewers_token():
    plaid = _Plaid()
    assert _viewer_token(plaid) == TOKEN
    ((url, kwargs),) = plaid.calls
    assert url == "http://plaid-rpc:8080/rest/v1/analyze/warehouse-sign-in/viewer-token"
    # Nothing in the request names a user: plaid derives the viewer from their
    # credential.
    assert kwargs["json"] == {"database_uuid": str(DATABASE.uuid)}
    assert kwargs["headers"] == {"Authorization": "Bearer viewer-session"}


def test_a_token_is_reused_until_a_minute_before_it_lapses_by_its_viewer_only():
    plaid = _Plaid()
    _viewer_token(plaid, clock=1000.0)
    _viewer_token(plaid, clock=1539.0)
    assert len(plaid.calls) == 1
    _viewer_token(plaid, clock=1540.0)
    assert len(plaid.calls) == 2
    _viewer_token(plaid, session_token="someone-else", clock=1540.0)  # noqa: S106
    assert len(plaid.calls) == 3


def test_a_viewer_who_never_signed_in_is_told_how_and_gets_no_ones_token():
    sentence = "Sign in with Snowflake to view this dashboard."
    plaid = _Plaid(
        status=403, body={"detail": sentence, "data": {"code": "sign_in_required"}}
    )
    with pytest.raises(WarehouseSignInRequiredError) as refused:
        _viewer_token(plaid)
    assert refused.value.error.message == sentence
    assert refused.value.status == 403
    assert not plaid_security._VIEWER_TOKENS


@pytest.mark.parametrize(
    "session_token, automation", [(None, False), ("automation-session", True)]
)
def test_no_viewer_means_no_token(session_token, automation):
    plaid = _Plaid()
    with pytest.raises(WarehouseSignInRequiredError):
        _viewer_token(plaid, session_token=session_token, automation=automation)
    assert plaid.calls == []


def test_the_refusal_still_lets_plaid_register_the_database():
    # CreateDatabaseCommand saves a database whose connection test raises
    # OAuth2RedirectError.
    assert issubclass(WarehouseSignInRequiredError, OAuth2RedirectError)


def _database(extra):
    return SimpleNamespace(uuid=DATABASE.uuid, get_extra=lambda source=None: extra)


SIGNED_IN = {"plaid_external_lakehouse": True, "plaid_sign_in": True}


def test_snowflake_connects_as_the_viewer_with_their_default_role():
    url = make_url(
        "snowflake://PLAIDCLOUD_SVC@acct/PLAID/SCHEMA?warehouse=WH&role=PLAID_ROLE"
    )
    with patch.object(
        superset,
        "security_manager",
        SimpleNamespace(warehouse_viewer_token=lambda db: TOKEN),
    ):
        url, kwargs = SnowflakeEngineSpec.impersonate_user(
            _database(SIGNED_IN),
            "ann",
            None,
            url,
            {"connect_args": {"application": "PlaidCloud"}},
        )
    assert kwargs["connect_args"] == {
        "application": "PlaidCloud",
        "authenticator": "oauth",
        "token": "ann-access",
    }
    assert (url.username, url.password, dict(url.query)) == (
        "ANN",
        None,
        {"warehouse": "WH"},
    )


def test_databricks_connects_as_the_viewer_never_the_service_principal():
    url = make_url("databricks://token@adb-1.7.azuredatabricks.net:443/main")
    kwargs = {
        "connect_args": {
            "credentials_provider": object(),
            "user_agent_entry": "PlaidCloud",
        }
    }
    with patch.object(
        superset,
        "security_manager",
        SimpleNamespace(warehouse_viewer_token=lambda db: TOKEN),
    ):
        url, kwargs = DatabricksNativeEngineSpec.impersonate_user(
            _database(SIGNED_IN), "ann", None, url, kwargs
        )
    assert kwargs["connect_args"] == {
        "user_agent_entry": "PlaidCloud",
        "access_token": "ann-access",
    }
    assert url.password is None


@pytest.mark.parametrize(
    "extra", [{"plaid_external_lakehouse": True}, {"plaid_sign_in": True}, {}]
)
def test_any_other_database_is_untouched(extra):
    url = make_url("snowflake://PLAIDCLOUD_SVC@acct/PLAID")

    def refuse(_db):
        raise AssertionError("no viewer token for a database not marked plaid_sign_in")

    with patch.object(
        superset, "security_manager", SimpleNamespace(warehouse_viewer_token=refuse)
    ):
        new_url, kwargs = SnowflakeEngineSpec.impersonate_user(
            _database(extra), None, None, url, {}
        )
    assert new_url == url
    assert "token" not in kwargs.get("connect_args", {})


def test_a_refusal_reaches_the_query_not_a_shared_identity():
    def refuse(_db):
        raise WarehouseSignInRequiredError(
            "Sign in with Snowflake to view this dashboard."
        )

    url = make_url("snowflake://PLAIDCLOUD_SVC@acct/PLAID")
    with (
        patch.object(
            superset, "security_manager", SimpleNamespace(warehouse_viewer_token=refuse)
        ),
        pytest.raises(WarehouseSignInRequiredError),
    ):
        SnowflakeEngineSpec.impersonate_user(_database(SIGNED_IN), "ann", None, url, {})
