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
# pylint: disable=unused-argument, import-outside-toplevel, protected-access

from datetime import datetime
from typing import Any, Optional

import pytest
from pytest_mock import MockerFixture

from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
from superset.utils import json
from tests.unit_tests.db_engine_specs.utils import assert_convert_dttm
from tests.unit_tests.fixtures.common import dttm  # noqa: F401


def test_get_parameters_from_uri() -> None:
    """
    Test that the result from ``get_parameters_from_uri`` is JSON serializable.
    """
    from superset.db_engine_specs.databricks import (
        DatabricksNativeEngineSpec,
        DatabricksNativeParametersType,
    )

    parameters = DatabricksNativeEngineSpec.get_parameters_from_uri(
        "databricks+connector://token:abc12345@my_hostname:1234/test"
    )
    assert parameters == DatabricksNativeParametersType(
        {
            "access_token": "abc12345",
            "host": "my_hostname",
            "port": 1234,
            "database": "test",
            "encryption": False,
        }
    )
    assert json.loads(json.dumps(parameters)) == parameters


def test_build_sqlalchemy_uri() -> None:
    """
    test that the parameters are can correctly be compiled into a
    sqlalchemy_uri
    """
    from superset.db_engine_specs.databricks import (
        DatabricksNativeEngineSpec,
        DatabricksNativeParametersType,
    )

    parameters = DatabricksNativeParametersType(
        {
            "access_token": "abc12345",
            "host": "my_hostname",
            "port": 1234,
            "database": "test",
            "encryption": False,
        }
    )
    encrypted_extra = None
    sqlalchemy_uri = DatabricksNativeEngineSpec.build_sqlalchemy_uri(
        parameters, encrypted_extra
    )
    assert sqlalchemy_uri == (
        "databricks+connector://token:abc12345@my_hostname:1234/test"
    )


def test_parameters_json_schema() -> None:
    """
    test that the parameters schema can be converted to json
    """
    from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec

    json_schema = DatabricksNativeEngineSpec.parameters_json_schema()

    assert json_schema == {
        "type": "object",
        "properties": {
            "access_token": {"type": "string"},
            "database": {"type": "string"},
            "encryption": {
                "description": "Use an encrypted connection to the database",
                "type": "boolean",
            },
            "host": {"type": "string"},
            "http_path": {"type": "string"},
            "port": {
                "description": "Database port",
                "maximum": 65536,
                "minimum": 0,
                "type": "integer",
            },
        },
        "required": ["access_token", "database", "host", "http_path", "port"],
    }


def test_get_extra_params(mocker: MockerFixture) -> None:
    """
    Test the ``get_extra_params`` method.
    """
    from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec

    database = mocker.MagicMock()

    database.extra = {}
    assert DatabricksNativeEngineSpec.get_extra_params(database) == {
        "engine_params": {
            "connect_args": {
                "http_headers": [("User-Agent", "PlaidCloud_Lakehouse")],
                "user_agent_entry": "PlaidCloud_Lakehouse",
            }
        }
    }

    database.extra = json.dumps(
        {
            "engine_params": {
                "connect_args": {
                    "http_headers": [
                        ("User-Agent", "Custom user agent"),
                        ("X-Trace", "1"),
                    ],
                    "_user_agent_entry": "Custom user agent",
                    "foo": "bar",
                }
            }
        }
    )
    assert DatabricksNativeEngineSpec.get_extra_params(database) == {
        "engine_params": {
            "connect_args": {
                "http_headers": [
                    ("X-Trace", "1"),
                    ("User-Agent", "PlaidCloud_Lakehouse"),
                ],
                "user_agent_entry": "PlaidCloud_Lakehouse",
                "foo": "bar",
            }
        }
    }

    # it should also remove whitespace from http_path
    database.extra = json.dumps(
        {
            "engine_params": {
                "connect_args": {
                    "http_headers": [("User-Agent", "Custom user agent")],
                    "user_agent_entry": "Custom user agent",
                    "http_path": "/some_path_here_with_whitespace ",
                }
            }
        }
    )
    assert DatabricksNativeEngineSpec.get_extra_params(database) == {
        "engine_params": {
            "connect_args": {
                "http_headers": [("User-Agent", "PlaidCloud_Lakehouse")],
                "user_agent_entry": "PlaidCloud_Lakehouse",
                "http_path": "/some_path_here_with_whitespace",
            }
        }
    }


def test_extract_errors() -> None:
    """
    Test that custom error messages are extracted correctly.
    """

    msg = ": mismatched input 'from_'. Expecting: "
    result = DatabricksNativeEngineSpec.extract_errors(Exception(msg))

    assert result == [
        SupersetError(
            message=": mismatched input 'from_'. Expecting: ",
            error_type=SupersetErrorType.GENERIC_DB_ENGINE_ERROR,
            level=ErrorLevel.ERROR,
            extra={
                "engine_name": "Databricks (legacy)",
                "issue_codes": [
                    {
                        "code": 1002,
                        "message": "Issue 1002 - The database returned an unexpected error.",  # noqa: E501
                    }
                ],
            },
        )
    ]


def test_extract_errors_with_context() -> None:
    """
    Test that custom error messages are extracted correctly with context.
    """

    msg = ": mismatched input 'from_'. Expecting: "
    context = {"hostname": "foo"}
    result = DatabricksNativeEngineSpec.extract_errors(Exception(msg), context)

    assert result == [
        SupersetError(
            message=": mismatched input 'from_'. Expecting: ",
            error_type=SupersetErrorType.GENERIC_DB_ENGINE_ERROR,
            level=ErrorLevel.ERROR,
            extra={
                "engine_name": "Databricks (legacy)",
                "issue_codes": [
                    {
                        "code": 1002,
                        "message": "Issue 1002 - The database returned an unexpected error.",  # noqa: E501
                    }
                ],
            },
        )
    ]


@pytest.mark.parametrize(
    "target_type,expected_result",
    [
        ("Date", "CAST('2019-01-02' AS DATE)"),
        (
            "TimeStamp",
            "CAST('2019-01-02 03:04:05.678900' AS TIMESTAMP)",
        ),
        ("UnknownType", None),
    ],
)
def test_convert_dttm(
    target_type: str,
    expected_result: Optional[str],
    dttm: datetime,  # noqa: F811
) -> None:
    from superset.db_engine_specs.databricks import (
        DatabricksNativeEngineSpec as spec,  # noqa: N813
    )

    assert_convert_dttm(spec, target_type, expected_result, dttm)


def test_get_prequeries(mocker: MockerFixture) -> None:
    """
    Test the ``get_prequeries`` method.
    """
    from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec

    database = mocker.MagicMock()

    assert DatabricksNativeEngineSpec.get_prequeries(database) == []
    assert DatabricksNativeEngineSpec.get_prequeries(database, schema="test") == [
        "USE SCHEMA `test`",
    ]
    assert DatabricksNativeEngineSpec.get_prequeries(database, catalog="test") == [
        "USE CATALOG `test`",
    ]
    assert DatabricksNativeEngineSpec.get_prequeries(
        database, catalog="foo", schema="bar"
    ) == [
        "USE CATALOG `foo`",
        "USE SCHEMA `bar`",
    ]

    assert DatabricksNativeEngineSpec.get_prequeries(
        database, catalog="with-hyphen", schema="hyphen-again"
    ) == [
        "USE CATALOG `with-hyphen`",
        "USE SCHEMA `hyphen-again`",
    ]

    assert DatabricksNativeEngineSpec.get_prequeries(
        database, catalog="`escaped-hyphen`", schema="`hyphen-escaped`"
    ) == [
        "USE CATALOG `escaped-hyphen`",
        "USE SCHEMA `hyphen-escaped`",
    ]


def m2m_database(
    mocker: MockerFixture, encrypted_extra: Optional[dict[str, Any]] = None
):
    database = mocker.MagicMock()
    database.url_object.host = "dbc-1.cloud.databricks.com"
    database.encrypted_extra = encrypted_extra and json.dumps(encrypted_extra)
    return database


M2M = {
    "auth_method": "oauth-m2m",
    "auth_params": {"client_id": "sp-id", "client_secret": "sp-secret"},
}


def test_oauth_m2m_credentials_refresh_on_expiry(mocker: MockerFixture) -> None:
    from superset.db_engine_specs.databricks import (
        DatabricksNativeEngineSpec,
        oauth_m2m_credentials,
    )

    oauth_m2m_credentials.cache_clear()
    clock = mocker.patch(
        "superset.db_engine_specs.databricks.time.monotonic", return_value=0.0
    )
    post = mocker.patch("superset.db_engine_specs.databricks.requests.post")
    post.return_value.json.side_effect = [
        {"access_token": "t1", "expires_in": 3600},
        {"access_token": "t2", "expires_in": 3600},
    ]
    params: dict[str, Any] = {"connect_args": {"http_path": "/sql/1"}}

    DatabricksNativeEngineSpec.update_params_from_encrypted_extra(
        m2m_database(mocker, M2M), params
    )
    provider = params["connect_args"]["credentials_provider"]
    headers = provider()

    assert params["connect_args"]["http_path"] == "/sql/1"
    assert headers() == {"Authorization": "Bearer t1"}
    clock.return_value = 3000.0
    assert headers() == {"Authorization": "Bearer t1"}
    clock.return_value = 3541.0  # within a minute of expiry
    assert headers() == {"Authorization": "Bearer t2"}
    post.assert_called_with(
        "https://dbc-1.cloud.databricks.com/oidc/v1/token",
        data={"grant_type": "client_credentials", "scope": "all-apis"},
        auth=("sp-id", "sp-secret"),
        timeout=30,
    )
    assert post.call_count == 2

    # A new engine for the next query reuses the same provider and token.
    again: dict[str, Any] = {}
    DatabricksNativeEngineSpec.update_params_from_encrypted_extra(
        m2m_database(mocker, M2M), again
    )
    assert again["connect_args"]["credentials_provider"] is provider


def test_pat_and_other_encrypted_extra_unchanged(mocker: MockerFixture) -> None:
    from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec

    params: dict[str, Any] = {}
    DatabricksNativeEngineSpec.update_params_from_encrypted_extra(
        m2m_database(mocker), params
    )
    assert params == {}

    DatabricksNativeEngineSpec.update_params_from_encrypted_extra(
        m2m_database(mocker, {"pool_size": 5}), params
    )
    assert params == {"pool_size": 5}


def test_oauth_m2m_secret_masked(mocker: MockerFixture) -> None:
    from superset.constants import PASSWORD_MASK
    from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec

    masked = DatabricksNativeEngineSpec.mask_encrypted_extra(json.dumps(M2M))

    assert masked is not None
    assert "sp-secret" not in masked
    assert json.loads(masked)["auth_params"] == PASSWORD_MASK
    assert DatabricksNativeEngineSpec.unmask_encrypted_extra(
        json.dumps(M2M), masked
    ) == json.dumps(M2M)
    rotated = {**M2M, "auth_params": {"client_id": "sp-id", "client_secret": "new"}}
    assert (
        json.loads(
            DatabricksNativeEngineSpec.unmask_encrypted_extra(  # type: ignore[arg-type]
                json.dumps(M2M), json.dumps(rotated)
            )
        )
        == rotated
    )


def test_oauth_m2m_credentials_fit_connector(mocker: MockerFixture) -> None:
    authenticators = pytest.importorskip("databricks.sql.auth.authenticators")
    from superset.db_engine_specs.databricks import OAuthM2MCredentials

    post = mocker.patch("superset.db_engine_specs.databricks.requests.post")
    post.return_value.json.return_value = {"access_token": "t1", "expires_in": 60}
    headers: dict[str, Any] = {}

    authenticators.ExternalAuthProvider(
        OAuthM2MCredentials("dbc-1.cloud.databricks.com", "sp-id", "sp-secret")
    ).add_headers(headers)

    assert headers == {"Authorization": "Bearer t1"}


@pytest.mark.parametrize(
    "host",
    [
        "evil.example.com",
        "dbc-1.cloud.databricks.com.evil.io",
        "cloud.databricks.com",
        "dbc-1.cloud-databricks.com",
        "",
    ],
)
def test_oauth_m2m_secret_only_to_databricks_hosts(
    mocker: MockerFixture, host: str
) -> None:
    from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec

    database = m2m_database(mocker, M2M)
    database.url_object.host = host
    post = mocker.patch("superset.db_engine_specs.databricks.requests.post")

    with pytest.raises(ValueError, match="Databricks workspace host"):
        DatabricksNativeEngineSpec.update_params_from_encrypted_extra(database, {})
    post.assert_not_called()


@pytest.mark.parametrize(
    "host",
    [
        "DBC-1.Cloud.Databricks.com",
        "adb-123.4.azuredatabricks.net",
        "1234.5.gcp.databricks.com",
    ],
)
def test_oauth_m2m_workspace_hosts_accepted(mocker: MockerFixture, host: str) -> None:
    from superset.db_engine_specs.databricks import DatabricksNativeEngineSpec

    database = m2m_database(mocker, M2M)
    database.url_object.host = host
    params: dict[str, Any] = {}

    DatabricksNativeEngineSpec.update_params_from_encrypted_extra(database, params)

    assert "credentials_provider" in params["connect_args"]


PLAID_SCHEMA = "report2cb4d1ff-62fc-4aa7-981a-e4db56ab2ff9"


@pytest.fixture
def databricks_dialect() -> Any:
    """Databricks dialect with the Superset monkeypatch applied (1.x dialect only)."""
    pytest.importorskip("databricks.sqlalchemy.dialect")
    from databricks.sqlalchemy.dialect import DatabricksDialect

    from superset.db_engine_specs.databricks import (
        monkeypatch_dialect_identifier_quoting,
    )

    monkeypatch_dialect_identifier_quoting()
    dialect = DatabricksDialect()
    dialect.catalog = "plaid_test"
    dialect.schema = "default"
    return dialect


def test_has_table_quotes_identifiers(databricks_dialect: Any, mocker: MockerFixture):
    connection = mocker.MagicMock()

    assert databricks_dialect.has_table(connection, "t", schema=PLAID_SCHEMA) is True

    connection.execute.assert_called_once_with(
        f"DESCRIBE TABLE `plaid_test`.`{PLAID_SCHEMA}`.`t`"
    )


def test_has_table_escapes_backticks(databricks_dialect: Any, mocker: MockerFixture):
    connection = mocker.MagicMock()

    databricks_dialect.has_table(connection, "a`b", schema="s`1", catalog="c`")

    connection.execute.assert_called_once_with("DESCRIBE TABLE `c```.`s``1`.`a``b`")


@pytest.mark.parametrize(
    "message", ["Table or view not found", "[TABLE_OR_VIEW_NOT_FOUND] nope"]
)
def test_has_table_not_found(
    databricks_dialect: Any, mocker: MockerFixture, message: str
):
    from sqlalchemy.exc import DatabaseError

    connection = mocker.MagicMock()
    connection.execute.side_effect = DatabaseError("stmt", {}, Exception(message))

    assert databricks_dialect.has_table(connection, "t") is False


def test_has_table_reraises_other_errors(
    databricks_dialect: Any, mocker: MockerFixture
):
    from sqlalchemy.exc import DatabaseError

    connection = mocker.MagicMock()
    connection.execute.side_effect = DatabaseError("stmt", {}, Exception("boom"))

    with pytest.raises(DatabaseError):
        databricks_dialect.has_table(connection, "t")


def test_get_table_and_view_names_quote_identifiers(
    databricks_dialect: Any, mocker: MockerFixture
):
    cursor = mocker.MagicMock()
    cursor.execute.return_value.fetchall.return_value = [("s", "t1", False)]
    databricks_dialect.get_connection_cursor = mocker.MagicMock()
    databricks_dialect.get_connection_cursor.return_value.__enter__.return_value = (
        cursor
    )

    assert databricks_dialect.get_table_names(None, schema=PLAID_SCHEMA) == ["t1"]
    assert databricks_dialect.get_view_names(None, schema=PLAID_SCHEMA) == ["t1"]

    assert [call.args[0] for call in cursor.execute.call_args_list] == [
        f"SHOW TABLES FROM `plaid_test`.`{PLAID_SCHEMA}`",
        f"SHOW VIEWS FROM `plaid_test`.`{PLAID_SCHEMA}`",
    ]


def test_identifier_quoting_is_applied_on_import() -> None:
    pytest.importorskip("databricks.sqlalchemy.dialect")
    from databricks.sqlalchemy.dialect import DatabricksDialect

    import superset.db_engine_specs.databricks  # noqa: F401

    module = DatabricksDialect.has_table.__module__
    assert module == "superset.db_engine_specs.databricks"
