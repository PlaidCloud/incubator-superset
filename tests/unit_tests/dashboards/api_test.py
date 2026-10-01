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

from typing import Any
from unittest.mock import MagicMock

import pytest

from superset.dashboards.schemas import DashboardGetResponseSchema


@pytest.fixture
def mock_dashboard() -> MagicMock:
    dash = MagicMock()
    dash.id = 1
    dash.slug = "test-slug"
    dash.url = "/superset/dashboard/test-slug/"
    dash.dashboard_title = "Test Dashboard"
    dash.thumbnail_url = "http://example.com/thumb.png"
    dash.published = True
    dash.css = ""
    dash.theme = None
    dash.json_metadata = "{}"
    dash.position_json = "{}"
    dash.certified_by = None
    dash.certification_details = None
    dash.changed_by_name = "admin"
    dash.changed_by = MagicMock(id=1, first_name="admin", last_name="user")
    dash.changed_on = None
    dash.changed_on_humanized = "2 days ago"
    dash.created_by = MagicMock(id=1, first_name="admin", last_name="user")
    dash.created_on_humanized = "5 days ago"
    dash.charts = []
    dash.owners = []
    dash.roles = []
    dash.tags = []
    dash.custom_tags = []
    dash.is_managed_externally = False
    dash.uuid = None
    return dash


def test_schema_column_selection_excludes_thumbnail(
    mock_dashboard: MagicMock,
) -> None:
    schema = DashboardGetResponseSchema(only=["id", "dashboard_title"])
    result = schema.dump(mock_dashboard)
    assert "id" in result
    assert "dashboard_title" in result
    assert "thumbnail_url" not in result
    assert "slug" not in result


def test_schema_column_selection_with_data_key(
    mock_dashboard: MagicMock,
) -> None:
    """Fields with data_key should work when using the internal field name."""
    schema = DashboardGetResponseSchema(only=["id", "changed_on_humanized"])
    result = schema.dump(mock_dashboard)
    assert "id" in result
    assert "changed_on_delta_humanized" in result
    assert "dashboard_title" not in result


def test_schema_full_response_includes_thumbnail(
    mock_dashboard: MagicMock,
) -> None:
    schema = DashboardGetResponseSchema()
    result = schema.dump(mock_dashboard)
    assert "thumbnail_url" in result
    assert "id" in result
    assert "dashboard_title" in result


def test_data_key_mapping_logic() -> None:
    """The key_to_name mapping used in the API correctly maps data_key to field name."""
    schema = DashboardGetResponseSchema()
    key_to_name = {
        field.data_key or name: name for name, field in schema.fields.items()
    }
    # changed_on_delta_humanized is the data_key for changed_on_humanized
    assert key_to_name["changed_on_delta_humanized"] == "changed_on_humanized"
    assert key_to_name["created_on_delta_humanized"] == "created_on_humanized"
    # fields without data_key map to themselves
    assert key_to_name["id"] == "id"
    assert key_to_name["thumbnail_url"] == "thumbnail_url"


AUDIENCE_RESULT = {
    "state": "groups",
    "groups": [{"id": "a", "name": "Fin", "deleted": False, "member_count": 3}],
    "foreign_roles": [],
    "owners": ["Paul"],
    "admin_count": 2,
}


def test_get_audience_reads_plaid_and_projects_the_payload(
    mocker: Any, client: Any, full_api_access: None
) -> None:
    from superset import security_manager

    mocker.patch(
        "superset.dashboards.api.DashboardDAO.get_by_id_or_slug",
        return_value=MagicMock(id=7),
    )
    mocker.patch.object(security_manager, "get_rpc", create=True)
    mocker.patch.object(security_manager, "_rpc_token", create=True, return_value="tok")
    call = mocker.patch("plaid.security.call_plaid_rpc", return_value=AUDIENCE_RESULT)

    response = client.get("/api/v1/dashboard/7/audience")

    assert response.status_code == 200
    assert response.json["result"] == {
        "state": "groups",
        "groups": [{"id": "a", "name": "Fin", "deleted": False}],
        "foreign_roles": [],
    }
    call.assert_called_once_with(
        "dashboard/dashboard/audience", {"dashboard_id": 7}, "tok"
    )


def test_get_audience_is_501_without_plaid(client: Any, full_api_access: None) -> None:
    assert client.get("/api/v1/dashboard/7/audience").status_code == 501


@pytest.mark.parametrize(
    "error_name", ["DashboardNotFoundError", "DashboardAccessDeniedError"]
)
def test_get_audience_hidden_dashboard_is_404_without_calling_plaid(
    mocker: Any, client: Any, full_api_access: None, error_name: str
) -> None:
    from superset import security_manager
    from superset.dashboards import api

    mocker.patch.object(security_manager, "get_rpc", create=True)
    mocker.patch(
        "superset.dashboards.api.DashboardDAO.get_by_id_or_slug",
        side_effect=getattr(api, error_name)(),
    )
    call = mocker.patch("plaid.security.call_plaid_rpc")

    assert client.get("/api/v1/dashboard/7/audience").status_code == 404
    call.assert_not_called()


def test_get_audience_rpc_failure_is_502(
    mocker: Any, client: Any, full_api_access: None
) -> None:
    from superset import security_manager

    mocker.patch(
        "superset.dashboards.api.DashboardDAO.get_by_id_or_slug",
        return_value=MagicMock(id=7),
    )
    mocker.patch.object(security_manager, "get_rpc", create=True)
    mocker.patch.object(security_manager, "_rpc_token", create=True, return_value="tok")
    mocker.patch("plaid.security.call_plaid_rpc", side_effect=RuntimeError("down"))

    assert client.get("/api/v1/dashboard/7/audience").status_code == 502


def test_get_audience_non_object_reply_is_502(
    mocker: Any, client: Any, full_api_access: None
) -> None:
    from superset import security_manager

    mocker.patch(
        "superset.dashboards.api.DashboardDAO.get_by_id_or_slug",
        return_value=MagicMock(id=7),
    )
    mocker.patch.object(security_manager, "get_rpc", create=True)
    mocker.patch.object(security_manager, "_rpc_token", create=True, return_value="tok")
    mocker.patch("plaid.security.call_plaid_rpc", return_value=["not", "an", "object"])

    assert client.get("/api/v1/dashboard/7/audience").status_code == 502


SENT = {"status": "sent", "message": "Your request was sent"}


@pytest.fixture
def plaid_rpc(mocker: Any) -> Any:
    from superset import security_manager

    mocker.patch.object(security_manager, "get_rpc", create=True)
    mocker.patch.object(security_manager, "_rpc_token", create=True, return_value="tok")
    return mocker.patch("plaid.security.call_plaid_rpc", return_value=dict(SENT))


def test_request_access_calls_the_plaid_rpc_with_the_users_token(
    client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    response = client.post(
        "/api/v1/dashboard/access_request",
        json={"dashboard_id": 7, "note": "<b>pls</b>"},
    )

    assert response.status_code == 200
    assert response.json == SENT
    plaid_rpc.assert_called_once_with(
        "dashboard/dashboard/request_access",
        {"dashboard_id": 7, "note": "<b>pls</b>"},
        "tok",
    )


def test_request_access_answers_alike_for_nonexistent_draft_sentinel_and_group_ids(
    mocker: Any, client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    """Nonexistent, Draft, sentinel-restricted and group-restricted ids."""
    lookup = mocker.patch("superset.dashboards.api.DashboardDAO.get_by_id_or_slug")

    responses = [
        client.post("/api/v1/dashboard/access_request", json={"dashboard_id": i})
        for i in (999999, 11, 12, 13)
    ]

    assert [r.status_code for r in responses] == [200] * 4
    assert [r.json for r in responses] == [SENT] * 4
    assert [r.get_data() for r in responses] == [responses[0].get_data()] * 4
    assert [c.args[1]["dashboard_id"] for c in plaid_rpc.call_args_list] == [
        999999,
        11,
        12,
        13,
    ]
    lookup.assert_not_called()


def test_request_access_forwards_a_slug_as_is_without_resolving_it(
    mocker: Any, client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    lookup = mocker.patch("superset.dashboards.api.DashboardDAO.get_by_id_or_slug")

    response = client.post(
        "/api/v1/dashboard/access_request", json={"dashboard_id": "my-slug"}
    )

    assert (response.status_code, response.json) == (200, SENT)
    assert plaid_rpc.call_args.args[1] == {"dashboard_id": "my-slug", "note": ""}
    lookup.assert_not_called()


@pytest.mark.parametrize(
    "dashboard_id", [0, -1, 2**31, True, None, "a b", "x" * 256, "../etc", [7]]
)
def test_request_access_rejects_an_id_that_is_neither_int4_nor_slug(
    client: Any, full_api_access: None, plaid_rpc: Any, dashboard_id: Any
) -> None:
    response = client.post(
        "/api/v1/dashboard/access_request", json={"dashboard_id": dashboard_id}
    )

    assert response.status_code == 400
    plaid_rpc.assert_not_called()


def test_request_access_logs_the_note_length_only(
    caplog: Any, client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    caplog.set_level("INFO")

    client.post(
        "/api/v1/dashboard/access_request",
        json={"dashboard_id": 7, "note": "secret-note"},
    )

    assert "note of 11 characters" in caplog.text
    assert "secret-note" not in caplog.text


def test_request_access_note_over_500_is_400(
    client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    response = client.post(
        "/api/v1/dashboard/access_request",
        json={"dashboard_id": 7, "note": "x" * 501},
    )

    assert response.status_code == 400
    plaid_rpc.assert_not_called()


def test_request_access_plaid_failure_is_502_without_retry(
    client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    plaid_rpc.side_effect = RuntimeError("down")

    response = client.post("/api/v1/dashboard/access_request", json={"dashboard_id": 7})

    assert response.status_code == 502
    assert plaid_rpc.call_count == 1


def test_request_access_is_501_without_plaid(
    client: Any, full_api_access: None
) -> None:
    response = client.post("/api/v1/dashboard/access_request", json={"dashboard_id": 7})

    assert response.status_code == 501


@pytest.mark.parametrize("path", ["charts", "datasets"])
def test_unopenable_dashboard_looks_like_a_missing_one_on_plaid(
    mocker: Any, client: Any, full_api_access: None, path: str
) -> None:
    from superset import security_manager
    from superset.dashboards import api

    mocker.patch.object(security_manager, "get_rpc", create=True)
    results = []
    for error in (api.DashboardNotFoundError(), api.DashboardAccessDeniedError()):
        mocker.patch(
            "superset.dashboards.api.DashboardDAO.get_charts_for_dashboard",
            side_effect=error,
        )
        mocker.patch(
            "superset.dashboards.api.DashboardDAO.get_datasets_for_dashboard",
            side_effect=error,
        )
        mocker.patch(
            "superset.dashboards.api.DashboardDAO.get_by_id_or_slug", side_effect=error
        )
        response = client.get(f"/api/v1/dashboard/7/{path}")
        results.append((response.status_code, response.get_data()))

    assert results[0][0] == 404
    assert results[0] == results[1]


def test_unopenable_dashboard_is_still_403_on_stock_superset(
    mocker: Any, client: Any, full_api_access: None
) -> None:
    from superset.dashboards import api

    mocker.patch(
        "superset.dashboards.api.DashboardDAO.get_charts_for_dashboard",
        side_effect=api.DashboardAccessDeniedError(),
    )

    assert client.get("/api/v1/dashboard/7/charts").status_code == 403


CONTEXT = {"title": "Recon", "owners": ["Paul", "Chris"]}


def test_access_context_returns_what_plaid_returns(
    client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    plaid_rpc.return_value = {**CONTEXT, "extra": "dropped"}

    response = client.post("/api/v1/dashboard/access_context", json={"dashboard_id": 7})

    assert (response.status_code, response.json) == (200, {"result": CONTEXT})
    plaid_rpc.assert_called_once_with(
        "dashboard/dashboard/request_context", {"dashboard_id": 7}, "tok"
    )


@pytest.mark.parametrize(
    "reply",
    [{}, None, [], {"title": 5, "owners": []}, {"title": "x", "owners": [1]}],
)
def test_access_context_is_empty_for_anything_but_title_and_owners(
    client: Any, full_api_access: None, plaid_rpc: Any, reply: Any
) -> None:
    plaid_rpc.return_value = reply

    response = client.post("/api/v1/dashboard/access_context", json={"dashboard_id": 7})

    assert (response.status_code, response.json) == (200, {"result": {}})


def test_access_context_treats_an_rpc_failure_as_empty(
    client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    plaid_rpc.side_effect = RuntimeError("down")

    response = client.post(
        "/api/v1/dashboard/access_context", json={"dashboard_id": "a-slug"}
    )

    assert (response.status_code, response.json) == (200, {"result": {}})
    assert plaid_rpc.call_args.args[1] == {"dashboard_id": "a-slug"}


def test_access_context_rejects_a_bad_id(
    client: Any, full_api_access: None, plaid_rpc: Any
) -> None:
    response = client.post("/api/v1/dashboard/access_context", json={"dashboard_id": 0})

    assert response.status_code == 400
    plaid_rpc.assert_not_called()


def _both_errors(mocker: Any) -> list[Exception]:
    from superset import security_manager
    from superset.dashboards import api

    mocker.patch.object(security_manager, "get_rpc", create=True)
    return [api.DashboardNotFoundError(), api.DashboardAccessDeniedError()]


@pytest.mark.parametrize("path", ["", "/tabs"])
def test_get_and_tabs_answer_alike_for_missing_and_denied(
    mocker: Any, client: Any, full_api_access: None, path: str
) -> None:
    results = []
    for error in _both_errors(mocker):
        mocker.patch(
            "superset.dashboards.api.DashboardDAO.get_by_id_or_slug",
            side_effect=error,
        )
        mocker.patch(
            "superset.dashboards.api.DashboardDAO.get_tabs_for_dashboard",
            side_effect=error,
        )
        response = client.get(f"/api/v1/dashboard/7{path}")
        results.append((response.status_code, response.get_data()))

    assert results[0][0] == 404
    assert results[0] == results[1]


@pytest.mark.parametrize(
    "method, command",
    [
        ("post", "AddFavoriteDashboardCommand"),
        ("delete", "DelFavoriteDashboardCommand"),
    ],
)
def test_favorites_answer_alike_for_missing_and_denied(
    mocker: Any, client: Any, full_api_access: None, method: str, command: str
) -> None:
    results = []
    for error in _both_errors(mocker):
        mocker.patch(
            f"superset.dashboards.api.{command}",
            return_value=MagicMock(run=MagicMock(side_effect=error)),
        )
        response = getattr(client, method)("/api/v1/dashboard/7/favorites/")
        results.append((response.status_code, response.get_data()))

    assert results[0][0] == 404
    assert results[0] == results[1]


def test_permalink_create_answers_alike_for_missing_and_denied(
    mocker: Any, client: Any, full_api_access: None
) -> None:
    results = []
    for error in _both_errors(mocker):
        mocker.patch(
            "superset.dashboards.permalink.api.CreateDashboardPermalinkCommand",
            return_value=MagicMock(run=MagicMock(side_effect=error)),
        )
        response = client.post("/api/v1/dashboard/7/permalink", json={})
        results.append((response.status_code, response.get_data()))

    assert results[0][0] == 404
    assert results[0] == results[1]


@pytest.mark.parametrize(
    "method, path",
    [
        ("post", "/api/v1/dashboard/7/filter_state"),
        ("put", "/api/v1/dashboard/7/filter_state/k"),
        ("get", "/api/v1/dashboard/7/filter_state/k"),
        ("delete", "/api/v1/dashboard/7/filter_state/k"),
    ],
)
def test_filter_state_answers_alike_for_missing_and_denied(
    mocker: Any, client: Any, full_api_access: None, method: str, path: str
) -> None:
    results = []
    for error in _both_errors(mocker):
        mocker.patch(
            "superset.commands.dashboard.filter_state.utils.DashboardDAO."
            "get_by_id_or_slug",
            side_effect=error,
        )
        response = getattr(client, method)(path, json={"value": "{}"})
        results.append((response.status_code, response.get_data()))

    assert results[0][0] == 404
    assert results[0] == results[1]


def _page(mocker: Any, client: Any, dashboard: Any, *, plaid: bool) -> Any:
    from superset import security_manager
    from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
    from superset.exceptions import SupersetSecurityException

    if plaid:
        mocker.patch.object(security_manager, "get_rpc", create=True)
    mocker.patch("superset.views.core.get_current_user", return_value=MagicMock())
    mocker.patch("superset.views.core.bootstrap_user_data", return_value={})
    mocker.patch("superset.views.core.common_bootstrap_payload", return_value={})
    shell = mocker.patch(
        "superset.views.core.Superset.render_app_template",
        side_effect=lambda **kw: f"SHELL:{kw['title']}",
    )
    if dashboard is not None:
        dashboard.raise_for_access.side_effect = SupersetSecurityException(
            SupersetError(
                error_type=SupersetErrorType.DASHBOARD_SECURITY_ACCESS_ERROR,
                message="no",
                level=ErrorLevel.ERROR,
            )
        )
    mocker.patch("superset.views.core.Dashboard.get", return_value=dashboard)
    response = client.get("/superset/dashboard/7/")
    return response.status_code, response.get_data(as_text=True), shell


def test_full_page_load_of_a_missing_or_denied_dashboard_renders_the_same_shell(
    mocker: Any, client: Any, full_api_access: None
) -> None:
    missing = _page(mocker, client, None, plaid=True)
    denied = _page(mocker, client, MagicMock(dashboard_title="Secret"), plaid=True)

    assert missing[:2] == denied[:2] == (404, "SHELL:Dashboard")


def test_full_page_load_keeps_the_static_404_on_stock_superset(
    mocker: Any, client: Any, full_api_access: None
) -> None:
    status, body, shell = _page(mocker, client, None, plaid=False)

    assert status == 404
    assert "SHELL" not in body
    shell.assert_not_called()
