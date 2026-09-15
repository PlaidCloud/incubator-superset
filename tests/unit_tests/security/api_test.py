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

import prison
import pytest

from superset.extensions import csrf


@pytest.mark.parametrize(
    "app",
    [{"WTF_CSRF_ENABLED": True}],
    indirect=True,
)
def test_csrf_not_exempt(app_context: None) -> None:
    """
    Test that REST API is not exempt from CSRF.
    """
    assert {blueprint.name for blueprint in csrf._exempt_blueprints} == {
        "GroupApi",
        "MenuApi",
        "SecurityApi",
        "OpenApi",
        # The fork registers SecurityManager.permission_view_menu_api =
        # SupersetPermissionViewMenuApi (superset/security/manager.py), a
        # subclass of FAB's PermissionViewMenuApi, to allow filtering by `id`
        # and by related permission/view_menu name fields (sc-23044 /
        # apache/superset#40293). FAB derives the Flask blueprint name from
        # the runtime class name, so the registered blueprint is named after
        # the fork's subclass, not the upstream base class.
        "SupersetPermissionViewMenuApi",
        "SupersetRoleApi",
        "SupersetUserApi",
        "PermissionApi",
        "ViewMenuApi",
    }


def test_user_registrations_list_omits_registration_hash(
    client: Any, full_api_access: None
) -> None:
    response = client.get("/api/v1/security/user_registrations/")

    assert response.status_code == 200
    assert "registration_hash" not in response.json["list_columns"]


@pytest.mark.parametrize("column", ["registration_hash", "password"])
def test_user_registrations_refuse_filter_on_secret_columns(
    client: Any, full_api_access: None, column: str
) -> None:
    """sc-24025: a prefix filter would read the hash one character at a time."""
    q = prison.dumps({"filters": [{"col": column, "opr": "sw", "value": "a"}]})
    response = client.get(f"/api/v1/security/user_registrations/?q={q}")

    assert response.status_code == 400


def test_user_registrations_still_filter_on_username(
    client: Any, full_api_access: None
) -> None:
    q = prison.dumps({"filters": [{"col": "username", "opr": "sw", "value": "a"}]})
    response = client.get(f"/api/v1/security/user_registrations/?q={q}")

    assert response.status_code == 200
