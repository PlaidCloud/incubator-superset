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

# pylint: disable=unused-argument, import-outside-toplevel

from typing import Any

from pytest_mock import MockerFixture


def test_get_pdf_renders_as_caller(
    mocker: MockerFixture,
    app: Any,
    client: Any,
    full_api_access: None,
) -> None:
    """
    The permalink PDF endpoint must render as the calling user, never as a
    hardcoded ``admin`` — otherwise every chart resolves RLS and
    datasource_access as admin (sc-24049).
    """
    from superset import security_manager
    from superset.dashboards.permalink import api as permalink_api

    caller = mocker.MagicMock(name="caller")
    mocker.patch.object(permalink_api, "g", mocker.MagicMock(user=caller), create=True)
    find_user = mocker.patch.object(security_manager, "find_user")

    command = mocker.patch.object(permalink_api, "GetDashboardPermalinkCommand")
    command.return_value.run.return_value = {"dashboardId": 1, "state": {}}

    screenshot = mocker.patch.object(permalink_api, "DashboardScreenshot")
    screenshot.return_value.get_pdf.return_value = b"%PDF-1.4 fake"

    response = client.get("/api/v1/dashboard/permalink/abc/pdf")

    assert response.status_code == 200
    screenshot.return_value.get_pdf.assert_called_once_with(user=caller)
    find_user.assert_not_called()
