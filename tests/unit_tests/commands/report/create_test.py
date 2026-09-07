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
"""Unit tests for CreateReportScheduleCommand.validate() alert access control."""

from __future__ import annotations

from typing import Any

import pytest
from pytest_mock import MockerFixture

from superset import security_manager
from superset.commands.report.create import CreateReportScheduleCommand
from superset.commands.report.exceptions import ReportScheduleForbiddenError
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType
from superset.exceptions import SupersetSecurityException
from superset.reports.models import ReportCreationMethod, ReportScheduleType


def _alert_props(**overrides: Any) -> dict[str, Any]:
    props: dict[str, Any] = {
        "type": ReportScheduleType.ALERT,
        "name": "alert1",
        "crontab": "0 9 * * *",
        "creation_method": ReportCreationMethod.ALERTS_REPORTS,
        "database": 5,
        "sql": "SELECT value FROM metrics",
        "owners": [],
    }
    props.update(overrides)
    return props


def _setup(mocker: MockerFixture, *, database: Any) -> None:
    mocker.patch(
        "superset.commands.report.create.ReportScheduleDAO.validate_update_uniqueness",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.report.create.ReportScheduleDAO.validate_unique_creation_method",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.report.create.DatabaseDAO.find_by_id",
        return_value=database,
    )
    mocker.patch.object(CreateReportScheduleCommand, "validate_report_frequency")
    mocker.patch.object(CreateReportScheduleCommand, "validate_chart_dashboard")
    mocker.patch.object(CreateReportScheduleCommand, "populate_owners", return_value=[])


def test_alert_create_checks_query_access(mocker: MockerFixture) -> None:
    database = mocker.Mock()
    _setup(mocker, database=database)
    raise_for_access = mocker.patch.object(security_manager, "raise_for_access")

    CreateReportScheduleCommand(_alert_props()).validate()

    raise_for_access.assert_called_once()
    assert raise_for_access.call_args.kwargs["database"] is database
    assert raise_for_access.call_args.kwargs["sql"] == "SELECT value FROM metrics"


def test_alert_create_denied_access_raises_forbidden(mocker: MockerFixture) -> None:
    database = mocker.Mock()
    _setup(mocker, database=database)
    mocker.patch.object(
        security_manager,
        "raise_for_access",
        side_effect=SupersetSecurityException(
            SupersetError(
                message="denied",
                error_type=SupersetErrorType.DATASOURCE_SECURITY_ACCESS_ERROR,
                level=ErrorLevel.ERROR,
            )
        ),
    )

    with pytest.raises(ReportScheduleForbiddenError):
        CreateReportScheduleCommand(_alert_props()).validate()
