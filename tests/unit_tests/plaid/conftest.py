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
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def rls_guard_listeners_stay_in_plaid_tests() -> Iterator[None]:
    """`rls_guard.install_orm_listeners()` attaches process-wide SQLAlchemy
    listeners. Remove them after each test so a later test elsewhere in the run
    (e.g. one that creates an `admin` user inside a request) never inherits the
    automation-user veto."""
    yield
    from flask_appbuilder.security.sqla.models import Group, Role, User
    from sqlalchemy import event

    from plaid import rls_guard

    if not getattr(Role, "_plaid_rls_orm_guard_installed", False):
        return
    listeners = [
        (Role.user, "append", rls_guard._guard_role_user_append),
        (Group.roles, "append", rls_guard._guard_group_role_append),
        (Group.users, "append", rls_guard._guard_group_user_append),
        (User.username, "set", rls_guard._guard_automation_username),
        (User, "before_delete", rls_guard._guard_automation_user_delete),
        *(
            (getattr(User, name), operation, rls_guard._guard_automation_user_change)
            for name, operations in (
                ("password", ("set",)),
                ("active", ("set",)),
                ("email", ("set",)),
                ("roles", ("append", "remove")),
                ("groups", ("append", "remove")),
            )
            for operation in operations
        ),
    ]
    for target, name, listener in listeners:
        if event.contains(target, name, listener):
            event.remove(target, name, listener)
    del Role._plaid_rls_orm_guard_installed
