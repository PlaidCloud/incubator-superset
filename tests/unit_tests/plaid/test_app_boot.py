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
"""sc-23432 -- regression test for the app-boot crash that took Superset's
celerybeat and worker pods down on every beta tenant.

`PlaidSecurityManager.__init__` used to call `rls_guard.install()` eagerly.
`install()` imports `superset.row_level_security.api.RLSRestApi`, which
transitively reaches `superset.db_engine_specs.base` -- whose module-scope
Marshmallow schemas call Flask-Babel's `gettext` (`__(...)`) at import time.
FAB's own `AppBuilder.init_app` constructs the security manager at
`flask_appbuilder/base.py:201` and only registers Babel on the app two lines
later, at `:202` (`self.bm = BabelManager(self)`). Importing `RLSRestApi`
from inside that `__init__` therefore ran before Babel existed in
`app.extensions`, raising `KeyError: 'babel'` and crashing every process
that constructs the app -- web workers, celery workers, and celerybeat
alike, none of which need an HTTP request to build it.

`test_rls_guard.py`'s 42 tests all passed while this was broken: that file
deliberately imports only `plaid.rls_guard` (never `plaid.security`, never a
real app-factory boot) specifically to dodge the `plaidcloud.rpc` dependency
gate -- see its own module docstring. A test that only imports `rls_guard`
reproduces that exact blind spot. This file instead builds the app the same
way the container does: `superset.app:create_app()`, with
`CUSTOM_SECURITY_MANAGER` wired to `PlaidSecurityManager`, the way every
tenant's deployed `superset_config.py` wires it.

Runs in a subprocess rather than in-process. `superset.row_level_security.api`
(and everything it pulls in, including `db_engine_specs.base`) is *also*
imported unconditionally by Superset's own `init_views()` on every app boot,
crash or no crash. Once that import has succeeded anywhere in this pytest
process -- e.g. from another test module's `app` fixture building a plain
app earlier in the same session -- Python caches the module, and the
Babel-at-import-time crash this guards against can never reproduce again in
that process, regardless of test order. Only a fresh interpreter, with a
virgin `sys.modules`, exercises the actual import order FAB and
`plaid.security` produce at real boot.
"""

import os
import subprocess
import sys
import textwrap

import pytest

# plaid/ imports plaidcloud-rpc, which is in requirements/base.txt but not in
# the development.txt that CI installs, so this module is only importable
# where the runtime dependencies are present (the superset image). Skipping
# loudly beats a collection error that aborts the whole unit-test run -- see
# test_security.py.
pytest.importorskip("plaidcloud.rpc.connection.jsonrpc")


def test_app_boots_with_plaid_security_manager_wired(tmp_path):
    """The regression check: a fresh process constructing the app via the
    real factory entrypoint, with `PlaidSecurityManager` wired in exactly
    the way a deployed tenant wires it, must not raise.

    Before the fix, this fails with `KeyError: 'babel'` out of
    `plaid/security.py`'s `PlaidSecurityManager.__init__` ->
    `rls_guard.install()` -> `superset.row_level_security.api` ->
    `superset.db_engine_specs.base`. After the fix, `install()` is deferred
    to a `before_request` hook (see `plaid/security.py`), so construction
    alone never imports that chain.
    """
    home = tmp_path / "superset_home"
    home.mkdir()
    config_path = tmp_path / "superset_config.py"
    config_path.write_text(
        textwrap.dedent(
            """
            from plaid.security import PlaidSecurityManager

            CUSTOM_SECURITY_MANAGER = PlaidSecurityManager
            """
        )
    )

    env = {
        **os.environ,
        "SUPERSET_HOME": str(home),
        "SUPERSET_CONFIG_PATH": str(config_path),
        "SUPERSET_TESTENV": "true",
        "SUPERSET_SECRET_KEY": "not-a-secret",
    }

    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell, no untrusted input
        [sys.executable, "-c", "from superset.app import create_app; create_app()"],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert result.returncode == 0, (
        "App construction crashed in a fresh process -- this is the exact "
        "boot path every worker, celery worker, and celerybeat process runs "
        f"(sc-23432). Captured stderr:\n{result.stderr[-4000:]}"
    )
    assert "KeyError: 'babel'" not in result.stderr


def test_route_guard_installed_before_first_request_dispatches(tmp_path):
    """The window that actually matters, per sc-23432's non-negotiable: the
    guard must be installed before any request can mutate a role or RLS
    rule. Also run in a subprocess for the same cache-freshness reason as
    above, and because it needs the same `CUSTOM_SECURITY_MANAGER` wiring.

    Asserts the guard is (a) NOT installed from construction alone -- proving
    the fix actually defers it, not just happens to avoid the crash some
    other way -- and (b) IS installed after one request is dispatched through
    Flask's real WSGI test client, before that request's own view function
    would have had a chance to run.
    """
    home = tmp_path / "superset_home"
    home.mkdir()
    config_path = tmp_path / "superset_config.py"
    config_path.write_text(
        textwrap.dedent(
            """
            from plaid.security import PlaidSecurityManager

            CUSTOM_SECURITY_MANAGER = PlaidSecurityManager
            """
        )
    )

    env = {
        **os.environ,
        "SUPERSET_HOME": str(home),
        "SUPERSET_CONFIG_PATH": str(config_path),
        "SUPERSET_TESTENV": "true",
        "SUPERSET_SECRET_KEY": "not-a-secret",
    }

    script = textwrap.dedent(
        """
        from superset.app import create_app

        # Import RLSRestApi only after create_app() -- importing it beforehand
        # pulls in superset.models.core at config-load time, which raises its
        # own unrelated "App not initialized yet" out of encrypted_field_factory
        # (see plaid/security.py's ADMIN_ONLY_VIEW_MENUS comment for the same
        # gotcha). create_app()'s own init_views() already imports RLSRestApi
        # unconditionally, so it is guaranteed importable by this point.
        app = create_app()
        from superset.row_level_security.api import RLSRestApi

        assert getattr(RLSRestApi, "_plaid_rls_guard_installed", False) is False, (
            "guard should not be installed from construction alone"
        )

        client = app.test_client()
        resp = client.get("/health")
        assert resp.status_code == 200

        assert getattr(RLSRestApi, "_plaid_rls_guard_installed", False) is True, (
            "guard must be installed before the first request's view function runs"
        )
        print("OK")
        """
    )

    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell, no untrusted input
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert result.returncode == 0, (
        f"stdout:\n{result.stdout[-2000:]}\nstderr:\n{result.stderr[-4000:]}"
    )
    assert "OK" in result.stdout
