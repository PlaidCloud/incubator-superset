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

"""Tests for the PlaidCloud MCP user resolver (MCP_USER_RESOLVER)."""

from types import SimpleNamespace
from typing import Any

from plaid.mcp_oauth import (
    _allowed_client_redirect_uris,
    DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS,
    plaid_user_resolver,
)


def _token(claims: Any) -> SimpleNamespace:
    """An access token stand-in that always carries a DCR client_id.

    The client_id is always populated on a real FastMCP AccessToken, so it is
    present here to prove the resolver never reaches for it.
    """
    return SimpleNamespace(claims=claims, client_id="claude-dcr-client")


APP = SimpleNamespace(config={})


def test_prefers_email_claim() -> None:
    """Email wins, because auth_user_oauth keys Superset users on email."""
    token = _token(
        {
            "email": "pat@plaidcloud.com",
            "preferred_username": "pbuxton",
            "sub": "0c8f-uuid",
        }
    )
    assert plaid_user_resolver(APP, token) == "pat@plaidcloud.com"


def test_falls_back_to_preferred_username_without_email() -> None:
    """Realms that omit the email claim still resolve to something usable."""
    token = _token({"preferred_username": "pbuxton", "sub": "0c8f-uuid"})
    assert plaid_user_resolver(APP, token) == "pbuxton"


def test_returns_none_for_sub_only_token() -> None:
    """An opaque `sub` is not a Superset user key, so the caller fails closed."""
    assert plaid_user_resolver(APP, _token({"sub": "0c8f-uuid"})) is None


def test_never_falls_back_to_client_id() -> None:
    """client_id identifies the MCP client, not a person."""
    assert plaid_user_resolver(APP, _token({})) is None
    assert plaid_user_resolver(APP, SimpleNamespace(client_id="claude")) is None


def test_returns_none_when_claims_missing_or_malformed() -> None:
    """A token with no usable claims dict resolves to None, never a guess."""
    assert plaid_user_resolver(APP, _token(None)) is None
    assert plaid_user_resolver(APP, _token("not-a-dict")) is None


def test_coerces_non_string_claim_to_string() -> None:
    """A numeric claim is returned as a string for the DB lookup."""
    assert plaid_user_resolver(APP, _token({"preferred_username": 12345})) == "12345"


# -- _allowed_client_redirect_uris --


def _app(**config: object) -> SimpleNamespace:
    return SimpleNamespace(config=dict(config))


def test_default_patterns_cover_loopback_and_claude_web() -> None:
    """Both local clients and claude.ai web can complete OAuth out of the box."""
    patterns = _allowed_client_redirect_uris(_app())
    assert "http://localhost:*" in patterns
    assert "http://127.0.0.1:*" in patterns
    assert "https://claude.ai/api/mcp/auth_callback" in patterns


def test_defaults_are_not_shared_between_calls() -> None:
    """Callers cannot mutate the module-level default list."""
    patterns = _allowed_client_redirect_uris(_app())
    patterns.append("https://evil.example.com/callback")
    assert (
        "https://evil.example.com/callback" not in DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS
    )
    assert "https://evil.example.com/callback" not in _allowed_client_redirect_uris(
        _app()
    )


def test_config_overrides_defaults() -> None:
    """A configured list replaces the defaults wholesale."""
    patterns = _allowed_client_redirect_uris(
        _app(MCP_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS=["https://example.com/cb"])
    )
    assert patterns == ["https://example.com/cb"]


def test_empty_config_falls_back_to_defaults() -> None:
    """An empty list would reject every client, so it is treated as unset."""
    assert _allowed_client_redirect_uris(
        _app(MCP_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS=[])
    ) == list(DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS)


def test_malformed_config_falls_back_to_defaults() -> None:
    """A bare string is a config mistake, not a one-element list."""
    assert _allowed_client_redirect_uris(
        _app(MCP_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS="https://example.com/cb")
    ) == list(DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS)
