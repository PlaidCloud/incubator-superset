# coding=utf-8
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
"""OAuth Proxy auth factory for the Superset MCP sidecar.

Wires a FastMCP ``OAuthProxy`` in front of the MCP server so MCP clients get
the OAuth discovery surface the bare ``JWTVerifier`` does not provide: Protected
Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414) and
proxied ``/authorize`` / ``/token`` / DCR ``/register`` against Keycloak (PKCE +
loopback redirect for local clients).

Referenced from ``superset_config.py`` as::

    from plaid.mcp_oauth import build_mcp_auth_factory, plaid_user_resolver
    MCP_AUTH_FACTORY = build_mcp_auth_factory
    MCP_USER_RESOLVER = plaid_user_resolver

``superset.mcp_service.server._create_auth_provider`` calls the factory with the
Flask app and treats a ``None`` return / raised exception as "no auth", so this
never fails open -- it degrades to plain token validation instead.

Mirrors the controlplane-rpc proxy (``plaidcloud_cp_rest.mcp.oauth``): a public
Keycloak client (no secret), ``MultiAuth`` so direct Keycloak bearer tokens also
work, and shared Redis client storage so DCR clients survive across MCP pods.
"""

import logging
from typing import Any

__author__ = "Patrick Buxton"
__maintainer__ = "Patrick Buxton <pat@plaidcloud.com>"
__copyright__ = "© Copyright 2018-2026, PlaidCloud, Inc"
__license__ = "Proprietary"

log = logging.getLogger(__name__)

# Redirect URI patterns accepted from DCR-registered MCP clients. FastMCP's
# ``ProxyDCRClient.validate_redirect_uri`` RAISES when patterns are configured
# and none match -- there is no fallback to the client's registered URIs,
# despite what its docstring says -- so a client whose callback is missing here
# cannot complete OAuth at all. Loopback covers local clients (Claude Desktop,
# Claude Code); hosted clients need their callback listed explicitly.
DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS = [
    "http://localhost:*",
    "http://127.0.0.1:*",
    "https://claude.ai/api/mcp/auth_callback",
]

# Retained for callers that imported the old name; loopback is now a subset of
# the default patterns rather than the whole of it.
LOOPBACK_REDIRECT_URIS = ["http://localhost:*", "http://127.0.0.1:*"]


def _allowed_client_redirect_uris(app: Any) -> list[str]:
    """Resolve the redirect URI patterns the OAuth proxy accepts from clients.

    Defaults to loopback plus the Claude web callback. Set
    ``MCP_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS`` to a list to add another hosted
    client without a code change; an empty list would reject every client, so
    it is treated as "unset" rather than taken literally.

    Args:
        app: The Flask application carrying the deployment's config.

    Returns:
        The redirect URI patterns to pass to ``OAuthProxy``.
    """
    configured = app.config.get("MCP_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS")
    if not configured:
        return list(DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS)
    if not isinstance(configured, (list, tuple)):
        log.error(
            "MCP_OAUTH_ALLOWED_CLIENT_REDIRECT_URIS must be a list (got %s); "
            "using defaults",
            type(configured).__name__,
        )
        return list(DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS)
    return [str(pattern) for pattern in configured]


def _keycloak_endpoints(app: Any) -> dict[str, str]:
    """Resolve Keycloak OIDC endpoints, deriving from the realm issuer.

    ``MCP_JWT_ISSUER`` is the Keycloak realm URL (e.g.
    ``https://auth.example.io/realms/PlaidCloud``); the standard endpoints hang
    off ``/protocol/openid-connect/*``. Explicit ``MCP_OAUTH_UPSTREAM_*`` config
    overrides win when set.
    """
    realm = (app.config.get("MCP_JWT_ISSUER") or "").rstrip("/")
    base = f"{realm}/protocol/openid-connect"
    return {
        "authorize": app.config.get("MCP_OAUTH_UPSTREAM_AUTHORIZE_URL")
        or f"{base}/auth",
        "token": app.config.get("MCP_OAUTH_UPSTREAM_TOKEN_URL") or f"{base}/token",
        "revoke": app.config.get("MCP_OAUTH_UPSTREAM_REVOCATION_URL")
        or f"{base}/revoke",
    }


def build_keycloak_verifier(app: Any) -> Any:
    """Build the JWTVerifier that validates Keycloak-issued access tokens."""
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    return JWTVerifier(
        jwks_uri=app.config.get("MCP_JWKS_URI"),
        issuer=app.config.get("MCP_JWT_ISSUER"),
        audience=app.config.get("MCP_JWT_AUDIENCE"),
        algorithm=app.config.get("MCP_JWT_ALGORITHM", "RS256"),
    )


def _client_storage() -> Any | None:
    """Shared Redis store for DCR-registered clients (multi-pod safe).

    Reuses Superset's ``MCP_STORE_CONFIG`` Redis via ``get_mcp_store``; returns
    ``None`` (FastMCP falls back to in-memory) when Redis is not configured.
    """
    try:
        from superset.mcp_service.storage import get_mcp_store

        return get_mcp_store(prefix="mcp_oauth_v1_")
    except Exception:  # pragma: no cover - storage is best-effort
        log.warning("MCP OAuth client storage unavailable; using in-memory store")
        return None


def build_mcp_auth_factory(app: Any) -> Any:
    """Build the MCP auth provider (factory for ``MCP_AUTH_FACTORY``).

    Returns ``MultiAuth(OAuthProxy, [verifier])`` when the proxy is configured
    (``MCP_OAUTH_CLIENT_ID`` + ``MCP_OAUTH_SIGNING_KEY`` set), else the bare
    verifier. Never raises; returns ``None`` only if even the verifier can't be
    built (``server._create_auth_provider`` treats that as "no auth", the same
    as the default factory).
    """
    try:
        verifier = build_keycloak_verifier(app)
    except Exception:
        log.exception("Failed to build MCP JWT verifier; MCP auth not configured")
        return None

    client_id = app.config.get("MCP_OAUTH_CLIENT_ID")
    signing_key = app.config.get("MCP_OAUTH_SIGNING_KEY")
    if not (client_id and signing_key):
        log.info("MCP OAuth proxy not configured; using token validation only")
        return verifier

    try:
        from fastmcp.server.auth import MultiAuth
        from fastmcp.server.auth.oauth_proxy import OAuthProxy

        service_url = (app.config.get("MCP_SERVICE_URL") or "").rstrip("/")
        # base_url is the host root, NOT the /mcp endpoint. FastMCP appends the
        # transport mount path (/mcp) itself when it derives the resource URL and
        # the .well-known discovery routes (resource_url = base_url + mcp_path).
        # Passing '<host>/mcp' here double-counts the mount and advertises a
        # bogus resource of '<host>/mcp/mcp', which strict MCP clients reject.
        base_url = app.config.get("MCP_OAUTH_BASE_URL") or service_url
        if not base_url.lower().startswith(("http://", "https://")):
            log.error(
                "MCP OAuth proxy needs an absolute MCP_SERVICE_URL/"
                "MCP_OAUTH_BASE_URL (got %r); using token validation only",
                base_url,
            )
            return verifier
        if not (
            app.config.get("MCP_JWT_ISSUER")
            or app.config.get("MCP_OAUTH_UPSTREAM_AUTHORIZE_URL")
        ):
            log.error(
                "MCP OAuth proxy needs MCP_JWT_ISSUER (or explicit upstream "
                "endpoints); using token validation only",
            )
            return verifier
        endpoints = _keycloak_endpoints(app)

        extra_authorize_params = None
        if app.config.get("MCP_JWT_AUDIENCE"):
            extra_authorize_params = {"audience": app.config["MCP_JWT_AUDIENCE"]}

        proxy = OAuthProxy(
            upstream_authorization_endpoint=endpoints["authorize"],
            upstream_token_endpoint=endpoints["token"],
            upstream_revocation_endpoint=endpoints["revoke"],
            upstream_client_id=client_id,
            # Public client: no secret, PKCE-only token endpoint auth.
            upstream_client_secret=None,
            token_endpoint_auth_method="none",  # noqa: S106 - auth method, not a secret
            forward_pkce=True,
            token_verifier=verifier,
            base_url=base_url,
            # Resolves under base_url (<host>/auth/callback); must be a valid
            # redirect URI on the upstream Keycloak client.
            redirect_path="/auth/callback",
            allowed_client_redirect_uris=_allowed_client_redirect_uris(app),
            valid_scopes=["openid", "profile", "email"],
            client_storage=_client_storage(),
            # No consent screen (matches controlplane-rpc); the resource is
            # IP-allowlisted and the upstream is a single trusted Keycloak realm.
            require_authorization_consent=False,
            jwt_signing_key=signing_key,
            extra_authorize_params=extra_authorize_params,
        )

        log.info("MCP OAuth proxy enabled (base_url=%s)", base_url)
        return MultiAuth(server=proxy, verifiers=[verifier])
    except Exception:
        # Never fail open: degrade to token validation only.
        log.exception("Failed to build MCP OAuth proxy; falling back to verifier")
        return verifier


def plaid_user_resolver(app: Any, access_token: Any) -> str | None:
    """Resolve a verified MCP access token to a Superset user key.

    Wired as ``MCP_USER_RESOLVER`` and called by
    ``superset.mcp_service.auth._resolve_user_from_jwt_context``.

    Returns the ``email`` claim, because that is what our user rows are keyed
    on: ``PlaidSecurityManager.auth_user_oauth`` looks users up by email, and
    ``oauth_user_info`` sets ``username`` from the Keycloak *display name*
    (``name``, falling back to ``preferred_username``). Superset's default
    resolver prefers ``preferred_username``, which therefore matches no user
    row on our tenants.

    ``preferred_username`` is kept as a secondary only for realms that omit the
    email claim. There is deliberately no ``client_id`` fallback -- that
    identifies the registered MCP client, not a person, and returning it would
    authenticate a request as whichever user happened to share that name.

    Args:
        app: The Flask application, unused; part of the resolver contract.
        access_token: The verified FastMCP ``AccessToken`` for this request.

    Returns:
        The claim value to look the Superset user up by, or None when the
        token carries no usable identity (the caller then fails closed).
    """
    claims = getattr(access_token, "claims", None)
    if not isinstance(claims, dict):
        log.warning("MCP access token carries no claims dict; cannot resolve user")
        return None

    identity = claims.get("email") or claims.get("preferred_username")
    if not identity:
        log.warning(
            "MCP access token has neither email nor preferred_username claim; "
            "cannot resolve user",
        )
        return None

    return str(identity)
