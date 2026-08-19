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

    from plaid.mcp_oauth import build_mcp_auth_factory
    MCP_AUTH_FACTORY = build_mcp_auth_factory

``superset.mcp_service.server._create_auth_provider`` calls the factory with the
Flask app and treats a ``None`` return / raised exception as "no auth", so this
never fails open -- it degrades to plain token validation instead.

Mirrors the controlplane-rpc proxy (``plaidcloud_cp_rest.mcp.oauth``): a public
Keycloak client (no secret), ``MultiAuth`` so direct Keycloak bearer tokens also
work, and shared Redis client storage so DCR clients survive across MCP pods.
"""

import logging
from typing import Any

__author__ = 'Patrick Buxton'
__maintainer__ = 'Patrick Buxton <pat@plaidcloud.com>'
__copyright__ = '© Copyright 2018-2026, PlaidCloud, Inc'
__license__ = 'Proprietary'

log = logging.getLogger(__name__)

# Loopback redirect patterns for local MCP clients (Claude Desktop, etc.).
LOOPBACK_REDIRECT_URIS = ['http://localhost:*', 'http://127.0.0.1:*']


def _keycloak_endpoints(app: Any) -> dict[str, str]:
    """Resolve Keycloak OIDC endpoints, deriving from the realm issuer.

    ``MCP_JWT_ISSUER`` is the Keycloak realm URL (e.g.
    ``https://auth.example.io/realms/PlaidCloud``); the standard endpoints hang
    off ``/protocol/openid-connect/*``. Explicit ``MCP_OAUTH_UPSTREAM_*`` config
    overrides win when set.
    """
    realm = (app.config.get('MCP_JWT_ISSUER') or '').rstrip('/')
    base = f'{realm}/protocol/openid-connect'
    return {
        'authorize': app.config.get('MCP_OAUTH_UPSTREAM_AUTHORIZE_URL') or f'{base}/auth',
        'token': app.config.get('MCP_OAUTH_UPSTREAM_TOKEN_URL') or f'{base}/token',
        'revoke': app.config.get('MCP_OAUTH_UPSTREAM_REVOCATION_URL') or f'{base}/revoke',
    }


def build_keycloak_verifier(app: Any) -> Any:
    """Build the JWTVerifier that validates Keycloak-issued access tokens."""
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    return JWTVerifier(
        jwks_uri=app.config.get('MCP_JWKS_URI'),
        issuer=app.config.get('MCP_JWT_ISSUER'),
        audience=app.config.get('MCP_JWT_AUDIENCE'),
        algorithm=app.config.get('MCP_JWT_ALGORITHM', 'RS256'),
    )


def _client_storage() -> Any | None:
    """Shared Redis store for DCR-registered clients (multi-pod safe).

    Reuses Superset's ``MCP_STORE_CONFIG`` Redis via ``get_mcp_store``; returns
    ``None`` (FastMCP falls back to in-memory) when Redis is not configured.
    """
    try:
        from superset.mcp_service.storage import get_mcp_store

        return get_mcp_store(prefix='mcp_oauth_v1_')
    except Exception:  # pragma: no cover - storage is best-effort
        log.warning('MCP OAuth client storage unavailable; using in-memory store')
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
        log.exception('Failed to build MCP JWT verifier; MCP auth not configured')
        return None

    client_id = app.config.get('MCP_OAUTH_CLIENT_ID')
    signing_key = app.config.get('MCP_OAUTH_SIGNING_KEY')
    if not (client_id and signing_key):
        log.info('MCP OAuth proxy not configured; using token validation only')
        return verifier

    try:
        from fastmcp.server.auth import MultiAuth
        from fastmcp.server.auth.oauth_proxy import OAuthProxy

        service_url = (app.config.get('MCP_SERVICE_URL') or '').rstrip('/')
        # base_url is the host root, NOT the /mcp endpoint. FastMCP appends the
        # transport mount path (/mcp) itself when it derives the resource URL and
        # the .well-known discovery routes (resource_url = base_url + mcp_path).
        # Passing '<host>/mcp' here double-counts the mount and advertises a
        # bogus resource of '<host>/mcp/mcp', which strict MCP clients reject.
        base_url = app.config.get('MCP_OAUTH_BASE_URL') or service_url
        if not base_url.lower().startswith(('http://', 'https://')):
            log.error(
                'MCP OAuth proxy needs an absolute MCP_SERVICE_URL/'
                'MCP_OAUTH_BASE_URL (got %r); using token validation only',
                base_url,
            )
            return verifier
        if not (app.config.get('MCP_JWT_ISSUER')
                or app.config.get('MCP_OAUTH_UPSTREAM_AUTHORIZE_URL')):
            log.error(
                'MCP OAuth proxy needs MCP_JWT_ISSUER (or explicit upstream '
                'endpoints); using token validation only',
            )
            return verifier
        endpoints = _keycloak_endpoints(app)

        extra_authorize_params = None
        if app.config.get('MCP_JWT_AUDIENCE'):
            extra_authorize_params = {'audience': app.config['MCP_JWT_AUDIENCE']}

        proxy = OAuthProxy(
            upstream_authorization_endpoint=endpoints['authorize'],
            upstream_token_endpoint=endpoints['token'],
            upstream_revocation_endpoint=endpoints['revoke'],
            upstream_client_id=client_id,
            # Public client: no secret, PKCE-only token endpoint auth.
            upstream_client_secret=None,
            token_endpoint_auth_method='none',
            forward_pkce=True,
            token_verifier=verifier,
            base_url=base_url,
            # Resolves under base_url (<host>/auth/callback); must be a valid
            # redirect URI on the upstream Keycloak client.
            redirect_path='/auth/callback',
            allowed_client_redirect_uris=LOOPBACK_REDIRECT_URIS,
            valid_scopes=['openid', 'profile', 'email'],
            client_storage=_client_storage(),
            # No consent screen (matches controlplane-rpc); the resource is
            # IP-allowlisted and the upstream is a single trusted Keycloak realm.
            require_authorization_consent=False,
            jwt_signing_key=signing_key,
            extra_authorize_params=extra_authorize_params,
        )

        log.info('MCP OAuth proxy enabled (base_url=%s)', base_url)
        return MultiAuth(server=proxy, verifiers=[verifier])
    except Exception:
        # Never fail open: degrade to token validation only.
        log.exception('Failed to build MCP OAuth proxy; falling back to verifier')
        return verifier
