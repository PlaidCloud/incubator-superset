import os
import sys
import logging
from base64 import b64encode
# from uuid import uuid4
from urllib.parse import urljoin, urlparse
from flask import request, redirect, url_for, session, make_response, Response
from flask_appbuilder.security.views import AuthOIDView, AuthOAuthView
from flask_appbuilder import expose
from flask_login import login_user, logout_user

log = logging.getLogger(__name__)


class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag:bool=True) -> Response:
        oauth = self.appbuilder.sm.oauth
        next_intent = request.args.get("next")
        if next_intent:
            session["next_redirect"] = next_intent
        redirect_uri = url_for('.authorize', _external=True, _scheme='https')
        return oauth.plaid.authorize_redirect(redirect_uri)

    @expose('/authorize')
    def authorize(self) -> Response:
        oauth = self.appbuilder.sm.oauth
        token = oauth.plaid.authorize_access_token()
        userinfo = oauth.plaid.parse_id_token(token, None)
        log.info(f"Fetched user info from token: {userinfo}")
        user_email = userinfo['email'].lower()
        if user_email.endswith('tartansolutions.com') or user_email.endswith('plaidcloud.com'):
            role_set = ["Admin", "Plaid", "Gamma"]
        else:
            role_set = ["Plaid", "Gamma"]
        user = self.appbuilder.sm.find_user(email=userinfo['email'].lower())
        name = userinfo.get('name', userinfo['preferred_username'])
        if not user:
            roles = [self.appbuilder.sm.find_role(role_name) for role_name in role_set]
            user = self.appbuilder.sm.add_user(
                name,
                first_name=userinfo['given_name'],
                last_name=userinfo['family_name'],
                email=userinfo["email"].lower(),
                role=roles,
                password=throwaway_password(),
            )
        login_user(user)
        session['token'] = token
        session['workspace'] = userinfo.get('default_plaid_group')
        next_url = session.pop("next_redirect", "/")
        return redirect(next_url)

    @expose("/logout/")
    def logout(self) -> Response:
        logout_user()
        session.clear()
        return redirect('/')


def throwaway_password() -> str:
    random_bytes = os.urandom(64)
    return b64encode(random_bytes).decode('utf-8')


class PlaidAuthOAuthView(AuthOAuthView):
    @expose("/login/")
    @expose("/login/<provider>")
    def login(self, provider=None):
        if provider is None:
            return super().login(provider='plaidkeycloak')
        return super().login(provider=provider)
