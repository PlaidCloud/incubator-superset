import os
import sys
import logging
from base64 import b64encode
# from uuid import uuid4
from urllib.parse import urljoin, urlparse
from flask import redirect, url_for, session, make_response, Response
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder import expose
from flask_login import login_user, logout_user

log = logging.getLogger(__name__)
class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True) -> Response:
        oauth = self.appbuilder.sm.oauth
        redirect_uri = url_for('.authorize', _external=True, _scheme='https')
        return oauth.plaid.authorize_redirect(redirect_uri)

    @expose('/authorize')
    def authorize(self) -> Response:
        oauth = self.appbuilder.sm.oauth
        token = oauth.plaid.authorize_access_token()
        userinfo = oauth.plaid.parse_id_token(token)
        log.info(f"Fetched user info from token: {userinfo}")
        user = self.appbuilder.sm.find_user(email=userinfo['email'].lower())
        if not user:
            roles = [self.appbuilder.sm.find_role(role_name) for role_name in ("Plaid", "Gamma")]
            user = self.appbuilder.sm.add_user(
                userinfo['name'],
                first_name=userinfo['given_name'],
                last_name=userinfo['family_name'],
                email=userinfo["email"].lower(),
                role=roles,
                password=throwaway_password(),
            )
        login_user(user)
        session['token'] = token
        session['workspace'] = userinfo['default_plaid_group']
        return redirect('/')

    @expose("/logout/")
    def logout(self) -> Response:
        base_url = self.appbuilder.app.config["OIDC_PARAMS"]["base_url"]
        # domain = "{}{}".format(".", urlparse(base_url).netloc)
        domain = f".{urlparse(base_url).netloc}"
        logout_user()
        response = make_response(redirect('/'))
        # TODO: probably parameterize cookie name, though I suspect it won't change.
        response.delete_cookie('_session_id', path='/', domain=domain)
        response.delete_cookie('session', path='/', domain=domain)
        return response

def throwaway_password() -> str:
    random_bytes = os.urandom(64)
    return b64encode(random_bytes).decode('utf-8')
