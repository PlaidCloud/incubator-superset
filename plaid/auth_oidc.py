import sys
from uuid import uuid4
from urllib.parse import urljoin
from flask import redirect, url_for, session
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder import expose
from flask_login import login_user, logout_user


class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        oauth = self.appbuilder.sm.oauth
        redirect_uri = url_for('.authorize', _external=True, _scheme='https')
        return oauth.plaid.authorize_redirect(redirect_uri)

    @expose('/authorize')
    def authorize(self):
        oauth = self.appbuilder.sm.oauth
        token = oauth.plaid.authorize_access_token()
        userinfo = oauth.plaid.parse_id_token(token)
        print(userinfo, file=sys.stderr)
        user = self.appbuilder.sm.find_user(email=userinfo['email'])
        if not user:
            plaid_role = self.appbuilder.sm.find_role("Plaid")
            user = self.appbuilder.sm.add_user(
                userinfo['name'],
                first_name=userinfo['given_name'],
                last_name=userinfo['family_name'],
                email=userinfo["email"],
                role=plaid_role,
                password=uuid4().bytes,
            )
        login_user(user)
        session["token"] = token
        return redirect('/')

    @expose("/logout/")
    def logout(self):
        logout_user()
        base_url = self.appbuilder.app.config["OIDC_PARAMS"]["base_url"]
        return redirect(urljoin(base_url, "/logout"))
