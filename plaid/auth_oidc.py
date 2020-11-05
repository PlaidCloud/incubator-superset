import sys
from urllib.parse import urljoin
from flask import redirect, url_for
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
                first_name="Garrett",
                last_name="Bates",
                email=userinfo["email"],
                role=plaid_role,
                password="waaaaaaaa",
            )
        login_user(user)
        return redirect('/')

    @expose("/logout/")
    def logout(self):
        logout_user()
        base_url = self.appbuilder.app.config["OIDC_PARAMS"]["base_url"]
        return redirect(urljoin(base_url, "/logout"))
