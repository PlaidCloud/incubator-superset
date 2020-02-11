import logging
from urllib.parse import quote
from flask import g, redirect, request, url_for
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder import expose
from flask_login import login_user

logger = logging.getLogger()

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        oauth = self.appbuilder.sm.oauth
        redirect_uri = url_for('authorize', _external=True)
        return oauth.plaid.authorize_redirect(redirect_uri)

        # if g.oidc_id_token is None:
        #     logger.info(f"Redirect URL: {request.url.replace('http://', 'https://', 1)}")
        #     return sm.oid.redirect_to_auth_server(request.url.replace('http://', 'https://', 1))

        # def handle_login():
        #     user = sm.auth_user_oid(oidc.user_getfield('email'))

        #     if user is None:
        #         info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
        #         user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'), info.get('email'), sm.find_role('Plaid'))

        #     login_user(user, remember=False)
        #     return redirect(self.appbuilder.get_url_for_index)

        # return handle_login()

    @expose('/authorize')
    def authorize(self):
        oauth = self.appbuilder.sm.oauth
        token = oauth.plaid.authorize_access_token()
        # TODO: Determine if there is anything we actually need to do with the user info.
        userinfo = oauth.plaid.parse_id_token(token)
        return redirect('/')

    # @expose('/logout/', methods=['GET', 'POST'])
    # def logout(self):

    #     oidc = self.appbuilder.sm.oid

    #     oidc.logout()
    #     super(AuthOIDCView, self).logout()
    #     redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login

    #     return redirect(oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout?redirect_uri=' + quote(redirect_url))