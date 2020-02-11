import logging
from urllib.parse import quote
from flask import g, redirect, request, url_for
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder import expose
from flask_login import login_user

logger = logging.getLogger(__name__)
logging.getLogger('authlib.integrations._client.base_app').setLevel("DEBUG")

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        oauth = self.appbuilder.sm.oauth
        redirect_uri = url_for('.authorize', _external=True, _scheme='https')
        return oauth.plaid.authorize_redirect(redirect_uri)

    @expose('/authorize')
    def authorize(self):
        oauth = self.appbuilder.sm.oauth
        logger.info(f"params: {oauth.plaid.retrieve_access_token_params(request)}")
        token = oauth.plaid.authorize_access_token()
        # TODO: Determine if there is anything we actually need to do with the user info.
        userinfo = oauth.plaid.parse_id_token(token)
        return redirect('/')
