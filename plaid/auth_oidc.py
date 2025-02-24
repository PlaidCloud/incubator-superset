import logging
from flask import current_app, redirect
from flask_appbuilder.security.views import AuthOAuthView
from flask_appbuilder import expose
from flask_login import logout_user


__author__ = 'Patrick Buxton'
__maintainer__ = 'Patrick Buxton <pat@plaidcloud.com>'
__copyright__ = '© Copyright 2018-2026, PlaidCloud, Inc'
__license__ = 'Proprietary'


log = logging.getLogger(__name__)


class PlaidAuthOAuthView(AuthOAuthView):
    # @expose("/login/")
    # @expose("/login/<provider>")
    # def login(self, provider=None):
    #     log.info("Login for %s", provider)
    #     if provider is None:
    #         return super().login(provider='plaidkeycloak')
    #     return super().login(provider=provider)

    @expose("/logout/")
    def logout(self):
        log.info('Logout using backend AuthOAuthView')
        logout_user()
        return redirect(
            current_app.config.get(
                "LOGOUT_REDIRECT_URL", self.appbuilder.get_url_for_index
            )
        )
