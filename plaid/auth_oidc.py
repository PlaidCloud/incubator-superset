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
