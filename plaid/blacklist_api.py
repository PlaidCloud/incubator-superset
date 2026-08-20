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

import time
import logging
from flask import current_app as app
from flask import request
from flask_appbuilder.api import expose
from superset.views.base_api import BaseSupersetApi


__author__ = 'Patrick Buxton'
__maintainer__ = 'Patrick Buxton <pat@plaidcloud.com>'
__copyright__ = '© Copyright 2018-2026, PlaidCloud, Inc'
__license__ = 'Proprietary'

REDIS_PREFIX = "oauth:blacklist"
log = logging.getLogger(__name__)

def blacklist_token(token: str, expires_at: int):
    """
    Blacklist a token until its natural expiry.
    """
    ttl = max(0, expires_at - int(time.time()))
    log.info('Blacklisting token: %s, ttl = %d', token, ttl)
    if ttl > 0:
        app.config["SESSION_REDIS"].set(f"{REDIS_PREFIX}:{token}", 1, ex=ttl)

def is_token_blacklisted(token: str) -> bool:
    log.info('Checking token for blacklist: %s', token)
    return app.config["SESSION_REDIS"].exists(f"{REDIS_PREFIX}:{token}") == 1


class TokenBlacklistApi(BaseSupersetApi):
    resource_name = "token_blacklist"
    allow_browser_login = False  # important

    @expose("/", methods=("POST",))
    #@protect()
    def blacklist(self):
        """
        POST /api/v1/token_blacklist/

        Body:
        {
          "access_token": "...",
          "expires_at": 1712345678
        }
        """
        if request.headers.get("X-Blacklist-Secret") != app.config["BLACKLIST_SECRET"]:
            return self.response_401()
        data = request.json or {}
        token = data.get("access_token")
        expires_at = data.get("expires_at")

        if not token or not expires_at:
            return self.response_400(message="access_token and expires_at required")

        blacklist_token(token, expires_at)
        return self.response(200, message="token blacklisted")
