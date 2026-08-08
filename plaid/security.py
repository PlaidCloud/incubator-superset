# coding=utf-8
"""
Plaid Security Class for Superset
"""
import logging
import time
import uuid
from typing import List, Optional, Union
from urllib.parse import urljoin

import jwt
from authlib.integrations.flask_client import token_update
from flask import session
from flask_appbuilder import Model
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_login import logout_user
from plaidcloud.rpc.connection.jsonrpc import SimpleRPC
from requests.exceptions import HTTPError
from sqlalchemy import func
from typing_extensions import override

from plaid import rls_guard
from plaid.auth_oidc import PlaidAuthOAuthView

# from plaid.blacklist_api import is_token_blacklisted
# from plaid.auth_oidc import AuthOIDCView
# from plaid.blacklist_api import TokenBlacklistApi
from superset.security import SupersetSecurityManager
from superset.security.manager import SupersetRoleApi

__author__ = "Garrett Bates"
__copyright__ = "© Copyright 2018=2026, PlaidCloud, Inc"
__credits__ = ["Garrett Bates"]
__license__ = "Proprietary"
__maintainer__ = ["Garrett Bates", "Patrick Buxton"]
__email__ = "garrett.bates@plaidcloud.com"


log = logging.getLogger(__name__)
USE_REFRESH_TOKENS = False
PROJECT_ACCESS = "project_access"


class _PlaidGuardedRoleApi(rls_guard.PlaidRoleApi, SupersetRoleApi):
    """`PlaidRoleApi`'s guard methods call `super()` on the allowed path,
    which MRO resolves to `SupersetRoleApi` / FAB's `RoleApi` -- so a
    legitimate write (the automation principal, or a role outside the
    `plaid_rls_` prefix) behaves exactly as upstream, including
    `SupersetRoleApi.pre_delete`'s permission-clearing override.
    """


class PlaidSecurityManager(SupersetSecurityManager):
    """Custom security manager class for PlaidCloud integration."""

    # The admin SPA routes (UsersListView, RolesListView, GroupsListView,
    # ActionLogView, UserRegistrationsView) all gate on the ("read", "security")
    # permission. Upstream only marks the "Security" menu category and the
    # individual menu items as admin-only, not the shared "security" view-menu,
    # so ("read", "security") gets granted to Alpha/Gamma and those roles can
    # reach /users/, /roles/, /list_groups/ etc. directly even though the menu
    # is hidden. Adding "security" here makes the routes Admin-only too.
    # UserRegistrationsRestAPI is a full ModelRestApi over RegisterUser, so FAB
    # registers can_add/can_edit/can_delete alongside can_list/can_show. Upstream
    # guards the "User Registrations" ModelView menu but not the REST API's
    # view-menu, so Alpha/Gamma can POST a registration with any email and a
    # chosen registration_hash, then activate it into a real ab_user row via the
    # unauthenticated /register/activation/<hash> route. Spelled as a literal
    # rather than UserRegistrationsRestAPI.__name__ because importing that class
    # here pulls superset.models.core in at config-load time, before init_app,
    # which raises "App not initialized yet" out of encrypted_field_factory.
    ADMIN_ONLY_VIEW_MENUS = SupersetSecurityManager.ADMIN_ONLY_VIEW_MENUS | {
        "security",
        "UserRegistrationsRestAPI",
    }

    # sc-23432 Part 4 -- protects `plaid_rls_*` roles from write access by
    # anyone but the automation principal. See `plaid/rls_guard.py`.
    role_api = _PlaidGuardedRoleApi

    def __init__(self, appbuilder):
        # These allowed me to turn this on without adjusting the superset_config.py
        # app = appbuilder.get_app
        # app.config['AUTH_TYPE'] = AUTH_OAUTH
        # app.config['AUTH_USER_REGISTRATION'] = True
        # app.config['AUTH_ROLES_SYNC_AT_LOGIN'] = True
        super().__init__(appbuilder)

        # sc-23432 Part 4 -- the RLS rules API (`RowLevelSecurityFilter`) has
        # no override attribute like `role_api` above; `RLSRestApi`'s write
        # routes are patched in place instead. Here, not at module import
        # time: `RLSRestApi` pulls in Superset's command/DAO layer, which
        # this constructor -- running after `super().__init__`, well after
        # Superset's own app factory has set up its view registry, and still
        # well before the app accepts its first request -- is a safer point
        # to depend on than being importable at `plaid.security`'s own
        # module-load time. See `plaid/rls_guard.py`.
        rls_guard.install()

        # The actual control for role/group escalation -- see rls_guard's
        # module docstring "What this protects" section for why route
        # patching alone (RoleApi above) is not enough on its own.
        rls_guard.install_orm_listeners()

        if self.auth_type == AUTH_OAUTH:
            self.authoauthview = PlaidAuthOAuthView

        @token_update.connect_via(appbuilder)
        def on_token_update(sender, name, token, refresh_token=None, access_token=None):
            # if refresh_token:
            #     item = OAuth2Token.find(name=name, refresh_token=refresh_token)
            # elif access_token:
            #     item = OAuth2Token.find(name=name, access_token=access_token)
            # else:
            #     return
            #
            # # update old token
            # item.access_token = token['access_token']
            # item.refresh_token = token.get('refresh_token')
            # item.expires_at = token['expires_at']
            # item.save()
            log.info(f"Updated token for {name} - {repr(token)}")
            self.appbuilder.sm.set_oauth_session(name, token)

    # def register_views(self) -> None:
    #     super().register_views()
    #     from plaid.blacklist_api import TokenBlacklistApi
    #     self.appbuilder.add_api(TokenBlacklistApi)

    def oauth_user_info(self, provider, response=None):
        # logging.debug("Oauth2 provider: {0}.".format(provider))
        if provider == "plaidkeycloak":
            me = self.appbuilder.sm.oauth_remotes[provider].get("userinfo")
            me.raise_for_status()
            data = me.json()
            log.debug("User info from Keycloak: %s", data)
            # This is for using keycloak groups
            # role_keys = []
            # if 'Dashboard Read Only' in data.get('groups'):
            #     role_keys.append('superset-gamma')
            # if 'Dashboard Read and Write' in data.get('groups'):
            #     role_keys.append('superset-alpha')
            # if data.get('is_admin', False):
            #     role_keys.append('superset-admin')

            # This is for using Keycloak roles - have to inspect the token
            access_token = response.get("access_token")
            decoded_token = jwt.decode(
                access_token, options={"verify_signature": False}
            )
            roles = set(decoded_token.get("realm_access", {}).get("roles", []))
            log.debug("Decoded token: %s", decoded_token)
            log.debug("Roles from token: %s", roles)
            role_keys = []
            if "dashboard.dashboard.read" in roles:
                role_keys.append("superset-gamma")
            if "dashboard.dashboard.write" in roles:
                role_keys.append("superset-alpha")
            if decoded_token.get("is_admin", False):
                role_keys.append("superset-admin")
            return {
                "username": data.get(
                    "name", data["preferred_username"]
                ),  # this matches OIDC implementation
                "first_name": data.get("given_name", ""),
                "last_name": data.get("family_name", ""),
                "email": data.get("email", ""),
                "role_keys": role_keys,  # These role_keys get mapped to real roles via the AUTH_ROLES_MAPPING config value
            }

    @override
    def find_user(self, username=None, email=None):
        """
        Finds user by username or email

        CRL 2026 this is a temporary override until Flask AppBuilder adds a way to make
        the email check case-insensitive
        """
        if username:
            if self.auth_username_ci:
                query = self.session.query(self.user_model).filter(
                    func.lower(self.user_model.username) == func.lower(username)
                )
            else:
                query = self.session.query(self.user_model).filter(
                    self.user_model.username == username
                )
            return self._resolve_single_user(query, "username", username)
        elif email:
            query = self.session.query(self.user_model).filter(
                func.lower(self.user_model.email) == func.lower(email)
            )
            return self._resolve_single_user(query, "email", email)

    def _resolve_single_user(self, query, field, value):
        """
        Picks one user when a lookup matches more than one row.

        ab_user.email and ab_user.username are case-sensitively unique, so rows
        differing only in case legally coexist. Prefer an active row, then an
        exact match, then the lowest id, so a login never fails on the ambiguity
        and never lands on a deactivated duplicate. Deactivated rows are still
        returned when they are all there is, leaving the active check to the
        caller.
        """
        users = query.order_by(self.user_model.id).all()
        if len(users) > 1:
            log.warning(
                "Multiple users match %s %s; preferring an active row, then the "
                "exact-case match, then the lowest id. Matching ids: %s",
                field,
                value,
                [user.id for user in users],
            )
        users.sort(
            key=lambda user: (not user.active, getattr(user, field) != value, user.id)
        )
        return users[0] if users else None

    def auth_user_oauth(self, userinfo):
        """
        Method for authenticating user with OAuth.
        N.B. This is the overridden to use email as the key instead of username
         This is as per OIDC registration

        :userinfo: dict with user information
                   (keys are the same as User model columns)
        """
        # extract the email from `userinfo`
        if "email" in userinfo and userinfo["email"]:
            email = userinfo["email"]
        else:
            log.error("OAUTH userinfo does not have email %s", userinfo)
            return None

        if "username" not in userinfo or not userinfo["username"]:
            log.error("OAUTH userinfo does not have username %s", userinfo)
            return None

        # Search the DB for this user by email
        user = self.find_user(email=email)

        # If user is not active, go away
        if user and (not user.is_active):
            log.debug("User is not active: %s", email)
            return None

        # If user is not registered, and not self-registration, go away
        if (not user) and (not self.auth_user_registration):
            return None

        # Sync the user's roles
        if user and len(user.roles) == 0:  # self.auth_roles_sync_at_login:
            user.roles = self._oauth_calculate_user_roles(userinfo)
            log.debug("Calculated new roles for user='%s' as: %s", email, user.roles)

        # If the user is new, register them
        if (not user) and self.auth_user_registration:
            user = self.add_user(
                username=userinfo["username"],
                first_name=userinfo.get("first_name", ""),
                last_name=userinfo.get("last_name", ""),
                email=email,
                role=self._oauth_calculate_user_roles(userinfo),
            )
            log.debug("New user registered: %s", user)

            # If user registration failed, go away
            if not user:
                log.error("Error creating a new OAuth user %s", email)
                return None

        # LOGIN SUCCESS (only if user is now registered)
        if user:
            self.store_user_project_access()
            self.update_user_auth_stat(user)
            return user
        else:
            session[PROJECT_ACCESS] = []
            return None

    # def sync_role_definitions(self):
    #     """PlaidSecurityManager constructor.
    #
    #     Establishes a Plaid role (and Public, if configured to do so) after
    #     invoking the super constructor.
    #
    #     Adds all permissions from Gamma to Plaid (and Public, if configured)
    #
    #     Args:
    #         appbuilder (:obj:`AppBuilder`): F.A.B AppBuilder main object.
    #     """
    #     super().sync_role_definitions()
    #
    #     pvms = self._get_all_pvms()
    #
    #     self.set_role('Plaid', self.is_plaid_user_pvm, pvms)
    #     plaid_role = self.find_role('Plaid')
    #
    #     if self.appbuilder.app.config.get('PUBLIC_ROLE_LIKE_PLAID', False):
    #         self.set_role('Public', self.is_plaid_user_pvm, pvms)
    #         public_role = self.find_role('Public')
    #     else:
    #         # Clear out public role.
    #         self.set_role('Public', lambda pvm: False, pvms)
    #
    #
    # def is_plaid_user_pvm(self, pvm) -> bool:
    #     """Determines which permission/view menu relations are in Plaid role.
    #
    #     This is written to be used by self.set_role() when creating the Plaid
    #     role.
    #
    #     Args:
    #         pvm (:obj:`PermissionView`): SQLA data model representing PVM.
    #
    #     Returns:
    #         bool: True if a proper Plaid PVM. False otherwise.
    #     """
    #     perm = self.get_perms().get(pvm.permission.name)
    #     return bool(perm) and pvm.view_menu.name in perm

    def get_rpc(self) -> SimpleRPC:
        base_url = f"http://{self.appbuilder.app.config.get('PLAID_RPC')}"
        rpc_url = urljoin(base_url, "json-rpc/")

        if self.auth_type == AUTH_OAUTH:
            rpc_token, secret = session["oauth"]
        else:
            rpc_token = session["token"]["access_token"]

        rpc = SimpleRPC(rpc_token, uri=rpc_url, verify_ssl=False)
        rpc._old_call_rpc = rpc.call_rpc

        def superset_call_rpc(*args, **kwargs):
            try:
                return rpc._old_call_rpc(*args, **kwargs)
            except HTTPError as e:
                if e.response.status_code == 401:
                    logout_user()
                    session.clear()
                    raise Exception(
                        "There were problems authenticating your access with PlaidCloud. "
                        "If you see this message, please refresh your browser"
                    ) from e
                raise

        rpc.call_rpc = superset_call_rpc
        return rpc

    def store_user_project_access(self):
        try:
            projects = self.get_rpc().analyze.project.projects(keys=["id"])
            project_ids = [str(uuid.UUID(p["id"])) for p in projects]
            session[PROJECT_ACCESS] = project_ids
        except Exception as e:
            log.error(str(e))
            session[PROJECT_ACCESS] = []  # No access

    def _can_access_project(self, project_id):
        log.info(dict(session))
        if PROJECT_ACCESS not in session:
            return self.is_admin()
        return str(uuid.UUID(project_id)) in session[PROJECT_ACCESS]

    def can_access_database(self, database: Union["Database"]) -> bool:
        log.info(f"Can access database: {database}")
        return self._can_access_project(
            str(database.uuid)
        ) or super().can_access_database(database)

    def can_access_datasource(self, datasource: "BaseDatasource") -> bool:
        log.info(f"Checking access to datasource: {datasource}")
        log.info(f"Checking access to datasource db id: {datasource.database.uuid}")
        if datasource.schema is None:
            log.info(f"No Schema: {datasource}")
            # Call the base method if there is no schema since there isn't a plaid schema.
            return super().can_access_datasource(datasource)

        project_id = str(datasource.database.uuid)
        return self._can_access_project(project_id) or super().can_access_datasource(
            datasource
        )

    def is_owner(self, resource: Model) -> bool:
        from superset.models.slice import Slice  # a Slice is a chart

        if isinstance(resource, Slice):
            return super().is_owner(resource) or any(
                [self.is_owner(dashboard) for dashboard in resource.dashboards]
            )

        return super().is_owner(resource)

    # def get_project_ids(self):
    #     log.info(f"About to fetch user project ids")
    #     from superset.models.core import Database
    #     rpc = self.get_rpc()
    #     start = time.time()
    #     projects = rpc.analyze.project.projects()
    #     end = time.time()
    #     log.info(f"Fetched user's projects in {end - start} seconds.")
    #     project_uuids = {str(uuid.UUID(project['id'])) for project in projects}
    #     log.info(f"Project IDs: {project_uuids}")
    #     return self.get_session.query(Database.id).filter(Database.uuid.in_(project_uuids))

    # Not actually called anywhere any more! Success!
    # def get_project_ids(self):
    #     return [db.id for db in self.get_project_dbs()]

    def _get_project_dbs(self):
        from superset.models.core import Database

        if PROJECT_ACCESS not in session:
            if self.is_admin():
                return self.session.query(Database)
            return []
        project_uuids = set(session[PROJECT_ACCESS])
        return self.session.query(Database).filter(Database.uuid.in_(project_uuids))

    def user_view_menu_names(self, permission_name: str) -> set[str]:
        if permission_name == "database_access":
            project_perms = {db.perm for db in self._get_project_dbs()}
            return project_perms | super().user_view_menu_names(permission_name)

        return super().user_view_menu_names(permission_name)

    # - Database.perm!
    # So I think maybe the other thing to do is to override user_view_menu_names, and add accessible projects in if it's queried on "database_access "?
    # Superset's get_accessible_databases is based on self.user_view_menu_names("database_access"), and it uses DATABASE_PERM_REGEX to extract the id, I think?
    # According to unpack_database_and_schema, it looks like a schema_permission looks like [database_name].[schema|table] , I think with the square brackets included.
    # unpack_database_and_schema is run on the things erturned by user_view_menu_names
    # so is the regex in get_accessible_databases()
    # Looks like maybe it's [database_name].[schema|table].id:<id> (where the first id is literal, the second is an id)
    # Actual examples:
    # ('all_database_access',),
    # ('all_query_access',),
    # ('[International Motors (21dc)].(id:1)',),
    # ('[International Motors (21dc)].[anlz21dccece-1043-4c10-9bb5-c512ca4d5393]',),
    # ('[International Motors (21dc)].[anlze395fd34-fedc-4f04-b3fd-c50d8d77c531]',),
    # ('[International Motors (21dc)].[gp_toolkit]',),
    # ('[International Motors (21dc)].[information_schema]',),
    # ('[International Motors (21dc)].[public]',),
    # ('Profile',),
    # ('[International Motors (21dc)].[ParentChildRecord](id:50)',),
    # ('[International Motors (21dc)].[ActivityDriverValueRecord](id:51)',),
    # ('[International Motors (21dc)].[ResourceDriverSplitRecord](id:52)',),
    # ('[International Motors (21dc)].[ResourceDriverValueRecord](id:53)',)

    # Not actually necessary to override this, since it depends on user_view_menu_names(), and we're overriding that.
    # def get_accessible_databases():
    #     # Return any databases that would be accessible under superset's security system, and also any
    #     # projects accessible under plaid's security system.
    #     return self.get_project_ids() + super().get_accessible_databases()

    def get_schemas_accessible_by_user(
        self,
        database: "Database",
        catalog: Optional[str],
        schemas: List[str],
        hierarchical: bool = True,
    ) -> List[str]:
        REPORTING_SCHEMA_PREFIX = "report"

        schema = str(database.uuid)
        if not schema.startswith(REPORTING_SCHEMA_PREFIX):
            schema = f"{REPORTING_SCHEMA_PREFIX}{schema}"

        if schema in schemas:
            return [schema]

        return []

    # I can't see that this has been used anywhere
    # def get_table_ids(self):
    #     rpc = self.get_rpc()
    #     start = time.time()
    #     tables = rpc.analyze.table.published_tables_by_project()
    #     end = time.time()
    #     table_ids = {str(uuid.UUID(table['id'].replace('analyzetable_', ''))) for table in tables}
    #     log.debug(f"Fetched table IDs in {end - start}: {table_ids}")
    #     return table_ids

    # def get_perms(self):
    #     """Accesses plaid permission dictionary from config.
    #
    #     Returns:
    #         dict: collection of view menus indexed by permission name.
    #     """
    #     return self.appbuilder.app.config.get('PLAID_BASE_PERMISSIONS')

    # This looks unused
    # def add_user_to_project(self, user, project_id):
    #     role = self.find_role(get_project_role_name(project_id))
    #
    #     if not role:
    #         return
    #
    #     if role not in user.roles:
    #         user.roles.append(role)
    #         log.debug(
    #             "Appended %s to %s roles list.", role.name, user.username
    #         )

    def set_oauth_session(self, provider, oauth_response):
        """
        Set the current session with OAuth token dict
        """
        # Save users token_dict on encrypted session cookie
        if USE_REFRESH_TOKENS:
            session["oauth_token_dict"] = oauth_response
        super().set_oauth_session(provider, oauth_response)

    def has_oauth_token(self):
        if self.auth_type == AUTH_OAUTH:
            return "oauth" in session
        # if self.auth_type == AUTH_OID:
        #     return 'token' in session
        return False

    # N.B. This method is called using FLASK_APP_MUTATOR in the superset-config secret
    #  It makes this call to validate the token in a before_request handler
    def validate_oauth_token(self):
        def _internal_validate():
            try:
                if self.auth_type == AUTH_OAUTH:
                    if "oauth" in session:
                        # Basic validation of token expiry
                        token, secret = session["oauth"]
                        # if is_token_blacklisted(token):
                        #     return False
                        if token_is_valid(token):
                            return True

                        if USE_REFRESH_TOKENS:
                            # to do the below, it needs custom `set_oauth_session` to save the `oauth_token_dict`
                            provider = session["oauth_provider"]
                            token_dict = session["oauth_token_dict"]
                            logging.info("Provider %s, Token %s", provider, token_dict)
                            # this will refresh the token if it is expired (via `token_update` listener)
                            self.appbuilder.sm.oauth_remotes[
                                provider
                            ].token = token_dict
                            user_resp = self.appbuilder.sm.oauth_remotes[provider].get(
                                "userinfo"
                            )
                            user_resp.raise_for_status()
                            logging.info("Got user response")
                            # ToDo - probably should check token now refreshed, or use the introspection

                            # ToDo - I could not get introspection to work, I was calling from FlaskOAuth2App, but needs to be and OAuth2Session which is the _get_oauth_client() of the Flask thing
                            # maybe we don't need to introspect anyway, can just check expiry.

                            # # new token now stored in session
                            # token_dict = session['oauth_token_dict']
                            # logging.info('Provider %s, Revised Token %s', provider, token_dict)
                            # token_endpoint = self.appbuilder.sm.oauth.plaidkeycloak.access_token_url
                            # intro_resp = self.appbuilder.sm.oauth_remotes[provider].introspect_token(token_endpoint, token=token_dict)
                            # intro_resp.raise_for_status()
                            # logging.info('Did introspection')
                            # token_info = intro_resp.json()
                            # if token_info['active']:
                            #     return True

                return False

            except Exception as e:
                logging.exception("Failed to validate oauth token: %s", e)
                return False

        result = _internal_validate()
        if not result:
            logout_user()
            session.clear()
        return result


def token_is_valid(access_token):
    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        expiration_timestamp = decoded_token["exp"]
        current_timestamp = time.time()
        return expiration_timestamp > current_timestamp
    except (jwt.exceptions.DecodeError, KeyError):
        return False
