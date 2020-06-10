# coding=utf-8
"""
Plaid Security Class for Superset
"""
import logging
import redis
from sqlalchemy import func, Table, MetaData
from superset.extensions import cache_manager
from superset.security import SupersetSecurityManager
from flask_appbuilder import Model
from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.sqla.manager import SecurityManager
from authlib.integrations.flask_client import OAuth
from plaid.auth_oidc import AuthOIDCView

__author__ = "Garrett Bates"
__copyright__ = "© Copyright 2018, Tartan Solutions, Inc"
__credits__ = ["Garrett Bates"]
__license__ = "Proprietary"
__maintainer__ = "Garrett Bates"
__email__ = "garrett.bates@tartansolutions.com"


log = logging.getLogger(__name__)


def get_project_role_name(project_id):
    """Fetch the datasource role name by project ID.
    """
    return 'project_' + project_id


class PlaidSecurityManager(SupersetSecurityManager):
    """Custom security manager class for PlaidCloud integration.
    """

    def __init__(self, appbuilder):
        super(PlaidSecurityManager, self).__init__(appbuilder)
        engine = self.get_session.get_bind(mapper=None, clause=None)
        metadata = MetaData(bind=engine, reflect=True)
        self.plaiduser_user = metadata.tables['plaiduser_user']
        if self.auth_type == AUTH_OID:
            oidc_params = self.appbuilder.app.config.get("OIDC_PARAMS")
            self.oauth = OAuth(app=appbuilder.get_app)
            self.oauth.register(
                'plaid',
                client_id=oidc_params['client_id'],
                client_secret=oidc_params['client_secret'],
                access_token_url=oidc_params['token_url'],
                authorize_url=oidc_params['auth_url'],
                authorize_params=oidc_params['auth_params'],
                jwks_uri=oidc_params['jwks_uri'],
                client_kwargs=oidc_params['client_kwargs'],
            )
        self.authoidview = AuthOIDCView


    def sync_role_definitions(self):
        """PlaidSecurityManager contructor.

        Establishes a Plaid role (and Public, if configured to do so) after
        invoking the super constructor.

        Args:
            appbuilder (:obj:`AppBuilder`): F.A.B AppBuilder main object.
        """
        super().sync_role_definitions()
        self.set_role('Plaid', self.is_plaid_user_pvm)
        if self.appbuilder.app.config.get('PUBLIC_ROLE_LIKE_PLAID', False):
            self.set_role('Public', self.is_plaid_user_pvm)
        else:
            # Clear out public role.
            self.set_role('Public', lambda pvm: False)


    def is_plaid_user_pvm(self, pvm):
        """Determines which permission/view menu relations are in Plaid role.

        This is written to be used by self.set_role() when creating the Plaid
        role.

        Args:
            pvm (:obj:`PermissionView`): SQLA data model representing PVM.

        Returns:
            bool: True if a proper Plaid PVM. False otherwise.
        """
        perm = self.get_perms().get(pvm.permission.name)
        return perm and pvm.view_menu.name in perm


    def get_perms(self):
        """Accesses plaid permission dictionary from config.

        Returns:
            dict: collection of view menus indexed by permission name.
        """
        return self.appbuilder.app.config.get('PLAID_BASE_PERMISSIONS')


    def set_project_role(self, project):
        project_perm = project.get_perm()
        self.add_permission_view_menu("database_access", project_perm)

        schema_perms = {t.schema for t in project.plaid_tables}
        table_perms = {t.perm for t in project.plaid_tables}

        def has_project_access_pvm(pvm):
            '''has_project_access_pvm()

            Callable to determine which permission/view menu relations will
            be added to a role. Used by self.set_role(name, callable)
            method.
            '''
            if pvm.permission.name == 'database_access':
                return pvm.view_menu.name == project_perm

            if pvm.permission.name == 'schema_access':
                return pvm.view_menu.name in schema_perms

            if pvm.permission.name == 'datasource_access':
                return pvm.view_menu.name in table_perms

            return False


        # Name the role after the project.
        self.set_role(
            role_name=get_project_role_name(project.uuid),
            pvm_check=has_project_access_pvm
        )


    def get_user_by_plaid_id(self, plaid_id):
        mapping = self.get_session.query(
                self.plaiduser_user
            ).filter_by(
                plaid_user_id=plaid_id
            ).one()

        return self.get_user_by_id(mapping.user_id)


    def add_user_to_project(self, user, project_id):
        role = self.find_role(get_project_role_name(project_id))

        if not role:
            return

        if role not in user.roles:
            user.roles.append(role)
            log.debug(
                "Appended %s to %s roles list.", role.name, user.username
            )