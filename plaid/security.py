# coding=utf-8
"""
Plaid Security Class for Superset
"""
import logging
import redis
import uuid
import time
from sqlalchemy import func, Table, MetaData
from typing import Union
from urllib.parse import urljoin
from superset.extensions import cache_manager
from superset.security import SupersetSecurityManager
from flask import session
from flask_appbuilder import Model
from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.sqla.manager import SecurityManager
from authlib.integrations.flask_client import OAuth
from plaid.auth_oidc import AuthOIDCView
from plaidcloud.rpc.connection.jsonrpc import SimpleRPC

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
        # engine = self.get_session.get_bind(mapper=None, clause=None)
        # metadata = MetaData(bind=engine, reflect=True)
        # self.plaiduser_user = metadata.tables['plaiduser_user']
        if self.auth_type == AUTH_OID:
            self.oidc_params = self.appbuilder.app.config.get("OIDC_PARAMS")
            self.oauth = OAuth(app=appbuilder.get_app)
            self.oauth.register(
                'plaid',
                client_id=self.oidc_params['client_id'],
                client_secret=self.oidc_params['client_secret'],
                access_token_url=self.oidc_params['token_url'],
                authorize_url=self.oidc_params['auth_url'],
                authorize_params=self.oidc_params['auth_params'],
                jwks_uri=self.oidc_params['jwks_uri'],
                client_kwargs=self.oidc_params['client_kwargs'],
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


    def get_rpc(self):
        base_url = "{}{}".format("http://", self.appbuilder.app.config.get("PLAID_RPC"))
        rpc_url = urljoin(base_url, "json-rpc/")
        if session.get("workspace") is None:
            temp_rpc = SimpleRPC(session["token"]["access_token"], uri=rpc_url, verify_ssl=False)
            session["workspace"] = temp_rpc.identity.me.workspace_id()
        # Specify user's default workspace in token.
        log.debug(f"workspace: {session['workspace']}")
        token = "{}_ws{}".format(session["token"]["access_token"], session["workspace"])
        return SimpleRPC(token, uri=rpc_url, verify_ssl=False)


    def can_access_database(self, database: Union["Database", "DruidCluster"]) -> bool:
        rpc = self.get_rpc()
        proj = rpc.analyze.project.project_sync(project_id=str(database.uuid))
        log.debug(proj)
        if proj["id"] is None:
            proj = rpc.analyze.project.project_sync(project_id=str(database.uuid).replace('-', ''))
        return proj.get("id", None) is not None or super().can_access_database(database)


    def can_access_schema(self, datasource: "BaseDatasource") -> bool:
        return self.can_access_datasource(datasource)


    def can_access_datasource(self, datasource: "BaseDatasource") -> bool:
        if datasource.schema is None:
            # Call the base method if there is no schema since it isn't a plaid table.
            return super().can_access_datasource(datasource)
        rpc = self.get_rpc()
        table_id = "{}{}".format("analyzetable_", str(datasource.uuid))
        table_id_without_dashes = table_id.replace("-", "")
        log.debug(table_id)
        table = rpc.analyze.table.table_sync(project_id=datasource.schema.replace("report", ""), table_id=table_id)
        log.debug(table)
        if table["id"] is None:
            table = rpc.analyze.table.table_sync(project_id=datasource.schema.replace("report", ""), table_id=table_id_without_dashes)            
            log.debug(table)
        return table.get('id', None) is not None
        

    def get_project_ids(self):
        from superset.models.core import Database
        rpc = self.get_rpc()
        start = time.time()
        projects = rpc.analyze.project.projects_sync()
        end = time.time()
        project_uuids = {str(uuid.UUID(project['id'])) for project in projects}
        log.debug(f"Fetched these projects in {end - start}: {project_uuids}")
        return self.get_session.query(Database.id).filter(Database.uuid.in_(project_uuids))


    def get_table_ids(self):
        rpc = self.get_rpc()
        start = time.time()
        tables = rpc.analyze.table.published_tables_by_project_sync()
        end = time.time()
        table_ids = {str(uuid.UUID(table['id'].replace('analyzetable_', ''))) for table in tables}
        log.debug(f"Fetched these tables in {end - start}: {table_ids}")
        return table_ids


    def get_perms(self):
        """Accesses plaid permission dictionary from config.

        Returns:
            dict: collection of view menus indexed by permission name.
        """
        return self.appbuilder.app.config.get('PLAID_BASE_PERMISSIONS')


    def add_user_to_project(self, user, project_id):
        role = self.find_role(get_project_role_name(project_id))

        if not role:
            return

        if role not in user.roles:
            user.roles.append(role)
            log.debug(
                "Appended %s to %s roles list.", role.name, user.username
            )
