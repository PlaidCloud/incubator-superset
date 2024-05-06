# coding=utf-8
"""
Plaid Security Class for Superset
"""
import logging
import uuid
import time
import jwt
from typing import Union, List

from sqlalchemy import func, Table, MetaData
from urllib.parse import urljoin
from flask import session
from flask_login import logout_user
from flask_appbuilder import Model
from flask_appbuilder.security.manager import AUTH_OID
from authlib.integrations.flask_client import OAuth
from requests.exceptions import HTTPError

from plaidcloud.rpc.connection.jsonrpc import SimpleRPC
from plaid.auth_oidc import AuthOIDCView

from superset.security import SupersetSecurityManager

__author__ = "Garrett Bates"
__copyright__ = "© Copyright 2018, Tartan Solutions, Inc"
__credits__ = ["Garrett Bates"]
__license__ = "Proprietary"
__maintainer__ = "Garrett Bates"
__email__ = "garrett.bates@tartansolutions.com"


log = logging.getLogger(__name__)


def get_project_role_name(project_id: str) -> str:
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

        Adds all permissions from Gamma to Plaid (and Public, if configured)

        Args:
            appbuilder (:obj:`AppBuilder`): F.A.B AppBuilder main object.
        """
        super().sync_role_definitions()

        pvms = self._get_all_pvms()

        self.set_role('Plaid', self.is_plaid_user_pvm, pvms)
        plaid_role = self.find_role('Plaid')

        if self.appbuilder.app.config.get('PUBLIC_ROLE_LIKE_PLAID', False):
            self.set_role('Public', self.is_plaid_user_pvm, pvms)
            public_role = self.find_role('Public')
        else:
            # Clear out public role.
            self.set_role('Public', lambda pvm: False, pvms)


    def is_plaid_user_pvm(self, pvm) -> bool:
        """Determines which permission/view menu relations are in Plaid role.

        This is written to be used by self.set_role() when creating the Plaid
        role.

        Args:
            pvm (:obj:`PermissionView`): SQLA data model representing PVM.

        Returns:
            bool: True if a proper Plaid PVM. False otherwise.
        """
        perm = self.get_perms().get(pvm.permission.name)
        return bool(perm) and pvm.view_menu.name in perm


    def get_rpc(self) -> SimpleRPC:
        base_url = f"http://{self.appbuilder.app.config.get('PLAID_RPC')}"
        rpc_url = urljoin(base_url, "json-rpc/")

        if 'workspace' in session:
            temp_token =  f"{session['token']['access_token']}_ws{session['workspace']}"
        else:
            temp_token = session['token']['access_token']

        rpc = SimpleRPC(session['token']['access_token'], uri=rpc_url, verify_ssl=False)

        try:
            rpc.identity.me.scopes()  # Just checking authentication
        except HTTPError as e:
            if e.response.status_code == 401:
                logout_user()
                session.clear()
                raise Exception('There were problems authenticating your access with PlaidCloud. If you see this message, please refresh your browser') from e
            raise

        return rpc


    def _can_access_project(self, project_id):
        rpc = self.get_rpc()
        try:
            proj = rpc.analyze.project.project(project_id=project_id)
        except:
            proj = None

        if not (proj and proj.get('id')) and '-' in project_id:
            # Try again without dashes
            smooshed_project_id = project_id.replace('-', '')
            try:
                proj = rpc.analyze.project.project(project_id=smooshed_project_id)
            except:
                proj = None

        return proj and proj.get('id')


    def can_access_database(self, database: Union["Database", "DruidCluster"]) -> bool:
        log.debug(f"Can access database: {database}")
        return (
            self._can_access_project(str(database.uuid))
            or super().can_access_database(database)
        )


    def can_access_schema(self, datasource: "BaseDatasource") -> bool:
        return self.can_access_datasource(datasource)


    def can_access_datasource(self, datasource: "BaseDatasource") -> bool:
        log.debug(f"Checking access to datasource: {datasource}")
        if datasource.schema is None:
            # Call the base method if there is no schema since there isn't a plaid schema.
            return super().can_access_datasource(datasource)

        project_id = datasource.schema.replace("report", "")
        return (
            self._can_access_project(project_id)
            or super().can_access_datasource(datasource)
        )


    def is_owner(self, resource: Model) -> bool:
        from superset.models.slice import Slice  # a Slice is a chart
        if isinstance(resource, Slice):
            return super().is_owner(resource) or any([self.is_owner(dashboard) for dashboard in resource.dashboards])

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
        rpc = self.get_rpc()
        projects = rpc.analyze.project.projects()
        project_uuids = {str(uuid.UUID(project['id'])) for project in projects}
        return self.get_session.query(Database).filter(Database.uuid.in_(project_uuids))

    def user_view_menu_names(self, permission_name: str) -> set[str]:
        if permission_name == 'database_access':
            project_perms = {db.perm for db in self._get_project_dbs()}
            return project_perms | super().user_view_menu_names(permission_name)

        return super().user_view_menu_names(permission_name)


    # - Database.perm!
    # So I think maybe the other thing to do is to override user_view_menu_names, and add accessible projects in if it's queried on "database_access "?
    # Superset's get_accessible_databases is based on self.user_view_menu_names("database_access"), and it uses DATABASE_PERM_REGEX to extract the id, I think?
    # According to unpack_database_and_schema, it looks like a schema_permission looks like [database_name].[schema|table] , I think with the square brackets included.
    # unpack_database_and_schema is run on the things erturned by user_view_menu_names
    # so is the regex in get_accessible_databases()
    #Looks like maybe it's [database_name].[schema|table].id:<id> (where the first id is literal, the second is an id)
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
            self, database: "Database", schemas: List[str], hierarchical: bool = True
    ) -> List[str]:
        REPORTING_SCHEMA_PREFIX = 'report'

        schema = str(database.uuid)
        if not schema.startswith(REPORTING_SCHEMA_PREFIX):
            schema = f'{REPORTING_SCHEMA_PREFIX}{schema}'

        if schema in schemas:
            return [schema]

        return []


    def get_table_ids(self):
        rpc = self.get_rpc()
        start = time.time()
        tables = rpc.analyze.table.published_tables_by_project()
        end = time.time()
        table_ids = {str(uuid.UUID(table['id'].replace('analyzetable_', ''))) for table in tables}
        log.debug(f"Fetched table IDs in {end - start}: {table_ids}")
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
