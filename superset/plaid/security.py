# coding=utf-8
"""
Plaid Security Class for Superset
"""
import logging
from sqlalchemy import func
from superset.security import SupersetSecurityManager
from plaidtools.connection.jsonrpc import SimpleRPC

__author__ = "Garrett Bates"
__copyright__ = "© Copyright 2018, Tartan Solutions, Inc"
__credits__ = ["Garrett Bates"]
__license__ = "Proprietary"
__maintainer__ = "Garrett Bates"
__email__ = "garrett.bates@tartansolutions.com"

log = logging.getLogger(__name__)

DATASOURCE_PREFIX = 'datasource_'

def get_ds_role_name(project_id):
    """Fetch the datasource role name by project ID.
    """
    return DATASOURCE_PREFIX + project_id

class PlaidSecurityManager(SupersetSecurityManager):
    """Custom security manager class for PlaidCloud integration.
    """
    @property
    def rpc(self):
        return SimpleRPC(self.oauth_tokengetter()[0],
                         '{}://{}/json-rpc/'.format(
                            self.appbuilder.app.config.get('SCHEME'),
                            self.appbuilder.app.config.get('PLAID_HOST')),
                         verify_ssl=False)


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


    def oauth_user_info(self, provider, resp=None):
        """Retrieves Plaid user info from RPC.

        If the specified oauth provider is not 'plaidcloud', the super
        implementation will be called instead.

        Args:
            provider (str): The name of the selected oauth provider.
            response: Not used. Consult super implementation for relevance.
        """
        if provider == 'plaidcloud':
            try:
                logging.debug("Oauth2 provider: %s.", provider)
                me = self.rpc.identity.me.info()
                logging.debug("user info from RPC: %s", repr(me))
                user = {
                    'first_name': me.get('first_name'),
                    'last_name': me.get('last_name'),
                    'username': me.get('username'),
                    'email': me.get('email'),
                    'active': me.get('is_active'),
                    'admin': me.get('is_admin'),
                }
                logging.debug("user info being returned: %s", repr(user))
                return user
            except: # pylint: disable=bare-except
                import traceback
                logging.exception(traceback.format_exc())

        # Just call the base method so defaults continue to work.
        return super().oauth_user_info(provider, resp)


    def auth_user_oauth(self, userinfo):
        """Create/configure the superset user post-authentication.

        Datasources that the user has access to will be synced here.

        Args:
            userinfo (dict): Information about Plaid user, in this format:
                first_name: First name of user.
                last_name: Last name of user.
                username: Username of user.
                email: Email of user.
                active: Boolean indicating if user account is active.
                admin: Boolean indicating administrator status of user.

        Returns:
            `User` SQLA data model of the new/existing user account.
        """
        user = super().auth_user_oauth(userinfo)
        if not user:
            # User registration is turned off, so random internet folks can't
            # register. However, we want to auto-register plaid users after
            # they authenticate. So, create them here if they don't exist.
            user = self.add_user(
                username=userinfo['username'],
                first_name=userinfo['first_name'],
                last_name=userinfo['last_name'],
                email=userinfo['email'],
                role=self.find_role('Plaid')
            )

            if not user:
                log.error(
                    'Error creating a new OAuth user %s', userinfo['username']
                )
                return None

        admin_enabled = self.appbuilder.app.config.get('ADMIN_ENABLED', False)

        if admin_enabled and userinfo.get('admin'):
            session = self.get_session
            admin_role = self.find_role('Admin')
            user.roles.append(admin_role)
            session.merge(user)
            session.commit()
        #else:
        #    admin_role = self.find_role('Admin')
        #    session = self.get_session
        #    user.roles.remove(admin_role)
        #    session.merge(user)
        #    session.commit()

        self.update_user_auth_stat(user)

        # If the user is an admin in plaidcloud, add them as an admin here.
        # if ('admin' in userinfo and userinfo.get('admin', False)):
        #     role = self.find_role('Admin')
        #     user.roles.append(role)
        #     self.get_session.commit()
        return user


    def sync_datasources(self, project_ids=[]):
        """Pulls all published tables from plaid and creates datasources for 
        them.

        Args:
            project_id (:obj:`list` of :obj:`str`): UUIDs of plaid projects to 
                sync. Default is empty list (all projects).

        Returns:
            None
        """
        # This import throws ImportError if hoisted to top of module.
        from superset.plaid import datasource_helpers as dh
        for proj_id, views in dh.sync_report_datasources(project_ids).items():
            view_perms = [view.get_perm() for view in views]

            # pvm = permission / view menu relation.
            def has_project_access_pvm(pvm):
                '''has_project_access_pvm()

                Callable to determine which permission/view menu relations will
                be added to a role. Used by self.set_role(name, callable)
                method.
                '''
                return pvm.permission.name == 'datasource_access' \
                       and pvm.view_menu.name in view_perms

            # Name the role after the project.
            self.set_role(
                role_name=get_ds_role_name(proj_id),
                pvm_check=has_project_access_pvm
            )
            log.debug('Role {} created.'.format(get_ds_role_name(proj_id)))
            # Add every user that has access to the project to this role.
            self.sync_datasource_perms(proj_id)


    def sync_datasource_perms(self, project_id):
        """Adds all users with project access to the corresponding project
        role.

        Args:
            project_id (str): Project ID to sync users with.
        """
        # Get all of the users that belong to the project we sync'd.
        log.debug('Fetching plaid users for project %s', project_id)
        plaid_users = self.rpc.analyze.project.members(project_id=project_id, details=True)
        log.debug('plaid_users: %s', repr(plaid_users))
        # Get a list of user names so we can bulk-select.
        usernames = [user['user_name'] for user in plaid_users]
        log.debug(usernames)
        role = self.find_role(get_ds_role_name(project_id))

        if not role:
            return

        log.debug(role.name)
        def add_user_to_role(user, role):
            if role not in user.roles:
                user.roles.append(role)
                log.debug(
                    "Appended %s to %s roles list.", role.name, user.username
                )

        for user in self.find_users(usernames):
            add_user_to_role(user, role)

        # Commit role changes.
        self.get_session.commit()


    def find_users(self, usernames=None, emails=None):
        """Finds users by username or email. If usernames are specified, emails
        will be ignored.

        Args:
            usernames (:obj:`list` of :obj:`str`): List of usernames to filter.
            emails (:obj:`list` of :obj:`str`): List of emails to filter.

        Returns:
            :obj:`list`: List containing `User` objects that match filter.
        """
        if usernames:
            # Not sure if lowercase comparison is necessary, but decided to
            # follow the pattern that SupersetSecurityManager.find_user() uses.
            lowercase_names = [x.lower() for x in usernames]
            return self.get_session.query(self.user_model).filter(
                func.lower(self.user_model.username).in_(lowercase_names)
            ).all()

        if emails:
            return self.get_session.query(self.user_model).filter(
                self.user_model.email.in_(emails)
            ).all()

        return []
