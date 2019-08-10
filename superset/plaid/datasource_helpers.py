# coding=utf-8

import logging
import traceback
from sqlalchemy import create_engine
from sqlalchemy.engine import reflection
from superset import db, security_manager
from superset.models.core import Database
from superset.connectors.sqla.models import SqlaTable

__author__ = "Garrett Bates"
__copyright__ = "© Copyright 2018, Tartan Solutions, Inc"
__credits__ = ["Garrett Bates"]
__license__ = "Proprietary"
__maintainer__ = "Garrett Bates"
__email__ = "garrett.bates@tartansolutions.com"

log = logging.getLogger(__name__)
log.setLevel("DEBUG")

def sync_report_datasources(project_ids=[]):
    '''Synchronize all project datasources that the current user has access to.

    The RPC is called via the security manager, using the current active token.

    Returns:
        dict: A collection of `SqlaTable` data models, indexed by project ID.
    '''
    log.debug('Syncing all report datasources.')
    try:
        projects = security_manager.rpc.analyze.project.projects(
            all_workspaces=True, id_filter=project_ids)
        log.debug(projects)
        return {
            project['id']: sync_report_datasource(project)
            for project in projects
        }
    except AttributeError:
        log.error('RPC unspecified. Login to fix this. %s', traceback.print_exc())
        return dict()
    except:
        log.error('Unexpected error: %s', traceback.print_exc())
        raise

def sync_report_datasource(project):
    """Synchronizes a single plaid project with superset.

    Args:
        workspace_name (str): Name of the Plaid workspace.
        project_name (str): Name of the Plaid project.
        project_id (str): Unique ID of the plaid project.

    Returns:
        list: Collection of `SqlaTable` objects representing report views.

    Remarks:
        I suspect this function is slow. Worst-case scenario involves opening
        two database connections per project, which can get expensive if there
        are many projects.
    """
    log.debug('project_id: %s', project['id'])
    log.debug('project_name: %s', project['name'])
    log.debug('workspace_name: %s', project['workspace_name'])

    database_url = get_report_database_url(
        report_user=project['report_database_user'],
        report_pass=project['report_database_password'],
    )
    schema_name = get_report_schema_name(project['id'])
    engine = create_engine(database_url)
    insp = reflection.Inspector.from_engine(engine)
    views = insp.get_view_names(schema_name)
    log.debug([view for view in views])
    if views: # The schema is not empty, so add the project as DB.
        database = add_report_database(
            database_name=project['id'],
            verbose_name=get_report_database_name(
                project['workspace_name'],
                project['name'],
                project['id'],
            ),
            report_user=project['report_database_user'],
            report_password=project['report_database_password'],
        )

        if not database:
            return [] # Can't really do much if no DB.

        # Add schema perm.
        schema_perm = security_manager.get_schema_perm(database, schema_name)
        security_manager.merge_perm('schema_access', schema_perm)
        views = get_report_views(database, schema_name)
    return views

def add_report_database(database_name, verbose_name, report_user, report_password):
    """Add a plaid data source to superset if it does not yet exist.

    Args:
        database_name (str): The unique name of the database.
        verbose_name (str): The human-friendly name of the database.
        report_user (str): The database role name used for the SQLA URI.
        report_password (str): The database role password used for the SQLA URI.

    Returns:
        `Database`: SQLA model representing the new/existing database.
    """
    database = find_report_database(database_name)
    if not database:
        if not (report_user and report_password):
            log.error(
                'Error creating a new database for project %s:'
                'report user and/or password unspecified.', database_name
            )
            return None
        database = Database(
            sqlalchemy_uri=get_report_database_url(report_user, report_password),
            password=report_password,
            database_name=database_name,
            verbose_name=verbose_name,
            expose_in_sqllab=True
        )
        db.session.add(database)
        db.session.commit()
    return database

def get_report_database_url(report_user, report_pass):
    host = security_manager.appbuilder.app.config.get('PLAID_DATABASE_HOST', 'localhost')    
    return 'postgresql://{0}:{1}@{2}/plaid_data'.format(report_user, report_pass, host)

def find_report_database(database_name):
    """Return a database entry from the superset database by name.

    Returns:
        `Database`: SQLA model representing the database.
    """
    return db.session \
             .query(Database) \
             .filter(Database.database_name == database_name) \
             .first() #noqa

def get_report_database_name(workspace_name, project_name, project_id):
    """Creates a human-readable database name with standard formatting.

    Returns:
        str: Human-readable name of database.
    """
    return '{} :: {} ({})'.format(workspace_name, project_name, project_id[:4])

def get_report_schema_name(project_id):
    """Creates a report schema name with standard formatting.

    Returns:
        str: Name of schema.
    """
    # Database is named after project ID, and schema is "report" + project ID.
    return 'report{}'.format(project_id)

def get_report_views(database, schema=None):
    """Get a list of report views from a database.

    If a view is found in the database that is not yet listed in superset,
    this method will create the view and return it with the others.

    Args:
        database (:obj:`Database`): SQLA model representing the database.
        schema (str, optional): Name of the reporting schema.

    Returns:
        list: Collection of `SqlaTable` objects representing report views.
    """
    # Iterate through each view available to the reporting user.
    # We want to add the view to superset if it doesn't exist.
    view_names_in_plaid = [obj.table for obj in database.get_all_view_names_in_schema(schema)]
    log.debug('Plaid views: %s', view_names_in_plaid)
    view_objs_in_db = db.session.query(
        SqlaTable
    ).filter(
        SqlaTable.table_name.in_(view_names_in_plaid),
        SqlaTable.schema == schema,
        SqlaTable.database_id == database.id
    ).all()

    view_names_in_db = [view.table_name for view in view_objs_in_db]
    log.debug('Superset views: %s', view_names_in_db)

    def add_view(view_name, schema, database):
        view_obj = SqlaTable(
            table_name=view_name,
            schema=schema,
            database=database,
        )
        db.session.add(view_obj)
        view_obj.fetch_metadata()
        return view_obj

    view_objs_in_db.extend([
        add_view(view_name, schema, database)
        for view_name in view_names_in_plaid if view_name not in view_names_in_db
    ])

    return view_objs_in_db
