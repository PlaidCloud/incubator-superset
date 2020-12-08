#!/usr/bin/env python
# coding=utf-8

import logging
import time
from enum import Enum
import json
import pika
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
)
from sqlalchemy.exc import NoSuchTableError
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import backref, relationship
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.schema import UniqueConstraint
from flask import current_app
from flask_appbuilder import Model
from superset.app import create_app
app = create_app()
app.app_context().push()
from superset import app, db, security_manager
from superset.connectors.sqla.models import SqlaTable, Database, SqlMetric
from superset.models.core import Database
from superset.models.slice import Slice


log = logging.getLogger(__name__)
log.setLevel('INFO')
logging.getLogger("pika").setLevel(logging.WARNING)
config = app.config
REQUIRED_FIELDS = {'event', 'type', 'data'}

User = security_manager.user_model
Role = security_manager.role_model

class BaseEnum(Enum):
    # TODO: Figure out how to avoid copy/pasting this class (and subclasses) from plaid.
    # maybe add it to plaidtools somehow?
    def __str__(self):
        return str(self.value)


class PlaidObjectType(BaseEnum):
    __order__ = 'Workspace Project Workflow Step Table View Udf Editor User WorkflowState StepState'

    Workspace = 'workspace'
    Project = 'project'
    Workflow = 'workflow'
    Step = 'step'
    Table = 'table'
    View = 'view'
    Udf = 'user-defined-function'
    Editor = 'data_editor'
    User = 'user'
    WorkflowState = 'workflow-state'
    StepState = 'step-state'


class EventType(BaseEnum):
    __order__ = 'Create Update Delete WorkspaceAccessChange ProjectAccessChange'

    Create = 'create'
    Update = 'update'
    Delete = 'delete'
    WorkspaceAccessChange = 'workspace-access-change'
    ProjectAccessChange = 'project-access-change'

class EventHandler():
    """Handles plaid-sourced events from a message queue."""

    def __init__(self):
        """Docstring"""
        rmq_connection_info = config.get('RABBITMQ_CONNECTION_INFO', {})

        self.host = rmq_connection_info.get('host', 'rabbitmq-rabbitmq-ha')
        self.port = rmq_connection_info.get('port', 5672)
        self.queue = rmq_connection_info.get('queue', 'events')
        self.vhost = rmq_connection_info.get('vhost', 'events')

        username = rmq_connection_info.get('username', 'event_user')
        password = rmq_connection_info.get('password', 'cocoa puffs')
        self.credentials = pika.PlainCredentials(username, password)


    def _connect(self):
        """Docstring"""
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                virtual_host=self.vhost,
                credentials=self.credentials,
                socket_timeout=15,
            )
        )
        return connection.channel()


    def consume(self):
        """Docstring"""
        channel = self._connect()
        for method, _, body in channel.consume(self.queue, inactivity_timeout=1): # pylint: disable=unused-variable
            try:
                data = json.loads(body)
            except:
                continue
            # Comment this out for debugging so messages aren't requeued.
            channel.basic_ack(method.delivery_tag)
            self.process_event(data)


    def process_event(self, info):
        event_type = EventType(info['event'])
        object_type = PlaidObjectType(info['type'])
        data = info['data']
        kwargs = {k: v for k, v in info.items() if k not in REQUIRED_FIELDS}

        event_handlers = {
            # PlaidObjectType.Workspace: self._handle_workspace_event,
            PlaidObjectType.Project: self._handle_project_event,
            PlaidObjectType.Table: self._handle_table_event,
            PlaidObjectType.View: self._handle_view_event,
            # PlaidObjectType.User: self._handle_user_event,
        }

        handle_event = event_handlers.get(object_type, self._handle_passthrough)

        handle_event(event_type, data, **kwargs)


    def _handle_workspace_event(self, event_type, data, **kwargs):
        if event_type is EventType.Create:
            # Create events would be a no-op here, so ignore them.
            pass
        elif event_type is EventType.Update:
            # TODO: Might need update call to use synchronize_session=False?
            db.session.query(Database).filter_by(
                workspace_id=data['id']
            ).update(
                {Database.workspace_name: data['name']}
            )
        elif event_type is EventType.Delete:
            db.session.query(Database).filter_by(workspace_id=data['id']).delete()
        
        db.session.commit()


    def _handle_project_event(self, event_type, data, **kwargs):
        def map_data_to_row(event_data, existing_project=None):
            if isinstance(existing_project, Database):
                proj = existing_project
            else:
                proj = Database()

            proj.database_name = event_data["name"]
            proj.verbose_name = event_data["id"]
            proj.uuid = event_data["id"]
            proj.password = event_data["report_database_password"]

            # TODO: Parameterize port, and maybe database name and driver.
            driver = "postgresql"
            host = config.get("PLAID_DATABASE_HOST")
            user = event_data["report_database_user"]
            port = "5432"
            db_name = "plaid_data" # This is static. Maybe configurable?

            # Construct URI and use sqla mapping method to set it.
            uri = f"{driver}://{user}:{proj.password}@{host}:{port}/{db_name}"
            proj.set_sqlalchemy_uri(uri)

            return proj


        def insert_project(event_data):
            if not db.session.query(db.session.query(Database).filter_by(verbose_name=event_data['id']).exists()).scalar():
                # Project doesn't exist, so make a new one.
                log.info(f"Inserting project {event_data['name']} ({event_data['id']}).")
                new_project = map_data_to_row(event_data)
                db.session.add(new_project)
                db.session.commit()
            else:
                # TODO: Log a warning here. No project should exist.
                update_project(event_data)


        def update_project(event_data):
            try:
                log.info(f"Updating project {event_data['name']} ({event_data['id']}).")
                existing_project = db.session.query(Database).filter_by(verbose_name=event_data['id']).one()
            except NoResultFound:
                # TODO: Log a warning here. A project should exist.
                insert_project(event_data)
            else:
                map_data_to_row(event_data, existing_project)
                db.session.commit()


        def delete_project(event_data):
            # TODO: Deleting a table associated with a chart breaks UI (can't set new datasource, can only delete chart)
            # Need to figure out how to handle this circumstance (delete charts too? update dataousrce to placeholder?)
            # If update to placeholder, how to regulate perms?
            project = db.session.query(Database).filter_by(verbose_name=event_data['id']).one()
            for table in project.plaid_tables:
                log.info(f"Deleting table {table.table_name} ({table.uuid}).")
                db.session.delete(table)
            log.info(f"Deleting project {event_data['name']} ({event_data['id']}).")
            db.session.delete(project)
            db.session.commit()


        if event_type is EventType.Create:
            insert_project(data)
        elif event_type is EventType.Update:
            update_project(data)
        elif event_type is EventType.Delete:
            delete_project(data)


    def _handle_table_event(self, event_type, data, **kwargs):

        def map_data_to_row(event_data, existing_table=None):
            if isinstance(existing_table, SqlaTable):
                table = existing_table
            else:
                table = SqlaTable()

            log.warning(event_data)
            table.table_name = event_data["published_name"]
            table.uuid = event_data["id"].replace('analyzetable_', '')
            table.schema = f"report{kwargs['project_id']}"

            return table


        def insert_table(event_data):
            if not event_data.get("published_name"):
                log.info(
                    f"Received table insert event for {event_data['id']} "
                    f"(Project {kwargs['project_id']}), but no published name is set. "
                    f"Skipping."
                )
                return
            log.info(f"Inserting table {event_data['published_name']} ({event_data['id']}) for project {kwargs['project_id']}.")
            log.info(f"{event_data['id'].replace('analyzetable_', '')}")
            if not db.session.query(
                db.session.query(SqlaTable).filter_by(
                        uuid=event_data['id'].replace('analyzetable_', ''),
                    ).exists()
                ).scalar():
                # Table doesn't exist, so make a new one.
                try:
                    new_table = map_data_to_row(event_data)
                    log.info(f"{new_table.database_id}")

                    # Test if source table/view actually exists before we add it.
                    try:
                        project = db.session.query(Database).filter_by(verbose_name=kwargs['project_id']).one()
                        log.info(project.get_all_view_names_in_schema(schema=new_table.schema))
                        # TODO: This is pretty dumb. Event is being processed before the DB can create the view. 
                        time.sleep(2)
                        project.get_table(table_name=new_table.table_name, schema=new_table.schema)
                        new_table.database = project
                    except NoSuchTableError:
                        log.warning(f"Table {new_table.schema}.{new_table.table_name} doesn't exist. Skipping.")
                        return

                    # If we've made it this far, the source table/view exists.
                    db.session.add(new_table)
                    db.session.commit()
                    
                    # Populate columns and metrics for table.
                    new_table.fetch_metadata()
                    
                    db.session.commit()
                except Exception:
                    log.exception("Error occurred while inserting a new table.")
                    db.session.rollback()
                    return
            else:
                log.warning("Received a create event for a table, but the table already exists.")
                update_table(event_data)


        def update_table(event_data):
            try:
                log.info(f"Updating table {event_data['published_name']} ({event_data['id']}) for project {kwargs['project_id']}.")
                existing_table = db.session.query(SqlaTable).filter_by(
                    uuid=event_data['id'].replace('analyzetable_', ''),
                ).one()
                if not event_data.get("published_name"):
                    # Table still exists, but the user unpublished it. So we want to delete.
                    log.info(f"Table {event_data['published_name']} ({event_data['id']}) has no published name, and will be deleted.")
                    delete_table(event_data)
                    return
                map_data_to_row(event_data, existing_table)
                # TODO: This is pretty dumb. Event is being processed before the DB can create the view.
                time.sleep(2)
                existing_table.fetch_metadata()
                db.session.commit()
            except NoResultFound:
                log.warning("Received an update event for a table that doesn't exist.")
                insert_table(event_data)
            except Exception:
                log.exception("Error occurred while updating a table.")
                db.session.rollback()


        def delete_table(event_data):
            try:
                log.info(f"Deleting table {event_data['published_name']} for project {kwargs['project_id']}.")
                table = db.session.query(SqlaTable).filter(
                    SqlaTable.uuid == event_data['id'],
                    SqlaTable.schema == f"report{kwargs['project_id']}",
                ).one()

                has_charts = db.session.query(
                        db.session.query(Slice).filter_by(datasource_id=table.id, datasource_type='plaid').exists()
                    ).scalar()

                has_metrics = db.session.query(
                        db.session.query(SqlMetric).filter(
                            SqlMetric.table_id == table.id,
                            SqlMetric.metric_name != 'count'
                        ).exists()
                    ).scalar()

                if not has_charts and not has_metrics:
                    security_manager.del_permission_view_menu('datasource_access', table.get_perm())
                    db.session.delete(table)
                    db.session.commit()
            except NoResultFound:
                log.warning("Received a delete event for a table that doesn't exist.")
            except Exception:
                log.exception("Error occurred while deleting a table.")
                db.session.rollback()


        if event_type is EventType.Create:
            insert_table(data)
        elif event_type is EventType.Update:
            update_table(data)
        elif event_type is EventType.Delete:
            delete_table(data)


    # TODO: Do we even care about views here? Are views what I think they are?
    def _handle_view_event(self, event_type, data, **kwargs):
        raise NotImplementedError()


    def _handle_user_event(self, event_type, data, **kwargs):
        plaid_role = security_manager.find_role("Plaid")

        def _get_user(event_data):
            return security_manager.get_session.query(
                    User
                ).join(
                    (PlaidUserMap, User.id == PlaidGroupMap.user_id),
                ).filter(
                    PlaidUserMap.plaid_user_id == event_data["id"]
                ).one()

        def add_user(event_data):
            try:
                user = _get_user(event_data)

                log.warning(f"Received a create event for user {user.first_name} {user.last_name} ({user.username}), but the user already exists.")

                user.username = event_data["name"]
                user.first_name = event_data["first_name"]
                user.last_name = event_data["last_name"]

                if db.session.query(db.session.query(PlaidUserMap).filter_by(user_id=user.id).exists()).scalar():
                    user_map = db.session.query(PlaidUserMap).filter_by(user_id=user.id).one()
                    user_map.plaid_user_id = event_data["id"]
                else:
                    user_map = PlaidUserMap()
                    user_map.user_id = user.id
                    user_map.plaid_user_id = event_data["id"]
                    db.session.add(user_map)                  

            except NoResultFound:
                # Create the user.
                user = security_manager.add_user(
                    username=event_data['name'],
                    first_name=event_data['first_name'],
                    last_name=event_data['last_name'],
                    email=event_data['email'],
                    role=security_manager.find_role('Plaid')
                )

                try:
                    # Map the user's ID to the plaid user's ID.
                    user_map = PlaidUserMap()
                    user_map.user_id = user.id
                    user_map.plaid_user_id = event_data["id"]
                    db.session.add(user_map)
                except AttributeError:
                    log.exception(f"Failed to create new user {event_data['name']} (ID: {event_data['id']}).")

            if plaid_role not in user.roles:
                user.roles.append(plaid_role)

            # Grant the user access to authorized projects.
            for project_id in event_data["projects"]:
                security_manager.add_user_to_project(user, project_id)

            db.session.commit()


        def update_user(event_data):
            try:
                # Look up user by their ID in plaid's DB.
                user = _get_user(event_data)

                user.username = event_data["name"]
                user.first_name = event_data["first_name"]
                user.last_name = event_data["last_name"]

                if plaid_role not in user.roles:
                    user.roles.append(plaid_role)

                security_manager.update_user(user)


            except NoResultFound:
                log.warning(
                    f"User {event_data['name']} ({event_data['id']}) "
                    f"was found while attempting to update."
                )
                add_user(event_data)


        # def update_project_access(event_data, project_id):
        #     try:
        #         project_role = security_manager.find_role(f'project_{project_id}')

        #         if not project_role:
        #             log.warning(f"Role not found for project {project_id}")
        #             return

        #         # Delete every user not in the list from the project role.
        #         user_maps = db.session.query(
        #             UserRoleMap
        #         ).join(
        #             (PlaidUserMap, UserRoleMap.user_id == PlaidUserMap.user_id),
        #             (Role, UserRoleMap.role_id == Role.id)
        #         ).filter(
        #             PlaidUserMap.plaid_user_id.notin_(event_data),
        #             Role.name == project_role.name,
        #         ).all()

        #         log.info(f"Users who lost access: {[user.user_id for user in user_maps]}")
        #         for mapp in user_maps:
        #             db.session.delete(mapp)

        #         # Get every user in the list that doesn't have the project role.
        #         # TODO: For workspace access changes, do we need to check access type?
        #         # For example:
        #         #   A workspace is changed and user gains scope to see data.
        #         #   However, they still don't have access to certain projects in
        #         #   this workspace based on user ACL, but they'll be added here
        #         #   anyway. It seems we need to reconfirm project access after
        #         #   a workspace is updated.
        #         users = db.session.query(
        #             User
        #         ).join(
        #             (Role, User.roles),
        #             (PlaidUserMap, User.id == PlaidUserMap.user_id),
        #         ).filter(
        #             Role.name != project_role.name,
        #             PlaidUserMap.plaid_user_id.in_(event_data)
        #         ).all()

        #         log.info(f"Users with access: {users}")
        #         # Add the project role for each user.
        #         for user in users:
        #             user.roles.append(project_role)

        #         db.session.commit()
        #     except Exception:
        #         log.exception("Something went wrong updating project access.")
        #         db.session.rollback()
        #     finally:
        #         # TODO: I believe destroying scoped session is necessary for long-running tasks.
        #         db.session.remove()

        if event_type is EventType.Create:
            add_user(data)
        elif event_type is EventType.Update:
            update_user(data)
        elif event_type is EventType.Delete:
            # TODO: There isn't a means to delete a user via security manager, so need to make one.
            pass
        elif event_type is EventType.ProjectAccessChange:
            update_project_access(data, kwargs['project_id'])
        elif event_type is EventType.WorkspaceAccessChange:
            for project_id in db.session.query(Database.uuid).filter_by(workspace_id=data['workspace_id']).scalar():
                update_project_access(data, project_id)


    def _handle_passthrough(self, event_type, data, **kwargs):
        # TODO: Should we debug log unhandled events?
        pass


if __name__ == "__main__":
    handler = EventHandler()
    handler.consume()