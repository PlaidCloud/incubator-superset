#!/usr/bin/env python
# coding=utf-8

import logging
from enum import Enum
import json
import pika
from sqlalchemy import in_, notin_
from sqlalchemy.orm.exc import NoResultFound

from flask_appbuilder import Model
from superset import app, db, security_manager
from superset.connectors.plaid.models import PlaidTable, PlaidProject

log = logging.getLogger(__name__)
config = app.config
REQUIRED_FIELDS = {'event', 'type', 'data'}

class PlaidUserMap(Model):
    """This model exists solely to relate superset user IDs to plaid user IDs."""

    __tablename__ = "plaiduser_user"
    __table_args__ = (UniqueConstraint("plaid_user_id"),)

    user_id = Column(Integer, ForeignKey("ab_user.id"), primary_key=True)
    plaid_user_id = Column(Integer, unique=True)

    user = relationship(
        "User",
        backref=backref("plaiduser_user", cascade="all, delete-orphan"),
        foreign_keys=[user_id],
    )

# Create just the table above, just in case.
Model.metadata.create_all(db.engine, tables=[Model.metadata.tables["plaiduser_user"]])

class BaseEnum(Enum):
    # TODO: Figure out how to avoid copy/pasting this class (and subclasses) from plaid.
    # maybe add it to plaidtools somehow?
    def __str__(self):
        return str(self.value)


class PlaidObjectType(BaseEnum):
    __order__ = 'Workspace Project Workflow Step Table View Udf Editor User'

    Workspace = 'workspace'
    Project = 'project'
    Workflow = 'workflow'
    Step = 'step'
    Table = 'table'
    View = 'view'
    Udf = 'user-defined-function'
    Editor = 'data_editor'
    User = 'user'


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
        self.host = 'rabbit-rabbitmq-ha.plaid'
        self.port = 5672
        self.queue = 'events'
        self.vhost = 'events'

        username = 'event_user'
        password = 'cocoa puffs'
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
        for _, __, body in channel.consume(self.queue, inactivity_timeout=1): # pylint: disable=unused-variable
            self.process_event(json.loads(body))


    def process_event(self, info):
        event_type = EventType(info['event'])
        object_type = PlaidObjectType(info['type'])
        data = info['data']
        kwargs = {k: v for k, v in info.items() if k not in REQUIRED_FIELDS}

        event_handlers = {
            PlaidObjectType.Workspace: self._handle_workspace_event,
            PlaidObjectType.Project: self._handle_project_event,
            PlaidObjectType.Table: self._handle_table_event,
            PlaidObjectType.View: self._handle_view_event,
            PlaidObjectType.User: self._handle_user_event,
        }

        handle_event = event_handlers.get(object_type, self._handle_passthrough)

        handle_event(event_type, data, **kwargs)


    def _handle_workspace_event(self, event_type, data, **kwargs):
        if event_type is EventType.Create:
            # Create events would be a no-op here, so ignore them.
            pass
        elif event_type is EventType.Update:
            # TODO: Might need update call to use synchronize_session=False?
            db.session.query(PlaidProject).filter_by(
                workspace_id=data['id']
            ).update(
                {PlaidProject.workspace_name: data['name']}
            )
        elif event_type is EventType.Delete:
            db.session.query(PlaidProject).filter_by(workspace_id=data['id']).delete()
        
        db.session.commit()


    def _handle_project_event(self, event_type, data, **kwargs):
        def map_data_to_row(event_data, existing_project=None):
            if isinstance(existing_project, PlaidProject):
                proj = existing_project
            else:
                proj = PlaidProject()

            proj.name = event_data["name"]
            proj.uuid = event_data["id"]
            proj.workspace_id = kwargs["workspace_id"]
            proj.workspace_name = event_data[""]
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
            if db.session.query(PlaidProject).filter_by(uuid=event_data['id']).exists():
                # Project doesn't exist, so make a new one.
                new_project = map_data_to_row(event_data)
                db.session.add(new_project)
                db.session.commit()
                
                security_manager.add_project(new_project)
            else:
                # TODO: Log a warning here. No project should exist.
                update_project(event_data)


        def update_project(event_data):
            try:
                existing_project = db.session.query(PlaidProject).filter_by(uuid=event_data['id']).one()
            except NoResultFound:
                # TODO: Log a warning here. A project should exist.
                insert_project(event_data)
            else:
                map_data_to_row(event_data, existing_project)
                db.session.commit()


        def delete_project(event_data):
            db.session.query(PlaidProject).filter_by(uuid=event_data['id']).delete()
            db.session.commit()


        if event_type is EventType.Create:
            insert_project(data)
        elif event_type is EventType.Update:
            update_project(data)
        elif event_type is EventType.Delete:
            delete_project(data)


    def _handle_table_event(self, event_type, data, **kwargs):
        if not data.get("published_name"):
            # Table isn't published, so do nothing.
            pass

        def map_data_to_row(event_data, existing_table=None):
            if isinstance(existing_table, PlaidTable):
                table = existing_table
            else:
                table = PlaidTable()

            table.table_name = event_data["id"]
            table.friendly_name = event_data["name"]
            table.project_id = kwargs["project_id"]
            table.schema = f"report{table.project_id.strip('-')}"

            return table


        def insert_table(event_data):
            # TODO: check if table exists. If it does, update, otherwise insert.
            if db.session.query(PlaidTable).filter_by(name=event_data['id']).exists():
                # Table doesn't exist, so make a new one.
                new_table = map_data_to_row(event_data)
                db.session.add(new_table)
                db.session.commit()
            else:
                # TODO: Log a warning here. No table should exist.
                update_table(event_data)


        def update_table(event_data):
            try:
                existing_table = db.session.query(PlaidTable).filter_by(name=event_data['id']).one()
            except NoResultFound:
                # TODO: Log a warning here. A table should exist.
                insert_table(event_data)
            else:
                map_data_to_row(event_data, existing_table)
                db.session.commit()


        def delete_table(event_data):
            db.session.query(PlaidTable).filter_by(name=event_data['id']).delete()
            db.session.commit()


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

        def add_user(event_data):
            # Create the user.
            user = security_manager.add_user(
                username=event_data['name'],
                first_name=event_data['first_name'],
                last_name=event_data['last_name'],
                email=event_data['email'],
                role=security_manager.find_role('Plaid')
            )

            # Map the user's ID to the plaid user's ID.
            user_map = PlaidUserMap()
            user_map.user_id = user.id
            user_map.plaid_user_id = event_data["id"]
            db.session.add(user_map)

            # Grant the user access to authorized projects.
            for project_id in event_data["projects"]:
                security_manager.add_user_to_project(user, project_id)
            
            db.session.commit()


        def update_user(event_data):
            try:
                # Look up user by their ID in plaid's DB.
                user = security_manager.get_session.query(
                           security_manager.user_model
                       ).join(
                            (PlaidUserMap, security_manager.user_model.id == PlaidGroupMap.user_id),
                       ).filter(
                           PlaidUserMap.plaid_user_id=event_data["id"]
                       ).one()

                user.username = event_data["name"]
                user.first_name = event_data["first_name"]
                user.last_name = event_data["last_name"]
                user.email = event_data["email"]
                
                security_manager.update_user(user)

            except NoResultFound:
                log.warning(
                    f"User {event_data['name']} ({event_data['id']}) "
                    f"was found while attempting to update."
                )
                add_user(event_data)


        def update_project_access(event_data):
            try:
                # Reassign table objects for readability.
                User = security_manager.user_model
                Role = security_manager.role_model
                UserRoleMap = Model.metadata.tables["ab_user"]

                project_role = security_manager.find_role(security_manager.get_project_role_name(project_id))

                # Delete every user not in the list from the project role.
                db.session.query(
                    UserRoleMap
                ).join(
                    (PlaidUserMap, UserRoleMap.user_id == PlaidUserMap.user_id),
                    (Role, UserRoleMap.role_id == Role.id)
                ).filter(
                    PlaidUserMap.plaid_user_id.notin_(event_data),
                    Role.name == project_role.name,
                ).delete()

                # Get every user in the list that doesn't have the project role.
                users = db.session.query(
                    User
                ).join(
                    (Role, User.roles),
                    (PlaidUserMap, User.id == PlaidUserMap.user_id),
                ).filter(
                    Role.name != project_role.name,
                    PlaidUserMap.plaid_user_id.in_(event_data)
                ).all()

                # Add the project role for each user.
                for user in users:
                    user.roles.add(role)

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                raise
            finally:
                # TODO: I believe destroying scoped session is necessary for long-running tasks.
                db.session.remove()

        if event_type is EventType.Create:
            add_user(data)
        elif event_type is EventType.Update:
            update_user(data)
        elif event_type is EventType.Delete:
            # TODO: There isn't a means to delete a user via security manager, so need to make one.
            pass
        elif event_type is EventType.ProjectAccessChange:
            update_project_access(data)    
        elif event_type is EventType.WorkspaceAccessChange:
            for project in db.session.query(PlaidProject).filter_by(workspace_id=event_data['workspace_id']).all():
                update_project_access(data)


    def _handle_passthrough(self, event_type, data, **kwargs):
        # TODO: Should we debug log unhandled events?
        pass


if __name__ == "__main__":
    handler = EventHandler()
    handler.consume()
