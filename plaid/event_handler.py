#!/usr/bin/env python
# coding=utf-8

from enum import Enum
import json
import pika
from sqlalchemy.orm.exc import NoResultFound

from superset import app, db
from superset.connectors.plaid.models import PlaidTable, PlaidProject

config = app.config
REQUIRED_FIELDS = {'event', 'type', 'data'}

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
        raise NotImplementedError()


    def _handle_view_event(self, event_type, data, **kwargs):
        raise NotImplementedError()


    def _handle_passthrough(self, event_type, data, **kwargs):
        # TODO: Should we debug log unhandled events?
        pass

if __name__ == "__main__":
    handler = EventHandler()
    handler.consume()
