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
        raise NotImplementedError()


    def _handle_project_event(self, event_type, data, **kwargs):
        # if 'workspace_id' not in kwargs:
        #     raise KeyError('workspace_id is required for handling project events.')

        def map_data_to_row(obj):
            if isinstance(obj, PlaidProject):
                proj = obj
            else:
                proj = PlaidProject()

            proj.name = obj["name"]
            proj.uuid = obj["id"]
            proj.workspace_id = kwargs["workspace_id"]
            proj.workspace_name = obj[""]
            proj.password = obj["report_database_password"]

            # TODO: Parameterize port, and maybe database name.
            driver = "postgresql"
            host = config.get("PLAID_DATABASE_HOST")
            user = obj["report_database_user"]
            port = "5432"
            db_name = "plaid_data" # This is static. Maybe configurable?

            # Construct URI and use sqla mapping method to set it.
            uri = f"{driver}://{user}:{proj.password}@{host}:{port}/{db_name}"
            proj.set_sqlalchemy_uri(uri)

            return proj


        def insert_project(obj):
            try:
                proj = db.session.query(PlaidProject).filter_by(uuid=obj['id']).one()
            except NoResultFound:
                # TODO: Continue with insert, since no result was found
                new_proj = map_data_to_row(obj)
                db.session.add(new_proj)
                db.session.commit()
            else:
                # TODO: Log a warning here.
                update_project(obj)             


        def update_project(obj):
            try:
                proj = db.session.query(PlaidProject).filter_by(uuid=obj['id']).one()
            except NoResultFound:
                # TODO: Log a warning here.
                insert_project(obj)
            else:
                updated_proj = map_data_to_row(proj)
                db.session.commit()


        def delete_project(obj):
            db.session.query(PlaidProject).filter_by(uuid=obj['id']).delete()

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
