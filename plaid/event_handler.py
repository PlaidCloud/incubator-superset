#!/usr/bin/env python
# coding=utf-8

import logging
import time
from enum import Enum
import json
from typing import Optional, Any, Dict

import pika
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
)
from sqlalchemy.exc import NoSuchTableError, SQLAlchemyError
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
from superset.models.cache import CacheKey
from superset.extensions import cache_manager


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
    def __str__(self) -> str:
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


class EventHandler:
    """Handles plaid-sourced events from a message queue."""

    def __init__(self) -> None:
        """Docstring"""
        rmq_connection_info = config.get('RABBITMQ_CONNECTION_INFO', {})

        self.host = rmq_connection_info.get('host', 'rabbitmq-rabbitmq-ha')
        self.port = rmq_connection_info.get('port', 5672)
        self.queue = rmq_connection_info.get('queue', 'events')
        self.vhost = rmq_connection_info.get('vhost', 'events')

        username = rmq_connection_info.get('username', 'event_user')
        password = rmq_connection_info.get('password', 'cocoa puffs')
        self.credentials = pika.PlainCredentials(username, password)

    def _connect(self) -> pika.channel.Channel:
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

    def consume(self) -> None:
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

    def process_event(self, info: Dict[str, Any]) -> None:
        try:
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

            # View should work because every time we change the query for a view, we run table.update()
            #   Oh, except, if there's an ancestor that changes that wouldn't work. Hmm.
            #   I'm supposed to not worry about this unless it's easy

            # Paul says that on every table change things are unpublished and republished. If that's so, I should be able
            #   to hook into that.
            #   It seems like every table extract runs an update_shape, which runs an object_tools.save_object (gst.save_object), which runs a _set_object_cache, which publishes either an Update event or a Create event

            handle_event = event_handlers.get(object_type, self._handle_passthrough)

            handle_event(event_type, data, **kwargs)
        except ValueError:
            # Skip this event as it is not recognized.
            self._handle_passthrough(event_type, {})

    def _handle_workspace_event(self, event_type: EventType, data: Dict[str, Any], **kwargs: Any) -> None:
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

    def _handle_project_event(self, event_type: EventType, data: Dict[str, Any], **kwargs: Any) -> None:
        def map_data_to_row(event_data: Dict[str, Any], existing_project: Optional[Database] = None) -> Database:
            if isinstance(existing_project, Database):
                proj = existing_project
            else:
                proj = Database()

            proj.database_name = f"{event_data['name']} ({event_data['id'][:4]})"
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

        def insert_project(event_data: Dict[str, Any]) -> None:
            if not db.session.query(db.session.query(Database).filter_by(uuid=event_data['id']).exists()).scalar():
                # Project doesn't exist, so make a new one.
                log.info(f"Inserting project {event_data['name']} ({event_data['id']}).")
                new_project = map_data_to_row(event_data)
                db.session.add(new_project)
                db.session.commit()
            else:
                # TODO: Log a warning here. No project should exist.
                update_project(event_data)

        def update_project(event_data: Dict[str, Any]) -> None:
            try:
                log.info(f"Updating project {event_data['name']} ({event_data['id']}).")
                existing_project = db.session.query(Database).filter_by(uuid=event_data['id']).one()
            except NoResultFound:
                # TODO: Log a warning here. A project should exist.
                insert_project(event_data)
            else:
                map_data_to_row(event_data, existing_project)
                db.session.commit()

        def delete_project(event_data: Dict[str, Any]) -> None:
            # TODO: Deleting a table associated with a chart breaks UI (can't set new datasource, can only delete chart)
            # Need to figure out how to handle this circumstance (delete charts too? update dataousrce to placeholder?)
            # If update to placeholder, how to regulate perms?
            project = db.session.query(Database).filter_by(uuid=event_data['id']).one()
            for table in project.tables:
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

    def _handle_table_event(self, event_type: EventType, data: Dict[str, Any], **kwargs: Any) -> None:

        def map_data_to_row(event_data: Dict[str, Any], existing_table: Optional[SqlaTable] = None) -> SqlaTable:
            if isinstance(existing_table, SqlaTable):
                table = existing_table
            else:
                table = SqlaTable()

            log.warning(event_data)
            table.table_name = event_data["published_name"]
            table.uuid = event_data["id"].replace('analyzetable_', '')
            table.schema = f"report{kwargs['project_id']}"

            return table

        def clear_table_cache(datasource_uid: str) -> None:
            # Copied from superset/cachekeys/api.py
            cache_key_objs = (
                db.session.query(CacheKey)
                .filter(CacheKey.datasource_uid == datasource_uid)
                .all()
            )
            cache_keys = [c.cache_key for c in cache_key_objs]
            if not cache_keys:
                log.info("No cache records found for datasource %s", datasource_uid)
                return

            all_keys_deleted = cache_manager.cache.delete_many(*cache_keys)
            if not all_keys_deleted:
                # expected behavior as keys may expire and cache is not a
                # persistent storage
                log.info(
                    "Some of the cache keys were not deleted in the list %s", cache_keys
                )

            try:
                delete_stmt = (
                    CacheKey.__table__.delete().where(  # pylint: disable=no-member
                        CacheKey.cache_key.in_(cache_keys)
                    )
                )
                db.session.execute(delete_stmt)
                db.session.commit()

                log.info(
                    "Invalidated %s cache records for datasource %s",
                    len(cache_keys),
                    datasource_uid,
                )
            except SQLAlchemyError as ex:  # pragma: no cover
                log.error(ex, exc_info=True)
                db.session.rollback()

        def insert_table(event_data: Dict[str, Any]) -> None:
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
                log.warning("Received a create event for a table, but the table already exists.")
                update_table(event_data)
                return

            # Table doesn't exist, so make a new one.
            try:
                new_table = map_data_to_row(event_data)
                log.info(f"{new_table.database_id}")

                # Test if source table/view actually exists before we add it.
                try:
                    project = db.session.query(Database).filter_by(uuid=kwargs['project_id']).one()
                    log.info(project.get_all_view_names_in_schema(schema=new_table.schema))
                    # TODO: This is pretty dumb. Event is being processed before the DB can create the view.
                    time.sleep(2)
                    project.get_table(table_name=new_table.table_name, schema=new_table.schema)
                    new_table.database = project
                except (NoResultFound, NoSuchTableError):
                    log.warning(f"Table {new_table.schema}.{new_table.table_name} doesn't exist. Skipping.")
                    return

                # If we've made it this far, the source table/view exists.
                db.session.add(new_table)
                db.session.commit()

                # Populate columns and metrics for table.
                new_table.fetch_metadata()

                db.session.commit()

                clear_table_cache(new_table.uid)

            except Exception:
                log.exception("Error occurred while inserting a new table.")
                db.session.rollback()
                return


        def update_table(event_data: Dict[str, Any]) -> None:
            try:
                log.info(f"Updating table {event_data['published_name']} ({event_data['id']}) for project {kwargs['project_id']}.")
                existing_table = db.session.query(SqlaTable).filter_by(
                    uuid=event_data['id'].replace('analyzetable_', ''),
                ).one()

                if not event_data.get("published_name"):
                    # !! We don't do this any more because sometimes there are multiple tables with the same published name !!
                    # !! Things may seriously break if this code is uncommented. !!

                    # # Table still exists, but the user unpublished it. So we want to delete.
                    # log.info(f"Table {event_data['published_name']} ({event_data['id']}) has no published name, and will be deleted.")
                    # delete_table(event_data)
                    return

                map_data_to_row(event_data, existing_table)
                clear_table_cache(existing_table.uid)

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

        def delete_table(event_data: Dict[str, Any]) -> None:
            try:
                log.info(f"Deleting table {event_data['published_name']} ({event_data['id']}) for project {kwargs['project_id']}.")
                table = db.session.query(SqlaTable).filter(
                    SqlaTable.uuid == event_data['id'].replace('analyzetable_', ''),
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
                    clear_table_cache(table.uid)
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
            # delete_table(data)
            log.warning(f"Received a delete event for table {data['published_name']}, but deleting tables through events is no longer permitted.")

    # TODO: Do we even care about views here? Are views what I think they are?
    #       ADT2022 - I don't think we do. I think that when the things we care about happen to views, a table
    #       event is published.
    def _handle_view_event(self, event_type: EventType, data: Dict[str, Any], **kwargs: Any) -> None:
        raise NotImplementedError()

    def _handle_passthrough(self, event_type: Optional[EventType], data: Optional[Dict[str, Any]], **kwargs: Any) -> None:
        # TODO: Should we debug log unhandled events?
        pass


if __name__ == "__main__":
    handler = EventHandler()
    handler.consume()
