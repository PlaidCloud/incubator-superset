#!/usr/bin/env python
# coding=utf-8

import logging
import time
from enum import Enum
import json
from typing import Optional, Any, Dict, Tuple, List
from collections.abc import Collection
import socket

from plaidcloud.config import config as cfg

import redis
from redis.sentinel import Sentinel
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
ANALYZE_CONNECTION_NAME = 'analyze_cache'
SUPERSET_QUEUE_KEY = 'superset-queue'
CLIENT_NAME = socket.gethostname().rsplit('-', 2)[0]
REDIS_CONNECTION_RETRY_WAIT_SECS = 0.2

User = security_manager.user_model
Role = security_manager.role_model

class RedisWithRetry(redis.Redis):
    def execute_command(self, *args, **options):
        """Override for execute_command to wait and try one extra time if there was a Connection Error"""
        try:
            return super().execute_command(*args, **options)
        except redis.ConnectionError:
            for i in range(int(REDIS_CONNECTION_RETRY_WAIT_SECS * 100)):
                time.sleep(0.01)
            return super().execute_command(*args, **options)

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

class MissingDataException(Exception):
    def __init__(self, event_data: Dict[str, Any], required_keys: Collection[str]) -> None:
        self.event_data = event_data
        self.required_keys = required_keys
        self.missing_keys = [key for key in self.required_keys if not self.event_data.get(key)]
        self.message = f"Event data is missing required fields {self.missing_keys}:\n\t {self.event_data}"
        super().__init__(self.message)

def check_keys(event_data: Dict[str, Any], required_keys: Collection[str]) -> None:
    required_keys = list(required_keys)
    if any(not event_data.get(key) for key in required_keys):
        raise MissingDataException(event_data, required_keys)

class EventHandler:
    """Handles plaid-sourced events from a message queue."""

    def __init__(self) -> None:
        """Loads redis connection info from plaidcloud.config"""
        self.rinfo = cfg.redis.get_url(ANALYZE_CONNECTION_NAME)

    def _connect(self):
        """Returns a redis connection"""
        if self.rinfo.sentinel:  # We're connecting to a sentinel cluster.
            sentinel_connection = Sentinel(
                self.rinfo.hosts, socket_timeout=self.rinfo.socket_timeout,
                db=self.rinfo.database, password=self.rinfo.password,
                health_check_interval=30, retry_on_timeout=True,
                client_name=CLIENT_NAME,
            )
            # needs to be writeable because it is popping from a list
            return sentinel_connection.master_for(
                self.rinfo.service_name, socket_timeout=self.rinfo.socket_timeout,
                redis_class=RedisWithRetry, decode_responses=True,
                client_name=CLIENT_NAME,
            )
        else:  # Single redis instance
            host, port = self.rinfo.hosts[0]
            return RedisWithRetry(
                host=host,
                port=port,
                db=self.rinfo.database,
                password=self.rinfo.password,
                decode_responses=True,
                socket_timeout=self.rinfo.socket_timeout,
                health_check_interval=30,
                retry_on_timeout=True,
                client_name=CLIENT_NAME,
            )

    def consume(self) -> None:
        """Loop, waiting for and processing events on the redis queue"""
        self._connect()
        while True:
            try:
                connection = self._connect()
                with connection:
                    key, message = connection.blpop(f'{SUPERSET_QUEUE_KEY}:{cfg.environment.designation}')
                    data = json.loads(message)
            except redis.TimeoutError:
                continue
            except:
                log.exception(f'Error popping event from queue')
                continue

            try:
                with db.session.begin():
                    table_ids = self.process_event(data)

                if table_ids:
                    for table_id in table_ids:
                        with db.session.begin():
                            clear_table_cache(table_id)
            except:
                log.exception(f'Error processing event with data: {data}')
                continue

    def process_event(self, info: Dict[str, Any]) -> Optional[List[str]]:
        try:
            event_type = EventType(info['event'])
            object_type = PlaidObjectType(info['type'])

            data = info['data']

            kwargs = {k: v for k, v in info.items() if k not in REQUIRED_FIELDS}

            event_handlers = {
                # PlaidObjectType.Workspace: self._handle_workspace_event,
                PlaidObjectType.Project: self._handle_project_event,
                PlaidObjectType.Table: self._handle_table_event,
                # PlaidObjectType.View: self._handle_view_event,
                # PlaidObjectType.User: self._handle_user_event,
            }

            handle_event = event_handlers.get(object_type, self._handle_passthrough)
            return handle_event(event_type, data, **kwargs)

        except ValueError:
            # Skip this event as it is not recognized.
            return self._handle_passthrough(event_type, {})

    def _handle_project_event(self, event_type: EventType, data: Dict[str, Any], **kwargs: Any) -> None:
        def map_data_to_db_row(event_data: Dict[str, Any], existing_project: Optional[Database] = None) -> Database:
            if isinstance(existing_project, Database):
                proj = existing_project
            else:
                proj = Database()

            check_keys(event_data, ['name', 'id', 'report_database_password', 'report_database_user'])

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
            display_name = f"{event_data['name']} ({event_data['id']})"

            if not db.session.query(db.session.query(Database).filter_by(uuid=event_data['id']).exists()).scalar():
                # Project doesn't exist, so make a new one.
                log.info(f"Inserting project {display_name}.")

                try:
                    new_project = map_data_to_db_row(event_data)
                except MissingDataException:
                    log.exception("Insert Project called with incomplete event data")
                    raise

                db.session.add(new_project)
            else:
                log.warning(f"Insert project called but project {display_name} already exists! Updating instead.")
                update_project(event_data)

        def update_project(event_data: Dict[str, Any]) -> None:
            display_name = f"{event_data['name']} ({event_data['id']})"
            log.info(f"Updating project {display_name}.")
            try:
                existing_project = db.session.query(Database).filter_by(uuid=event_data['id']).one()
            except NoResultFound:
                log.warning(f"Update project called but project {display_name} doesn't exist! Inserting instead.")
                insert_project(event_data)
            else:
                map_data_to_db_row(event_data, existing_project)

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

        if event_type is EventType.Create:
            insert_project(data)
        elif event_type is EventType.Update:
            update_project(data)
        elif event_type is EventType.Delete:
            delete_project(data)

    def _handle_table_event(self, event_type: EventType, data: Dict[str, Any], **kwargs: Any) -> Optional[List[str]]:

        def event_params(event_data: Dict[str, Any]) -> Tuple[int, str, str]:
            check_keys(event_data, ['published_name', 'id'])

            database_id = db.session.query(Database).filter_by(uuid=kwargs['project_id']).one().id
            table_name = event_data['published_name']
            schema = f"report{kwargs['project_id']}"

            return database_id, table_name, schema

        def existing_table_records(event_data: Dict[str, Any]) -> List[SqlaTable]:
            database_id, table_name, schema = event_params(event_data)

            return db.session.query(SqlaTable).filter(
                SqlaTable.database_id==database_id,
                SqlaTable.schema==schema,
                SqlaTable.table_name==table_name,
            ).all()

        def map_data_to_table_row(event_data: Dict[str, Any], existing_table: Optional[SqlaTable] = None) -> SqlaTable:
            if isinstance(existing_table, SqlaTable):
                table = existing_table
            else:
                table = SqlaTable()

            #TODO: should we just fill in database here too?
            _, table.table_name, table.schema = event_params(event_data)

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

                log.info(
                    "Invalidated %s cache records for datasource %s",
                    len(cache_keys),
                    datasource_uid,
                )
            except SQLAlchemyError as ex:  # pragma: no cover
                log.error(ex, exc_info=True)
                raise

        def insert_table(event_data: Dict[str, Any]) -> List[str]:
            if not kwargs.get('project_id'):
                log.warning(f"Insert Table called without project_id")
                return []

            try:
                check_keys(event_data, ['id', 'published_name'])
            except MissingDataException as e:
                if 'id' in event_data:
                    info = f"(Project {kwargs['project_id']} Table {event_data['id']})"
                else:
                    info = f"(Project {kwargs['project_id']})"

                if e.missing_keys == ['published_name']:
                    log.info(f"Insert Table called on unpublished table - {info}")
                    return []

                log.exception(f"Insert Table called with incomplete event data {info}")
                return []

            display_name = f"{event_data['published_name']} ({event_data['id']})"
            log.info(f"Inserting table {display_name} for project {kwargs['project_id']}.")

            # Test if source table/view actually exists before we add it.
            try:
                if not existing_table_records(event_data):
                    try:
                        new_table = map_data_to_table_row(event_data)
                    except MissingDataException:
                        log.exception(f"Insert Table called with incomplete event data (Project {kwargs['project_id']} Table {display_name})")
                        raise

                    project = db.session.query(Database).filter_by(uuid=kwargs['project_id']).one_or_none()
                    if not project:
                        log.error(f"The database for Project {kwargs['project_id']} does not exist. Create one by updating the Project record in PlaidCloud.")
                        return []

                    # TODO: This is pretty dumb. Event is being processed before the DB can create the view.
                    time.sleep(2)

                    project.get_table(table_name=new_table.table_name, schema=new_table.schema)
                    new_table.database = project
                    # If we've made it this far, the source table/view exists.
                    db.session.add(new_table)
                else:
                    log.warning(f"Received a create event for table {display_name}, but the table has already been published.")
                    return update_table(event_data)

            except (NoResultFound, NoSuchTableError):
                log.exception(f"Table {new_table.schema}.{new_table.table_name} doesn't exist. Skipping.")
                return []
            except:
                log.exception(f"Error occurred while inserting new table {display_name}.")
                raise

            try:
                # Populate columns and metrics for table.
                new_table.fetch_metadata()

                # clear_table_cache(new_table.uid)
                return [new_table.uid]
            except:
                log.exception(f"Error occurred while populating columns and metrics after inserting new table {display_name}")
                raise

        def update_table(event_data: Dict[str, Any]) -> List[str]:
            cache_tables = []
            if not kwargs.get('project_id'):
                log.warning(f"Update Table called without project_id")
                return cache_tables

            try:
                check_keys(event_data, ['id', 'published_name'])
            except MissingDataException as e:
                if 'id' in event_data:
                    info = f"(Project {kwargs['project_id']} Table {event_data['id']})"
                else:
                    info = f"(Project {kwargs['project_id']})"

                if e.missing_keys == ['published_name']:
                    log.info(f"Update Table called on unpublished table - {info}")
                    return cache_tables

                log.exception(f"Update Table called with incomplete event data {info}")
                return cache_tables

            display_name = f"{event_data['published_name']} ({event_data['id']})"
            log.info(f"Updating table {display_name} for project {kwargs['project_id']}.")

            if not event_data.get("published_name"):
                # !! We don't do this any more because sometimes there are multiple tables with the same published name !!
                # !! Things may seriously break if this code is uncommented. !!

                # # Table still exists, but the user unpublished it. So we want to delete.
                # log.info(f"Table {event_data['published_name']} ({event_data['id']}) has no published name, and will be deleted.")
                # delete_table(event_data)
                return cache_tables

            existing_tables = existing_table_records(event_data)
            if existing_tables:
                table_to_update, *tables_to_delete = existing_tables

                try:
                    map_data_to_table_row(event_data, table_to_update)
                except MissingDataException:
                    log.exception(f"Update Table called with incomplete event data (Project {kwargs['project_id']} Table {display_name})")
                    return cache_tables

                for old_table in tables_to_delete:
                    log.warning(f"Deleting extra table record: {old_table.table_name}, UUID: {old_table.uuid}, Superset ID: {old_table.id}, Superset UID: {old_table.uid}")
                    #TODO: log warning that we're deleting records
                    #This shouldn't actually happen. There shouldn't be tables to delete, witht he current existing_table_records query.
                    try:

                        db.session.delete(old_table)
                        cache_tables.append(old_table.uid)
                        # clear_table_cache(table_to_update.uid)

                    except:
                        log.exception(f"Error occurred while deleting an extra table record: {old_table.table_name}, UUID: {old_table.uuid}, Superset ID: {old_table.id}, Superset UID: {old_table.uid}")
                        raise
            else:
                log.warning(f"Received an update event but table {display_name} doesn't exist.")
                return insert_table(event_data)

            try:
                # clear_table_cache(table_to_update.uid)
                cache_tables.append(table_to_update.uid)

                # TODO: This is pretty dumb. Event is being processed before the DB can create the view.
                time.sleep(5)

                table_to_update.fetch_metadata()

            except:
                log.exception(f"Error occurred while updating table {display_name}.")
                raise

            return cache_tables

        def delete_table(event_data: Dict[str, Any]) -> List[str]:
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

                # clear_table_cache(table.uid)
                return [table.uid]
            except NoResultFound:
                log.warning("Received a delete event for a table that doesn't exist.")
            except:
                log.exception("Error occurred while deleting a table.")
                raise

        if event_type is EventType.Create:
            return insert_table(data)
        elif event_type is EventType.Update:
            return update_table(data)
        elif event_type is EventType.Delete:
            # return delete_table(data)
            log.warning(f"Received a delete event for table {data['published_name']}, but deleting tables through events is no longer permitted.")

    def _handle_passthrough(self, event_type: Optional[EventType], data: Optional[Dict[str, Any]], **kwargs: Any) -> None:
        # TODO: Should we debug log unhandled events?
        pass


if __name__ == "__main__":
    handler = EventHandler()
    handler.consume()
