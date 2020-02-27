# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# pylint: disable=C,R,W
import json
import logging
import time
from datetime import datetime

from superset.connectors.connector_registry import ConnectorRegistry
from superset.models.dashboard import Dashboard
from superset.models.slice import Slice

logger = logging.getLogger(__name__)


def load_types():
    types = {
        "__Dashboard__": Dashboard,
        "__Slice__": Slice,
        # "datetime": lambda dt: datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S"),
    }
    for source_type, source_class in ConnectorRegistry.sources.items():
        types[f"__{source_class.__name__}__"] = source_class
        types[f"__{source_class.metric_class.__name__}__"] = source_class.metric_class
        types[f"__{source_class.column_class.__name__}__"] = source_class.column_class
    return types


def decode_dashboards(o):
    """
    Function to be passed into json.loads obj_hook parameter
    Recreates the dashboard object from a json representation.
    """
    import superset.models.core as models
    decode_types = load_types()

    if "__datetime__" in o:
        return datetime.strptime(o["__datetime__"], "%Y-%m-%dT%H:%M:%S")
    elif any(key in decode_types for key in o):
        key = next(iter(o.keys()))
        return decode_types[key](**o[key])
    else:
        return o


def import_dashboards(session, data_stream, import_time=None):
    """Imports dashboards from a stream to databases"""
    current_tt = int(time.time())
    import_time = current_tt if import_time is None else import_time
    data = json.loads(data_stream.read(), object_hook=decode_dashboards)
    # TODO: import DRUID datasources
    for table in data["datasources"]:
        type(table).import_obj(table, import_time=import_time)
    session.commit()
    for dashboard in data["dashboards"]:
        Dashboard.import_obj(dashboard, import_time=import_time)
    session.commit()


def export_dashboards(session):
    """Returns all dashboards metadata as a json dump"""
    logger.info("Starting export")
    dashboards = session.query(Dashboard)
    dashboard_ids = []
    for dashboard in dashboards:
        dashboard_ids.append(dashboard.id)
    data = Dashboard.export_dashboards(dashboard_ids)
    return data
