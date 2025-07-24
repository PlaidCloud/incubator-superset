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
"""resize_dashboard_components_to_24_columns

Revision ID: 86beb9dd14eb
Revises: 32bf93dfe2a4
Create Date: 2025-07-22 14:15:22.828851

"""

from superset import db

# revision identifiers, used by Alembic.
revision = '86beb9dd14eb'  # This will be auto-generated
down_revision = '32bf93dfe2a4'

import json
import logging
from alembic import op
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

def upgrade():
    """
    Double width and height values for dashboard components to support 24-column grid
    """
    bind = op.get_bind()
    session = db.Session(bind=bind)
    print(bind.engine.url)


    try:
        # Import the Dashboard model
        from superset.models.dashboard import Dashboard

        # Get all dashboards with position_json
        dashboards = session.query(Dashboard).filter(Dashboard.position_json.isnot(None)).all()

        if len(dashboards) == 0:
            print("No dashboards found with position_json")
            return

        updated_count = 0
        total_dashboards = len(dashboards)

        print(f"Found {total_dashboards} dashboards to process")

        for dashboard in dashboards:
            print(f"Processing dashboard {dashboard.id}: {dashboard.dashboard_title}")

            try:
                pos = json.loads(dashboard.position_json)
            except Exception as e:
                print(f"Failed to parse dashboard {dashboard.id}: {e}")
                continue

            changed = False

            for key, val in pos.items():
                if key.startswith(("CHART", "COLUMN", "MARKDOWN")) and isinstance(val, dict) and val.get("meta"):
                    print(f"----------------{key}")
                    print(val)

                    meta = val.get("meta", {})
                    old_width = meta.get("width")
                    old_height = meta.get("height")

                    print(f"Found component {key} in dashboard {dashboard.id} with width {old_width} and height {old_height}")

                    if old_width is not None:
                        val["meta"]["width"] = old_width * 2
                        print(f"Updating width from {old_width} to {old_width * 2}")

                    if old_height is not None:
                        val["meta"]["height"] = old_height * 2
                        print(f"Updating height from {old_height} to {old_height * 2}")

                    changed = True

                print(" ")

            if changed:
                # Update the dashboard object
                from sqlalchemy.orm.attributes import flag_modified
                print("BEFORE JSON:")
                print(dashboard.position_json)
                original = dashboard.position_json
                dashboard.position_json = json.dumps(pos)
                if dashboard.position_json != original:
                    print("AFTER JSON:")
                    print(dashboard.position_json)
                    print(f"Committed changes for dashboard {dashboard.id}")
                else:
                    print(f"No change in JSON for dashboard {dashboard.id}")
                flag_modified(dashboard, "position_json")
                updated_count += 1
                print(f"Updated dashboard {dashboard.id}: {dashboard.dashboard_title}")
            else:
                print(f"No changes needed for dashboard {dashboard.id}: {dashboard.dashboard_title}")
        session.commit()
        print(f"Migration completed. Updated {updated_count} out of {total_dashboards} dashboards")

        # Fetch and print updated position_json for verification
        verification_dashboards = session.query(Dashboard).filter(Dashboard.position_json.isnot(None)).all()
        print("\n=== VERIFICATION: Updated Dashboard Position JSON ===")
        for dashboard in verification_dashboards:
            print(f"\nDashboard {dashboard.id}: {dashboard.dashboard_title}")
            print(f"Position JSON: {dashboard.position_json}")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to execute migration: {e}")
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Unexpected error during migration: {e}")
        raise
    finally:
        session.close()

def downgrade():
    """
    Halve width and height values to revert back to 12-column grid
    """
    bind = op.get_bind()
    session = db.Session(bind=bind)

    try:
        # Import the Dashboard model
        from superset.models.dashboard import Dashboard

        # Get all dashboards with position_json
        dashboards = session.query(Dashboard).filter(Dashboard.position_json.isnot(None)).all()

        if len(dashboards) == 0:
            print("No dashboards found with position_json")
            return

        reverted_count = 0
        total_dashboards = len(dashboards)

        print(f"Found {total_dashboards} dashboards to revert")

        for dashboard in dashboards:
            print(f"Reverting dashboard {dashboard.id}: {dashboard.dashboard_title}")

            try:
                pos = json.loads(dashboard.position_json)
            except Exception as e:
                print(f"Failed to parse dashboard {dashboard.id}: {e}")
                continue

            changed = False

            for key, val in pos.items():
                if key.startswith(("CHART", "COLUMN", "MARKDOWN")) and isinstance(val, dict) and val.get("meta"):
                    meta = val.get("meta", {})
                    old_width = meta.get("width")
                    old_height = meta.get("height")

                    if old_width is not None:
                        val["meta"]["width"] = max(1, old_width // 2)

                    if old_height is not None:
                        val["meta"]["height"] = max(1, old_height // 2)

                    changed = True

            if changed:
                # Update the dashboard object
                dashboard.position_json = json.dumps(pos)
                reverted_count += 1
                print(f"Reverted dashboard {dashboard.id}: {dashboard.dashboard_title}")

        session.commit()
        print(f"Downgrade completed. Reverted {reverted_count} out of {total_dashboards} dashboards")

    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Failed to revert migration: {e}")
        raise
    finally:
        session.close()
