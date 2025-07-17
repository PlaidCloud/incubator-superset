"""Double grid dimensions for 24-column layout

Revision ID: 15e0cba58c7c
Revises: 32bf93dfe2a4
Create Date: 2025-07-17 12:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '15e0cba58c7c'
down_revision = '32bf93dfe2a4'  # Replace with actual previous revision

import json
import logging
from alembic import op
from sqlalchemy import text

logger = logging.getLogger(__name__)

def upgrade():
    """
    Double width and height values in dashboard position_json
    """
    connection = op.get_bind()
    
    # Create backup table
    connection.execute(text("""
        CREATE TABLE dashboards_grid_backup AS 
        SELECT id, dashboard_title, position_json, created_on, changed_on
        FROM dashboards 
        WHERE position_json IS NOT NULL
    """))
    logger.info("Created backup table: dashboards_grid_backup")
    
    # Get all dashboards with position_json
    result = connection.execute(
        text("SELECT id, position_json FROM dashboards WHERE position_json IS NOT NULL")
    )
    
    updated_count = 0
    
    for row in result:
        dashboard_id = row[0]
        position_json_str = row[1]
        
        try:
            position_data = json.loads(position_json_str)
            updated_data = double_grid_dimensions(position_data)
            
            connection.execute(
                text("UPDATE dashboards SET position_json = :position_json WHERE id = :id"),
                {
                    "position_json": json.dumps(updated_data),
                    "id": dashboard_id
                }
            )
            updated_count += 1
            
        except Exception as e:
            logger.error(f"Failed to update dashboard {dashboard_id}: {e}")
    
    logger.info(f"Updated {updated_count} dashboards")

def downgrade():
    """
    Restore from backup table
    """
    connection = op.get_bind()
    
    # Restore from backup
    connection.execute(text("""
        UPDATE dashboards 
        SET position_json = backup.position_json
        FROM dashboards_grid_backup backup
        WHERE dashboards.id = backup.id
    """))
    
    logger.info("Restored dashboards from backup")

def double_grid_dimensions(position_data):
    """
    Double width and height values in position_json
    """
    if not isinstance(position_data, dict):
        return position_data
    
    updated_data = {}
    
    for component_id, component in position_data.items():
        if isinstance(component, dict):
            updated_component = component.copy()
            
            if component.get('type') == 'CHART' and 'meta' in component:
                meta = component['meta'].copy()
                
                # Double width
                if 'width' in meta:
                    meta['width'] = meta['width'] * 2
                
                # Double height  
                if 'height' in meta:
                    meta['height'] = meta['height'] * 2
                
                # Double x position
                if 'x' in meta:
                    meta['x'] = meta['x'] * 2
                
                # Double y position
                if 'y' in meta:
                    meta['y'] = meta['y'] * 2
                
                updated_component['meta'] = meta
            
            updated_data[component_id] = updated_component
        else:
            updated_data[component_id] = component
    
    return updated_data