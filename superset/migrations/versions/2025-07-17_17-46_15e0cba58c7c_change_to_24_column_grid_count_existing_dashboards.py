"""Double grid dimensions for 24-column layout

Revision ID: 15e0cba58c7c
Revises: 32bf93dfe2a4
Create Date: 2025-07-17 12:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '15e0cba58c7c'
down_revision = '32bf93dfe2a4'

import json
import logging
from alembic import op
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

def upgrade():
    """
    Double width and height values in dashboard position_json
    """
    connection = op.get_bind()
    
    try:
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
        
        logger.info(f"Migration completed. Updated: {updated_count} dashboards")
        
    except SQLAlchemyError as e:
        logger.error(f"Failed to execute migration: {e}")
        raise

def downgrade():
    """
    Halve width and height values in dashboard position_json
    """
    connection = op.get_bind()
    
    try:
        result = connection.execute(
            text("SELECT id, position_json FROM dashboards WHERE position_json IS NOT NULL")
        )
        
        reverted_count = 0
        
        for row in result:
            dashboard_id = row[0]
            position_json_str = row[1]
            
            try:
                position_data = json.loads(position_json_str)
                reverted_data = halve_grid_dimensions(position_data)
                
                connection.execute(
                    text("UPDATE dashboards SET position_json = :position_json WHERE id = :id"),
                    {
                        "position_json": json.dumps(reverted_data),
                        "id": dashboard_id
                    }
                )
                reverted_count += 1
                
            except Exception as e:
                logger.error(f"Failed to revert dashboard {dashboard_id}: {e}")
        
        logger.info(f"Downgrade completed. Reverted: {reverted_count} dashboards")
        
    except SQLAlchemyError as e:
        logger.error(f"Failed to revert migration: {e}")
        raise

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
            
            if 'meta' in component:
                meta = component['meta'].copy()
                
                # Double width
                if 'width' in meta:
                    meta['width'] = meta['width'] * 2
                
                # Double height  
                if 'height' in meta:
                    meta['height'] = meta['height'] * 2
                
                updated_component['meta'] = meta
            
            updated_data[component_id] = updated_component
        else:
            updated_data[component_id] = component
    
    return updated_data

def halve_grid_dimensions(position_data):
    """
    Halve width and height values in position_json
    """
    if not isinstance(position_data, dict):
        return position_data
    
    updated_data = {}
    
    for component_id, component in position_data.items():
        if isinstance(component, dict):
            updated_component = component.copy()
            
            if 'meta' in component:
                meta = component['meta'].copy()
                
                # Halve width (minimum 1)
                if 'width' in meta:
                    meta['width'] = max(1, meta['width'] // 2)
                
                # Halve height (minimum 1)
                if 'height' in meta:
                    meta['height'] = max(1, meta['height'] // 2)
                
                updated_component['meta'] = meta
            
            updated_data[component_id] = updated_component
        else:
            updated_data[component_id] = component
    
    return updated_data