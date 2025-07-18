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
        total_dashboards = 0
        
        for row in result:
            total_dashboards += 1
            dashboard_id = row[0]
            position_json_str = row[1]
            
            logger.info(f"Processing dashboard {dashboard_id}")
            logger.debug(f"Original position_json: {position_json_str[:200]}...")
            
            try:
                position_data = json.loads(position_json_str)
                logger.debug(f"Parsed position_data keys: {list(position_data.keys())}")
                
                updated_data = double_grid_dimensions(position_data)
                logger.debug(f"Updated position_data: {json.dumps(updated_data)[:200]}...")
                
                connection.execute(
                    text("UPDATE dashboards SET position_json = :position_json WHERE id = :id"),
                    {
                        "position_json": json.dumps(updated_data),
                        "id": dashboard_id
                    }
                )
                updated_count += 1
                logger.info(f"Successfully updated dashboard {dashboard_id}")
                
            except Exception as e:
                logger.error(f"Failed to update dashboard {dashboard_id}: {e}")
                logger.error(f"Position JSON was: {position_json_str}")
        
        logger.info(f"Migration completed. Total: {total_dashboards}, Updated: {updated_count} dashboards")
        
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
    logger.debug(f"double_grid_dimensions called with: {type(position_data)}")
    
    if not isinstance(position_data, dict):
        logger.warning(f"position_data is not dict, it's {type(position_data)}")
        return position_data
    
    updated_data = {}
    
    for component_id, component in position_data.items():
        logger.debug(f"Processing component {component_id}: {type(component)}")
        
        if isinstance(component, dict):
            updated_component = component.copy()
            
            if 'meta' in component:
                meta = component['meta'].copy()
                logger.debug(f"Original meta for {component_id}: {meta}")
                
                # Double width
                if 'width' in meta:
                    old_width = meta['width']
                    meta['width'] = meta['width'] * 2
                    logger.debug(f"Width changed from {old_width} to {meta['width']}")
                
                # Double height  
                if 'height' in meta:
                    old_height = meta['height']
                    meta['height'] = meta['height'] * 2
                    logger.debug(f"Height changed from {old_height} to {meta['height']}")
                
                updated_component['meta'] = meta
                logger.debug(f"Updated meta for {component_id}: {meta}")
            else:
                logger.debug(f"Component {component_id} has no meta field")
            
            updated_data[component_id] = updated_component
        else:
            logger.debug(f"Component {component_id} is not dict, keeping as-is")
            updated_data[component_id] = component
    
    logger.debug(f"Returning updated_data with keys: {list(updated_data.keys())}")
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