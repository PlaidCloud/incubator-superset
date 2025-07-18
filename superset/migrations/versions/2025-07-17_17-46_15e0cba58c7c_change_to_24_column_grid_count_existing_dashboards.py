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
    
    # Handle existing backup table
    try:
        # Check if backup table already exists
        backup_exists = connection.execute(text("""
            SELECT COUNT(*) 
            FROM information_schema.tables 
            WHERE table_name = 'dashboards_grid_backup'
        """)).scalar()
        
        if backup_exists > 0:
            logger.info("Backup table already exists, checking if migration already applied")
            
            # Check if migration was already applied by looking for doubled values
            sample_result = connection.execute(text("""
                SELECT position_json 
                FROM dashboards 
                WHERE position_json IS NOT NULL 
                AND position_json LIKE '%"width"%' 
                LIMIT 1
            """)).fetchone()
            
            if sample_result:
                sample_data = json.loads(sample_result[0])
                if is_migration_already_applied(sample_data):
                    logger.info("Migration appears to already be applied, skipping")
                    return
            
            # Backup exists but migration not applied, drop and recreate
            logger.info("Dropping existing backup table and creating new one")
            connection.execute(text("DROP TABLE dashboards_grid_backup"))
        
        # Create backup table
        connection.execute(text("""
            CREATE TABLE dashboards_grid_backup AS 
            SELECT id, dashboard_title, position_json, created_on, changed_on
            FROM dashboards 
            WHERE position_json IS NOT NULL
        """))
        logger.info("Created backup table: dashboards_grid_backup")
        
    except SQLAlchemyError as e:
        logger.error(f"Failed to handle backup table: {e}")
        raise
    
    # Get all dashboards with position_json
    try:
        result = connection.execute(
            text("SELECT id, position_json FROM dashboards WHERE position_json IS NOT NULL")
        )
        
        updated_count = 0
        error_count = 0
        
        for row in result:
            dashboard_id = row[0]
            position_json_str = row[1]
            
            try:
                position_data = json.loads(position_json_str)
                
                # Skip if already migrated
                if is_migration_already_applied(position_data):
                    logger.debug(f"Dashboard {dashboard_id} already migrated, skipping")
                    continue
                
                updated_data = double_grid_dimensions(position_data)
                
                connection.execute(
                    text("UPDATE dashboards SET position_json = :position_json WHERE id = :id"),
                    {
                        "position_json": json.dumps(updated_data),
                        "id": dashboard_id
                    }
                )
                updated_count += 1
                
                if updated_count % 10 == 0:
                    logger.info(f"Updated {updated_count} dashboards so far...")
                
            except Exception as e:
                error_count += 1
                logger.error(f"Failed to update dashboard {dashboard_id}: {e}")
        
        logger.info(f"Migration completed. Updated: {updated_count}, Errors: {error_count}")
        
    except SQLAlchemyError as e:
        logger.error(f"Failed to execute migration: {e}")
        raise

def downgrade():
    """
    Restore from backup table
    """
    connection = op.get_bind()
    
    try:
        # Check if backup table exists
        backup_exists = connection.execute(text("""
            SELECT COUNT(*) 
            FROM information_schema.tables 
            WHERE table_name = 'dashboards_grid_backup'
        """)).scalar()
        
        if backup_exists == 0:
            logger.warning("Backup table 'dashboards_grid_backup' not found. Cannot restore from backup.")
            logger.info("Attempting mathematical revert instead...")
            
            # Mathematical revert - halve the dimensions
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
            
            logger.info(f"Mathematical revert completed for {reverted_count} dashboards")
            return
        
        # Restore from backup
        connection.execute(text("""
            UPDATE dashboards 
            SET position_json = backup.position_json,
                changed_on = NOW()
            FROM dashboards_grid_backup backup
            WHERE dashboards.id = backup.id
        """))
        
        logger.info("Successfully restored dashboards from backup")
        
        connection.execute(text("DROP TABLE dashboards_grid_backup"))
        
    except SQLAlchemyError as e:
        logger.error(f"Failed to restore from backup: {e}")
        raise

def is_migration_already_applied(position_data):
    """
    Check if the migration has already been applied by looking for typical 24-column grid values
    """
    if not isinstance(position_data, dict):
        return False
    
    for component_id, component in position_data.items():
        if isinstance(component, dict) and component.get('type') == 'CHART':
            meta = component.get('meta', {})
            width = meta.get('width', 0)
            
            # If we find widths that are typical of 24-column grid (>12), assume already migrated
            if width > 12:
                return True
            
            # Also check for common doubled values from 12-column grid
            if width in [24, 22, 20, 18, 16, 14]:  # Common doubled values
                return True
    
    return False

def double_grid_dimensions(position_data):
    """
    Double width and height values in position_json for all component types
    """
    if not isinstance(position_data, dict):
        return position_data
    
    updated_data = {}
    
    for component_id, component in position_data.items():
        if isinstance(component, dict):
            updated_component = component.copy()
            
            # Handle all component types that have meta with positioning
            component_type = component.get('type')
            if component_type in ['CHART', 'TAB', 'ROW', 'COLUMN', 'HEADER', 'MARKDOWN', 'DIVIDER'] and 'meta' in component:
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

def halve_grid_dimensions(position_data):
    """
    Halve width and height values in position_json (for mathematical revert)
    """
    if not isinstance(position_data, dict):
        return position_data
    
    updated_data = {}
    
    for component_id, component in position_data.items():
        if isinstance(component, dict):
            updated_component = component.copy()
            
            component_type = component.get('type')
            if component_type in ['CHART', 'TAB', 'ROW', 'COLUMN', 'HEADER', 'MARKDOWN', 'DIVIDER'] and 'meta' in component:
                meta = component['meta'].copy()
                
                # Halve width (minimum 1)
                if 'width' in meta:
                    meta['width'] = max(1, meta['width'] // 2)
                
                # Halve height (minimum 4)
                if 'height' in meta:
                    meta['height'] = max(4, meta['height'] // 2)
                
                # Halve x position
                if 'x' in meta:
                    meta['x'] = meta['x'] // 2
                
                # Halve y position
                if 'y' in meta:
                    meta['y'] = meta['y'] // 2
                
                updated_component['meta'] = meta
            
            updated_data[component_id] = updated_component
        else:
            updated_data[component_id] = component
    
    return updated_data