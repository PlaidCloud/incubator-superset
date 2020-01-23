import logging
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from superset import appbuilder, conf, db, security_manager
from superset.connectors.plaid.models import metadata, PlaidTable, PlaidProject, PlaidMetric
from superset.connectors.sqla.models import SqlaTable, SqlMetric
from superset.models.slice import Slice

log = logging.getLogger(__name__)
log.setLevel('INFO')



def initialize_schema_and_perms():
    # Run this function _before_ processing events.
    metadata.create_all(bind=db.engine)
    appbuilder.add_permissions(update_perms=True)
    security_manager.create_custom_permissions()
    security_manager.set_role("Admin", security_manager._is_admin_pvm)
    security_manager.set_role("Alpha", security_manager._is_alpha_pvm)
    security_manager.set_role("Gamma", security_manager._is_gamma_pvm)
    security_manager.set_role("granter", security_manager._is_granter_pvm)
    security_manager.set_role("sql_lab", security_manager._is_sql_lab_pvm)
    if conf.get("PUBLIC_ROLE_LIKE_GAMMA", False):
        security_manager.set_role("Public", security_manager._is_gamma_pvm)
    security_manager.set_role('Plaid', security_manager.is_plaid_user_pvm)
    if security_manager.appbuilder.app.config.get('PUBLIC_ROLE_LIKE_PLAID', False):
        security_manager.set_role('Public', security_manager.is_plaid_user_pvm)


def add_changeme_datasource():
    proj = db.session.query(PlaidProject).filter_by(uuid="placeholder_project").first()
    if not proj:
        proj = PlaidProject()

        proj.name = "placeholder_project"
        proj.uuid = "placeholder_project"
        proj.workspace_id = "placeholder_workspace"
        proj.workspace_name = "placeholder_workspace"
        proj.password = "placeholder_project"

        driver = "postgresql"
        host = "google.com"
        user = "bogus"
        port = "5432"
        db_name = "bogus"

        # Construct URI and use sqla mapping method to set it.
        uri = f"{driver}://{user}:{proj.password}@{host}:{port}/{db_name}"
        proj.set_sqlalchemy_uri(uri)

        db.session.add(proj)
        db.session.commit()

    table = PlaidTable()

    table.table_name = "change_me"
    table.base_table_name = "change_me"
    table.project_id = "placeholder_project"
    table.project = proj
    table.schema = "placeholder"

    db.session.add(table)
    db.session.commit()


def update_charts_to_new_datasource():
    charts = db.session.query(Slice).filter_by(datasource_type='table').all()
    placeholder_table = db.session.query(PlaidTable).filter(
        PlaidTable.project_id == 'placeholder_project',
        PlaidTable.schema == 'placeholder',
        PlaidTable.table_name == 'change_me',
    ).one()
    for chart in charts:
        log.info(f'Updating {chart.slice_name}...')
        chart.datasource_type = 'plaid'
        try:
            old_table = db.session.query(SqlaTable).get(chart.datasource_id)
            new_table = db.session.query(PlaidTable).filter(
                PlaidTable.table_name == old_table.table_name,
                PlaidTable.schema == old_table.schema,
            ).one()

            chart.datasource_id = new_table.id
            db.session.commit()

        except NoResultFound:
            log.info(f'No result found for {old_table.schema}.{old_table.table_name}')
            chart.datasource_id = placeholder_table.id
            db.session.commit()
        except Exception:
            log.exception('idk what happened.')
            db.session.rollback()


def migrate_metrics():
    old_tables = db.session.query(SqlaTable).all()

    for old_table in old_tables:
        try:
            new_table = db.session.query(PlaidTable).filter(
                PlaidTable.table_name == old_table.table_name,
                PlaidTable.schema == old_table.schema,
            ).one()
            log.info(f"Found matching table for {old_table}. Porting metrics now.")
            try:
                for old_metric in old_table.metrics:

                    if db.session.query(
                        db.session.query(PlaidMetric).filter(
                            PlaidMetric.metric_name == old_metric.metric_name,
                            PlaidMetric.table_id == new_table.id
                        ).exists()
                    ).scalar():
                        continue
                    new_metric = PlaidMetric()
                    new_metric.metric_name = old_metric.metric_name
                    new_metric.verbose_name = old_metric.verbose_name
                    new_metric.metric_type = old_metric.metric_type
                    new_metric.table_id = new_table.id
                    new_metric.expression = old_metric.expression
                    new_metric.description = old_metric.description
                    new_metric.warning_text = old_metric.warning_text
                    db.session.add(new_metric)
                    db.session.commit()
                    log.info(f"Copying {old_metric.metric_name}...")
            except Exception:
                log.warning(f"Something happend. Idk what")
                db.session.rollback()
        except NoResultFound:
            log.warning(f"Table {old_table} does not exist. Continuing.")


if __name__ == '__main__':
    update_charts_to_new_datasource()