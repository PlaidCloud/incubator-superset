from flask import request, redirect, Response
from flask_appbuilder.baseviews import expose, expose_api
from flask_appbuilder.security.decorators import has_access_api
from flask_babel import gettext as __
from superset import appbuilder
from superset.views.core import BaseSupersetView
import datasource_helpers as dh
import simplejson as json

class Plaid(BaseSupersetView):
    """FAB view exposing some endpoints for Plaidcloud datasource management.
    """
    def json_response(self, obj, status=200):
        return Response(
            json.dumps(obj),
            status=status,
            mimetype='application/json')

    @expose_api(name='plaid_refresh', url='/api/refresh', methods=['GET'])
    @expose_api(name='plaid_refresh', url='/api/refresh/<project_id>', methods=['GET'])
    @has_access_api
    def refresh_async(self, project_id=None):
        """Endpoint to refresh user's datasource(s) without redirect.

        All projects' datasources will be synchronized if ID is unspecified.

        Args:
            project_id (str, optional): The UID of the project to synchronize.

        Returns:
            bool: True.
        """
        project_ids = []
        if project_id:
            project_ids.append(project_id)
        appbuilder.sm.sync_datasources(project_ids=project_ids)
        return self.json_response(True)

    @expose('/refresh')
    @expose('/refresh/<project_id>')
    @has_access_api
    def refresh(self, project_id=None):
        """Endpoint to refresh user's datasource(s) with redirect.

        All projects' datasources will be synchronized if ID is unspecified.
        This function will redirect the user to the tables list once finished.

        Args:
            project_id (str, optional): The UID of the project to synchronize.

        Returns:
            redirect to '/tablemodelview/list' view.
        """
        self.refresh_async(project_id)
        return redirect('/tablemodelview/list')

appbuilder.add_view_no_menu(Plaid)
appbuilder.add_link(
    'Refresh',
    label=__('Refresh'),
    href='/plaid/refresh',
    icon='fa-refresh',
    category='Sources',
    category_label=__('Sources'),
    category_icon='fa-database')
