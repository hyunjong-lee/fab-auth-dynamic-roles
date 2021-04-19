import logging

from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.sqla.manager import SecurityManager
from flask_oidc import OpenIDConnect

from .oidc_views import DynamicRoleAuthOIDCView


logger = logging.getLogger(__name__)


class DynamicRoleOIDCSecurityManagerMixin:
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
            self.authoidview = DynamicRoleAuthOIDCView


try:
    from superset.security import SupersetSecurityManager
    class SupersetOIDCSecurityManager(DynamicRoleOIDCSecurityManagerMixin,
                                      SupersetSecurityManager):
        pass

except ImportError:
    logger.error("from superset.security import SupersetSecurityManager failed")


try:
    from airflow.www_rbac.security import AirflowSecurityManager
    class AirflowOIDCSecurityManager(DynamicRoleOIDCSecurityManagerMixin,
                                     AirflowSecurityManager):
        pass

except ImportError:
    logger.error("from airflow.www_rbac.security import AirflowSecurityManager failed")

