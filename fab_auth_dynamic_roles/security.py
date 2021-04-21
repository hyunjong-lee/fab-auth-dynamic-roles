import logging

from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.sqla.manager import SecurityManager
from flask_oidc import OpenIDConnect

from .oidc_views import DynamicRoleAuthOIDCView
from .oauth_views import DynamicRoleAuthOAuthView


logger = logging.getLogger(__name__)


class DynamicRoleSecurityManagerMixin:
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
            self.authoidview = DynamicRoleAuthOIDCView
        elif self.auth_type == AUTH_OAUTH:
            self.authoauthview = DynamicRoleAuthOAuthView


try:
    from superset.security import SupersetSecurityManager
    class SupersetOIDCSecurityManager(DynamicRoleSecurityManagerMixin,
                                      SupersetSecurityManager):
        pass
    class SupersetOAuthSecurityManager(DynamicRoleSecurityManagerMixin,
                                       SupersetSecurityManager):
        pass

except ImportError:
    logger.error("from superset.security import SupersetSecurityManager failed")


try:
    from airflow.www_rbac.security import AirflowSecurityManager
    class AirflowOIDCSecurityManager(DynamicRoleSecurityManagerMixin,
                                     AirflowSecurityManager):
        pass
    class AirflowOAuthSecurityManager(DynamicRoleSecurityManagerMixin,
                                      AirflowSecurityManager):
        pass

except ImportError:
    logger.error("from airflow.www_rbac.security import AirflowSecurityManager failed")

