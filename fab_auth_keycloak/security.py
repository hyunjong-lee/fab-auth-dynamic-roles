import logging

from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.sqla.manager import SecurityManager
from flask_oidc import OpenIDConnect

from .views import KeycloakAuthOIDCView


logger = logging.getLogger(__name__)


class KeycloakOIDCSecurityManagerMixin:
    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
            self.authoidview = KeycloakAuthOIDCView


try:
    from superset.security import SupersetSecurityManager
    class SupersetOIDCSecurityManager(KeycloakOIDCSecurityManagerMixin,
                                      SupersetSecurityManager):
        pass

except ImportError:
    logger.error("couldn't import SupersetSecurityManager")


try:
    from airflow.www_rbac.security import AirflowSecurityManager
    class AirflowOIDCSecurityManager(KeycloakOIDCSecurityManagerMixin,
                                      SupersetSecurityManager):
        pass

except ImportError:
    logger.error("couldn't import AirflowSecurityManager")

