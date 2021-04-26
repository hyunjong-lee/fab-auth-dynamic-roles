import logging

from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.sqla.manager import SecurityManager
from flask_oidc import OpenIDConnect

from .oidc_views import DynamicRoleAuthOIDCView
from .oauth_views import DynamicRoleAuthOAuthView


log = logging.getLogger(__name__)


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
        def __init__(self, appbuilder):
            super().__init__(appbuilder)
            if self.auth_type == AUTH_OAUTH:
                self.oauth_user_info = self.get_oauth_user_info

        def get_oauth_user_info(self, provider, resp):
            if provider != 'azure':
                return super().get_oauth_user_info(provider, resp)

            log.error("message from fab_auth_dynamic_roles")
            log.error("Azure response received : {0}".format(resp))
            id_token = resp["id_token"]
            log.error(str(id_token))
            me = self._azure_jwt_token_parse(id_token)
            log.error("Parse JWT token : {0}".format(me))
            # must set username from email and email from email for migration from OIDC to OAuth
            return {
                "name": me.get("name", ""),
                "email": me["email"],
                "first_name": me.get("given_name", ""),
                "last_name": me.get("family_name", ""),
                "id": me["oid"],
                "username": me["email"],
                "roles": me.get("roles", []),
            }

except ImportError:
    log.error("from superset.security import SupersetSecurityManager failed")


try:
    from airflow.www.security import AirflowSecurityManager
    class AirflowOIDCSecurityManager(DynamicRoleSecurityManagerMixin,
                                     AirflowSecurityManager):
        pass
    class AirflowOAuthSecurityManager(DynamicRoleSecurityManagerMixin,
                                      AirflowSecurityManager):
        def __init__(self, appbuilder):
            super().__init__(appbuilder)
            if self.auth_type == AUTH_OAUTH:
                self.oauth_user_info = self.get_oauth_user_info

        def get_oauth_user_info(self, provider, resp):
            if provider != 'azure':
                return super().get_oauth_user_info(provider, resp)

            log.error("message from fab_auth_dynamic_roles")
            log.error("Azure response received : {0}".format(resp))
            id_token = resp["id_token"]
            log.error(str(id_token))
            me = self._azure_jwt_token_parse(id_token)
            log.error("Parse JWT token : {0}".format(me))
            # must set username from email and email from email for migration from OIDC to OAuth
            return {
                "name": me.get("name", ""),
                "email": me["email"],
                "first_name": me.get("given_name", ""),
                "last_name": me.get("family_name", ""),
                "id": me["oid"],
                "username": me["email"],
                "roles": me.get("roles", []),
            }

except ImportError:
    log.error("from airflow.www_rbac.security import AirflowSecurityManager failed")


try:
    from astronomer.flask_appbuilder.security import AirflowAstroSecurityManager
    class AirflowAstroOIDCSecurityManager(DynamicRoleSecurityManagerMixin,
                                          AirflowAstroSecurityManager):
        pass
    class AirflowAstroOAuthSecurityManager(DynamicRoleSecurityManagerMixin,
                                          AirflowAstroSecurityManager):
        pass

except ImportError:
    log.error("from astronomer.flask_appbuilder.security import AirflowAstroSecurityManager failed")
