import os
import logging
import urllib

from flask import redirect, request
from flask_admin import expose
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user


USERNAME_OIDC_FIELD = os.getenv(
    'USERNAME_OIDC_FIELD',
    default='preferred_username',
)

FIRST_NAME_OIDC_FIELD = os.getenv(
    'FIRST_NAME_OIDC_FIELD',
    default='given_name',
)

LAST_NAME_OIDC_FIELD = os.getenv(
    'LAST_NAME_OIDC_FIELD',
    default='family_name',
)

EMAIL_OIDC_FIELD = os.getenv(
    'EMAIL_OIDC_FIELD',
    default='email',
)

KEYCLOAK_CLIENT_ROLE_OIDC_FIELD = os.getenv(
    'KEYCLOAK_CLIENT_ROLE_OIDC_FIELD',
    default='roles',
)

KEYCLOAK_RESOURCE_ACCESS_APP_OIDC_FIELD = os.getenv(
    'KEYCLOAK_RESOURCE_ACCESS_APP_OIDC_FIELD',
    default='superset',
)

OIDC_LOGOUT_URI = 'OIDC_LOGOUT_URI'


logger = logging.getLogger(__name__)


class KeycloakAuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):

        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield(EMAIL_OIDC_FIELD))
            info = oidc.user_getinfo([
                USERNAME_OIDC_FIELD,
                FIRST_NAME_OIDC_FIELD,
                LAST_NAME_OIDC_FIELD,
                EMAIL_OIDC_FIELD,
                KEYCLOAK_CLIENT_ROLE_OIDC_FIELD,
            ])

            if user is None:
                user = sm.add_user(
                    username=info.get(USERNAME_OIDC_FIELD),
                    first_name=info.get(FIRST_NAME_OIDC_FIELD),
                    last_name=info.get(LAST_NAME_OIDC_FIELD),
                    email=info.get(EMAIL_OIDC_FIELD),
                    role=sm.find_role(sm.auth_user_registration_role)
                )
                logger.info(f"user added: {info.get(EMAIL_OIDC_FIELD)}")

            # sync roles from keycloak to flask
            user.roles.clear()
            sm.update_user(user)

            if info.get(KEYCLOAK_CLIENT_ROLE_OIDC_FIELD) is None:
                logger.error(f'user {info.get(EMAIL_OIDC_FIELD)} does not have ROLE')
                logger.error(f'user info: {info}')
            else:
                for role in info.get(KEYCLOAK_CLIENT_ROLE_OIDC_FIELD):
                    user.roles.append(sm.find_role(role))
                    logger.info(f"assign role: {role}, find_role: {sm.find_role(role)} to user: {info.get(EMAIL_OIDC_FIELD)}")
                sm.update_user(user)

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid
        oidc.logout()
        super(KeycloakAuthOIDCView, self).logout()

        request_root = request.url_root.strip('/')
        redirect_url = f'{request_root}{self.appbuilder.get_url_for_login}'

        issuer = oidc.client_secrets.get('issuer')
        logout_uri = f'{issuer}/protocol/openid-connect/logout?redirect_uri='
        if OIDC_LOGOUT_URI in self.appbuilder.app.config:
            logout_uri = self.appbuilder.app.config[OIDC_LOGOUT_URI]

        return redirect(f'{logout_uri}{urllib.parse.quote(redirect_url)}')
