import os
import logging
import urllib

from flask import redirect, request
from flask_admin import expose
from flask_appbuilder.security.views import AuthOAuthView
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

CLIENT_ROLE_OIDC_FIELD = os.getenv(
    'CLIENT_ROLE_OIDC_FIELD',
    default='roles',
)

RESOURCE_ACCESS_APP_OIDC_FIELD = os.getenv(
    'RESOURCE_ACCESS_APP_OIDC_FIELD',
    default='superset',
)

OIDC_LOGOUT_URI = 'OIDC_LOGOUT_URI'


logger = logging.getLogger(__name__)


# 이 view에서 해야할 작업

# - Sync roles dynamically
# - AzureAD의 경우 Group 정보 얻어와서 인증을 좀 더 부드럽게
# - 로그인 시 설정된 OAuth가 하나라면 바로 이동하도록 설정

class DynamicRoleAuthOAuthView(AuthOAuthView):
    pass
