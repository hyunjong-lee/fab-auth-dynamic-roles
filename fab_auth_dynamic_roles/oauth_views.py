import os
import logging
import urllib

from flask import flash, g, redirect, request, session, url_for
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.baseviews import expose
from flask_appbuilder.security.views import AuthOAuthView
from flask_login import login_user
import jwt


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


log = logging.getLogger(__name__)


# 이 view에서 해야할 작업

# - Sync roles dynamically
# - AzureAD의 경우 Group 정보 얻어와서 인증을 좀 더 부드럽게
# - 로그인 시 설정된 OAuth가 하나라면 바로 이동하도록 설정

class DynamicRoleAuthOAuthView(AuthOAuthView):

    @expose("/login/")
    @expose("/login/<provider>")
    @expose("/login/<provider>/<register>")
    def login(self, provider=None, register=None):
        log.debug("Provider: {0}".format(provider))
        if g.user is not None and g.user.is_authenticated:
            log.debug("Already authenticated {0}".format(g.user))
            return redirect(self.appbuilder.get_url_for_index)

        if provider is None:
            if len(self.appbuilder.sm.oauth_providers) > 1:
                return self.render_template(
                    self.login_template,
                    providers=self.appbuilder.sm.oauth_providers,
                    title=self.title,
                    appbuilder=self.appbuilder,
                )
            else:
                provider = self.appbuilder.sm.oauth_providers[0]["name"]

        log.debug("Going to call authorize for: {0}".format(provider))
        state = jwt.encode(
            request.args.to_dict(flat=False),
            self.appbuilder.app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        try:
            if register:
                log.debug("Login to Register")
                session["register"] = True
            if provider == "twitter":
                return self.appbuilder.sm.oauth_remotes[
                    provider
                ].authorize_redirect(
                    redirect_uri=url_for(
                        ".oauth_authorized",
                        provider=provider,
                        _external=True,
                        state=state,
                    )
                )
            else:
                return self.appbuilder.sm.oauth_remotes[
                    provider
                ].authorize_redirect(
                    redirect_uri=url_for(
                        ".oauth_authorized", provider=provider, _external=True
                    ),
                    state=state.decode("ascii")
                    if isinstance(state, bytes)
                    else state,
                )
        except Exception as e:
            log.error("Error on OAuth authorize: {0}".format(e))
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect(self.appbuilder.get_url_for_index)
