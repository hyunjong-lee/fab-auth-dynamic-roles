import logging
import os
import re
import urllib

from flask import flash, g, redirect, request, session, url_for
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.baseviews import expose
from flask_appbuilder.security.views import AuthOAuthView
from flask_login import login_user
import jwt


EMAIL_OAUTH_FIELD = os.getenv(
    'EMAIL_OAUTH_FIELD',
    default='email',
)

CLIENT_ROLE_OAUTH_FIELD = os.getenv(
    'CLIENT_ROLE_OAUTH_FIELD',
    default='roles',
)


log = logging.getLogger(__name__)


# TODO
# - AzureAD의 경우 Group 정보 얻어와서 인증을 좀 더 부드럽게

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

    @expose("/oauth-authorized/<provider>")
    def oauth_authorized(self, provider):
        log.debug("Authorized init")
        resp = self.appbuilder.sm.oauth_remotes[provider].authorize_access_token()
        if resp is None:
            flash(u"You denied the request to sign in.", "warning")
            return redirect(self.appbuilder.get_url_for_login)

        log.debug("OAUTH Authorized resp: {0}".format(resp))
        # Retrieves specific user info from the provider
        try:
            self.appbuilder.sm.set_oauth_session(provider, resp)
            userinfo = self.appbuilder.sm.oauth_user_info(provider, resp)
        except Exception as e:
            log.error("Error returning OAuth user info: {0}".format(e))
            user = None
        else:
            log.debug("User info retrieved from {0}: {1}".format(provider, userinfo))
            # User email is not whitelisted
            if provider in self.appbuilder.sm.oauth_whitelists:
                whitelist = self.appbuilder.sm.oauth_whitelists[provider]
                allow = False
                for e in whitelist:
                    if re.search(e, userinfo["email"]):
                        allow = True
                        break
                if not allow:
                    flash(u"You are not authorized.", "warning")
                    return redirect(self.appbuilder.get_url_for_login)
            else:
                log.debug("No whitelist for OAuth provider")
            user = self.appbuilder.sm.auth_user_oauth(userinfo)

        if user is None:
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        else:
            # sync roles from OAuth to flask
            sm = self.appbuilder.sm

            user.roles.clear()
            sm.update_user(user)

            if userinfo.get(CLIENT_ROLE_OAUTH_FIELD) is None:
                log.error(f'userinfo does not have {CLIENT_ROLE_OAUTH_FIELD} field')
                log.error(f'user info: {userinfo}')
            else:
                for role_name in userinfo.get(CLIENT_ROLE_OAUTH_FIELD):
                    role = sm.find_role(role_name)
                    if role is not None:
                        user.roles.append(role)
                        log.info(f"assign role: {role_name}, find_role: {role} to user: {userinfo.get(EMAIL_OAUTH_FIELD)}")
                    else:
                        log.error(f"role: {role_name} doesn't exist")
                sm.update_user(user)

            login_user(user)
            try:
                state = jwt.decode(
                    request.args["state"],
                    self.appbuilder.app.config["SECRET_KEY"],
                    algorithms=["HS256"],
                )
            except jwt.InvalidTokenError:
                raise Exception("State signature is not valid!")

            try:
                next_url = state["next"][0] or self.appbuilder.get_url_for_index
            except (KeyError, IndexError):
                next_url = self.appbuilder.get_url_for_index

            return redirect(next_url)
