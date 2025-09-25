import os
import logging
import time
from urllib.parse import urlencode
from flask import session, redirect, request, render_template_string, Blueprint, jsonify
from flask_appbuilder.security.manager import AUTH_OAUTH, AUTH_DB
from superset.security import SupersetSecurityManager
from flask_appbuilder.baseviews import expose
from flask_appbuilder.security.views import AuthOAuthView
import requests
from datetime import timedelta
from flask import Flask

# =============================================================================
# BASIC CONFIGURATION
# =============================================================================
SECRET_KEY = "123123123"

SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    "postgresql+psycopg2://superset:superset@db:5432/superset"
)

AUTH_TYPE = AUTH_OAUTH
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Gamma"
AUTH_ROLE_ADMIN = "Admin"
AUTH_ROLES_SYNC_AT_LOGIN = True
WTF_CSRF_ENABLED = False 
SHOW_STACKTRACE = True
AUTH_DB = True

# session config
SESSION_COOKIE_NAME = "superset_session_dev"
SESSION_COOKIE_SAMESITE = None
SESSION_COOKIE_SECURE = False
SESSION_PROTECTION = None
PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

OAUTH_PROVIDERS = [
    {
        "name": "keycloak",
        "icon": "fa-key",
        "token_key": "access_token",
        "remote_app": {
            "client_id": "superset",
            "client_secret": "a7N0pfE85z3xdHwiXH44DTExxvC7iZnB",
            "server_metadata_url": "http://keycloak.local:8180/realms/jmix-realm/.well-known/openid-configuration",
            "client_kwargs": {"scope": "openid profile email roles"},
        },
    }
]

# =============================================================================
# LOGGING
# =============================================================================
logger = logging.getLogger("superset_config")
logger.setLevel(logging.DEBUG)

# =============================================================================
# CUSTOM AUTH VIEW
# =============================================================================
class CustomAuthOAuthView(AuthOAuthView):
    @expose("/oauth-authorized/keycloak")
    def oauth_authorized_keycloak(self):
        super().oauth_authorized("keycloak")
        html = """
        <html><body>
            <script>
            if (window.opener && !window.opener.closed) {
                window.opener.location.reload();
            }
            window.close();
            </script>
        </body></html>
        """
        return render_template_string(html)

    @expose("/logout/")
    def logout(self):
        id_token = session.get("id_token")
        super().logout()
        session.clear()

        base_url = "http://keycloak.local:8180/realms/jmix-realm/protocol/openid-connect/logout"
        redirect_uri = "http://localhost:8088/login/"

        params = {"post_logout_redirect_uri": redirect_uri, "client_id": "superset"}
        if id_token:
            params["id_token_hint"] = id_token

        logout_url = f"{base_url}?{urlencode(params)}"
        return redirect(logout_url)

# =============================================================================
# CUSTOM SECURITY MANAGER
# =============================================================================
class KeycloakSecurityManager(SupersetSecurityManager):
    authoauthview = CustomAuthOAuthView

    def _extract_roles(self, data):
        roles = []
        if "realm_access" in data:
            roles.extend(data["realm_access"].get("roles", []))
        if "resource_access" in data and "superset" in data["resource_access"]:
            roles.extend(data["resource_access"]["superset"].get("roles", []))
        if not roles:
            roles = data.get("roles", [])
        if not roles:
            roles = ["Gamma"]
        return roles

    def oauth_user_info(self, provider, resp=None):
        if provider == "keycloak":
            try:
                if resp and "id_token" in resp:
                    session["id_token"] = resp["id_token"]

                me = self.appbuilder.sm.oauth_remotes[provider].get(
                    "http://keycloak.local:8180/realms/jmix-realm/protocol/openid-connect/userinfo"
                )
                me.raise_for_status()
                data = me.json()
                roles = self._extract_roles(data)

                return {
                    "username": data.get("preferred_username"),
                    "first_name": data.get("given_name", ""),
                    "last_name": data.get("family_name", ""),
                    "email": data.get("email", ""),
                    "role_keys": roles,
                }
            except Exception as e:
                logger.error("Error getting user info from Keycloak: %s", e)
                return None

    def get_user_from_request(self):
        try:
            from flask_login import current_user as _current_user
            if _current_user and getattr(_current_user, "is_authenticated", False):
                return None
        except Exception:
            pass

        token = request.args.get("access_token")
        if not token and "Authorization" in request.headers:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return None

        userinfo_url = "http://keycloak.local:8180/realms/jmix-realm/protocol/openid-connect/userinfo"
        try:
            resp = requests.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            roles = self._extract_roles(data)

            return {
                "username": data.get("preferred_username"),
                "first_name": data.get("given_name", ""),
                "last_name": data.get("family_name", ""),
                "email": data.get("email"),
                "role_keys": roles,
            }
        except requests.exceptions.RequestException as e:
            logger.error("❌ Error validating access_token with Keycloak: %s", e)
            return None
        except Exception as e:
            logger.error("❌ Unexpected error in get_user_from_request: %s", e)
            return None

CUSTOM_SECURITY_MANAGER = KeycloakSecurityManager

# =============================================================================
# ROLES & FEATURES
# =============================================================================
AUTH_ROLES_MAPPING = {
    "superset_users": ["Gamma", "Alpha"],
    "KeycloakAdmin": ["Admin"],
    "admin": ["Admin"],
}
GUEST_ROLE_NAME = "Gamma"

FEATURE_FLAGS = {"EMBEDDED_SUPERSET": True}
HTTP_HEADERS = {"X-Frame-Options": "ALLOWALL"}
SESSION_COOKIE_SAMESITE = None
ENABLE_CORS = True
CORS_OPTIONS = {"supports_credentials": True, "resources": r"/*", "origins": ["http://localhost:8080"]}
TALISMAN_ENABLED = False
CONTENT_SECURITY_POLICY = None
ENABLE_PROXY_FIX = True
TALISMAN_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://static.scarf.sh/",
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'strict-dynamic'"],
        "frame-ancestors": ["http://localhost:8080"]
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}
# =============================================================================
# GUEST TOKEN CACHE ENDPOINT
# =============================================================================
_cached_guest_token = None
_cached_expiry = 0

def FLASK_APP_MUTATOR(app: Flask) -> None:
    def csp_nonce():
        return ""

    app.jinja_env.globals["csp_nonce"] = csp_nonce

    bp = Blueprint("cached_guest_token", __name__)

    @bp.route("/cached_guest_token")
    def cached_guest_token():
        global _cached_guest_token, _cached_expiry

        if _cached_guest_token and _cached_expiry > time.time():
            return jsonify({"guest_token": _cached_guest_token})

        try:
            from superset.security.guest_token import GuestToken
            new_token = GuestToken().create(
                resources=[{"type": "dashboard", "id": "2ad9c913-18fd-49b0-af3d-506f0dd01bac"}],
                rls=[],
                user={"username": "guest", "first_name": "Guest", "last_name": "User", "roles": ["Gamma"]}
            )
            _cached_guest_token = new_token["token"]
            _cached_expiry = time.time() + 3600
            return jsonify({"guest_token": _cached_guest_token})
        except Exception as e:
            logger.error("❌ Error creating guest_token: %s", e)
            return jsonify({"error": str(e)}), 500

    app.register_blueprint(bp)

# =============================================================================
# UI CUSTOMIZATION
# =============================================================================
LOGO_TARGET_PATH = "/superset/welcome"
LOGO_TOOLTIP = "Welcome to Quanluc Dashboard"
LOGO_RIGHT_TEXT = "Quản lý quân lực"
APP_NAME = "Quản lý quân lực"
