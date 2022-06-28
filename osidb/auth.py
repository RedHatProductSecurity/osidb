import logging

from drf_spectacular.contrib.rest_framework_simplejwt import SimpleJWTScheme
from rest_framework_simplejwt.authentication import JWTAuthentication

from osidb.core import set_user_acls

_logger = logging.getLogger(__name__)

# This hack is necessary in order to set ACLs after authentication
# the normal way to do this would be through a Middleware, however
# DRF does not perform token authentication at the middleware level
# but instead does it later on at the view level, thus making the
# actual user performing the request unavailable inside Middleware
# code. This issue has been raised in the DRF multiple times but
# nothing has been done nor is there any plan to fix it.
# https://github.com/jpadilla/django-rest-framework-jwt/issues/45
# https://stackoverflow.com/a/41281748
# https://github.com/encode/django-rest-framework/discussions/7770


class OsidbTokenAuthentication(JWTAuthentication):
    """authenticate token"""

    def authenticate(self, request):
        creds = super().authenticate(request)
        if creds and creds[0].is_authenticated:
            _logger.info(f"ACLs set from auth override for user {creds[0].username}")
            set_user_acls(creds[0].groups.all())
        return creds


class OsidbTokenAuthenticationScheme(SimpleJWTScheme):
    """OpenAPI scheme extension for custom auth class to be properly discovered"""

    target_class = OsidbTokenAuthentication
    name = "OsidbTokenAuthentication"
