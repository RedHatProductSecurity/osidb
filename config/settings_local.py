import os
import sys
from importlib.util import find_spec

import ldap
from django_auth_ldap.config import GroupOfNamesType, LDAPSearch

from .settings import *

# SECURITY WARNING: keep the secret key used in production/stage secret!
SECRET_KEY = get_random_secret_key()  # pragma: allowlist secret

PUBLIC_READ_GROUPS = ["data-prodsec"]
PUBLIC_WRITE_GROUPS = ["data-prodsec-write"]
INTERNAL_READ_GROUPS = ["data-internal-read"]
INTERNAL_WRITE_GROUPS = ["data-internal-write"]
EMBARGO_READ_GROUPS = ["data-topsecret"]
EMBARGO_WRITE_GROUPS = ["data-topsecret-write"]
# Contains all non-admin groups
ALL_GROUPS = [
    *PUBLIC_READ_GROUPS,
    *PUBLIC_WRITE_GROUPS,
    *INTERNAL_READ_GROUPS,
    *INTERNAL_WRITE_GROUPS,
    *EMBARGO_READ_GROUPS,
    *EMBARGO_WRITE_GROUPS,
]
# Group for managing the OSIDB service (single value, used in LDAP DN lookups)
SERVICE_MANAGE_GROUP = "osidb-service-manage"

# Backward-compat aliases (singular) used by frozen migrations
PUBLIC_WRITE_GROUP = PUBLIC_WRITE_GROUPS[0]
INTERNAL_READ_GROUP = INTERNAL_READ_GROUPS[0]
INTERNAL_WRITE_GROUP = INTERNAL_WRITE_GROUPS[0]
EMBARGO_READ_GROUP = EMBARGO_READ_GROUPS[0]
EMBARGO_WRITE_GROUP = EMBARGO_WRITE_GROUPS[0]

DEBUG = True

ALLOWED_HOSTS = ["*"]

INTERNAL_IPS = ["127.0.0.1", "::1"]

AUTHENTICATION_BACKENDS += ("django_auth_ldap.backend.LDAPBackend",)

AUTH_LDAP_SERVER_URI = "ldap://testldap:1389"

AUTH_LDAP_BIND_DN = f"cn=admin,{LDAP_BASE_DN}"
AUTH_LDAP_BIND_PASSWORD = "adminpassword"
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    f"cn=users,cn=accounts,{LDAP_BASE_DN}", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"
)

AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    f"cn=groups,cn=accounts,{LDAP_BASE_DN}",
    ldap.SCOPE_SUBTREE,
    "(objectClass=groupOfNames)",
)
AUTH_LDAP_GROUP_TYPE = GroupOfNamesType(name_attr="cn")

AUTH_LDAP_ALWAYS_UPDATE_USER = True
AUTH_LDAP_FIND_GROUP_PERMS = True
AUTH_LDAP_MIRROR_GROUPS = True
AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
}

AUTH_LDAP_REQUIRE_GROUP = f"cn=active,cn=groups,cn=accounts,{LDAP_BASE_DN}"

AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_active": f"cn=active,cn=groups,cn=accounts,{LDAP_BASE_DN}",
    "is_staff": f"cn={SERVICE_MANAGE_GROUP},cn=groups,cn=accounts,{LDAP_BASE_DN}",
    "is_superuser": f"cn={SERVICE_MANAGE_GROUP},cn=groups,cn=accounts,{LDAP_BASE_DN}",
}


DATABASES = {
    "default": {
        "NAME": "osidb",
        "USER": "osidb_app_user",
        "PASSWORD": "passw0rd",
        "HOST": "osidb-data",
        "PORT": "5432",
        "ENGINE": "psqlextra.backend",
        "ATOMIC_REQUESTS": True,  # perform HTTP requests as atomic transactions
        "OPTIONS": {
            "sslmode": "require",
            # prevent libpq from automatically trying to connect to the db via GSSAPI
            "gssencmode": "disable",
            # this is a hack due to our inability to set a custom parameter either at
            # the database or role level in managed databases such as AWS RDS
            "options": "-c osidb.acl=00000000-0000-0000-0000-000000000000",
        },
        "CONN_MAX_AGE": 120,
        "TEST": {
            "TEMPLATE": "template1",
        },
    }
}

STATIC_ROOT = "/var/www/osidb/static/"
STATIC_URL = "/static/"

INSTALLED_APPS += ["osidb.tests"]

# Email configuration

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# django-silk profiling (opt-in)
#
# Setup:
#   1. Add OSIDB_ENABLE_SILK=1 to your .env
#   2. make sync-deps              (update local venv)
#   3. make apply-uv-dev-sync      (install dev deps in osidb-service container)
#   4. podman restart osidb-service (runs migrate + starts runserver)
#   5. Browse http://localhost:8000/silk/
#
# For load testing + profiling, see perf/silk_profiling.py
#
# To disable: remove OSIDB_ENABLE_SILK from .env and restart.
# Silk tables are harmless when left behind; to drop them:
#   podman exec osidb-service python manage.py migrate silk zero
if (
    os.environ.get("OSIDB_ENABLE_SILK", "").strip() not in ("", "0")
    and "pytest" not in sys.modules
    and find_spec("silk")
):
    INSTALLED_APPS += ["silk"]
    # Must be after GZipMiddleware per silk docs
    _gzip = MIDDLEWARE.index("django.middleware.gzip.GZipMiddleware")
    MIDDLEWARE.insert(_gzip + 1, "silk.middleware.SilkyMiddleware")
    SILKY_PYTHON_PROFILER = True
    SILKY_INTERCEPT_PERCENT = 100
