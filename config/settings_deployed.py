"""
Configurable Django settings for deployed OSIDB environments.
All environment-specific differences are driven by environment variables.

Required env vars:
    DJANGO_SECRET_KEY
    OSIDB_DB_USER, OSIDB_DB_PASSWORD, OSIDB_DB_HOST, OSIDB_DB_HOST_RO
    OSIDB_REDIS_PASSWORD
    KRB5_HOSTNAME
    ET_URL
    OSIDB_PUBLIC_READ_GROUPS        - List of LDAP groups for public read access
    OSIDB_PUBLIC_WRITE_GROUPS       - List of LDAP groups for public write access
    OSIDB_INTERNAL_READ_GROUPS      - List of LDAP groups for internal read access
    OSIDB_INTERNAL_WRITE_GROUPS     - List of LDAP groups for internal write access
    OSIDB_EMBARGO_READ_GROUPS       - List of LDAP groups for embargo read access
    OSIDB_EMBARGO_WRITE_GROUPS      - List of LDAP groups for embargo write access
    OSIDB_SERVICE_MANAGE_GROUP      - LDAP group for service management (single string)

Optional env vars for per-environment tuning:
    OSIDB_ENV                       - Environment name for log file prefixes (default: "prod")
    OSIDB_DB_NAME                   - Database name (default: "osidb")
    OSIDB_CORS_LITERAL_ORIGINS_ONLY - Use literal CORS origins instead of regex (default: "False");
                                      requires OSIDB_CORS_ALLOWED_ORIGINS (JSON list of origin strings)
"""

import ssl

import ldap
from django_auth_ldap.config import GroupOfUniqueNamesType, LDAPSearch, LDAPSearchUnion

from .settings import *

# --- Environment ---

ENV = get_env("OSIDB_ENV", default="prod")

# --- Django core ---

# django secret key provided by ansible vault
SECRET_KEY = get_env("DJANGO_SECRET_KEY")

# We trust OpenShift's HAProxy to strip the X-Forwarded-Proto header and to set it to "https" if
# the request came over HTTPS from the client to HAProxy.
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --- ACL groups ---
# All group variables are lists, fully configurable via env vars.
# Accepts JSON arrays (e.g. '["group-a", "group-b"]') or plain strings.

PUBLIC_READ_GROUPS = get_env_groups("OSIDB_PUBLIC_READ_GROUPS")
PUBLIC_WRITE_GROUPS = get_env_groups("OSIDB_PUBLIC_WRITE_GROUPS")
INTERNAL_READ_GROUPS = get_env_groups("OSIDB_INTERNAL_READ_GROUPS")
INTERNAL_WRITE_GROUPS = get_env_groups("OSIDB_INTERNAL_WRITE_GROUPS")
EMBARGO_READ_GROUPS = get_env_groups("OSIDB_EMBARGO_READ_GROUPS")
EMBARGO_WRITE_GROUPS = get_env_groups("OSIDB_EMBARGO_WRITE_GROUPS")
# Contains all non-admin groups
ALL_GROUPS = [
    *PUBLIC_READ_GROUPS,
    *PUBLIC_WRITE_GROUPS,
    *INTERNAL_READ_GROUPS,
    *INTERNAL_WRITE_GROUPS,
    *EMBARGO_READ_GROUPS,
    *EMBARGO_WRITE_GROUPS,
]
# Minimal group for managing the OSIDB service
SERVICE_MANAGE_GROUP = get_env("OSIDB_SERVICE_MANAGE_GROUP")

# Backward-compat aliases (singular) used by frozen migrations
PUBLIC_WRITE_GROUP = PUBLIC_WRITE_GROUPS[0]
INTERNAL_READ_GROUP = INTERNAL_READ_GROUPS[0]
INTERNAL_WRITE_GROUP = INTERNAL_WRITE_GROUPS[0]
EMBARGO_READ_GROUP = EMBARGO_READ_GROUPS[0]
EMBARGO_WRITE_GROUP = EMBARGO_WRITE_GROUPS[0]

# --- LDAP ---

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)

AUTH_LDAP_USER_SEARCH = LDAPSearchUnion(
    LDAPSearch("ou=users,dc=redhat,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"),
    LDAPSearch(
        "ou=serviceaccounts,dc=redhat,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"
    ),
)

AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "ou=adhoc,ou=managedgroups,dc=redhat,dc=com",
    ldap.SCOPE_SUBTREE,
    "(objectClass=groupOfUniqueNames)",
)
AUTH_LDAP_GROUP_TYPE = GroupOfUniqueNamesType(name_attr="cn")

AUTH_LDAP_ALWAYS_UPDATE_USER = True
AUTH_LDAP_FIND_GROUP_PERMS = True
AUTH_LDAP_MIRROR_GROUPS = True

AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
}

AUTH_LDAP_REQUIRE_GROUP = (
    f"cn={PUBLIC_READ_GROUPS[0]},ou=adhoc,ou=managedgroups,dc=redhat,dc=com"
)

AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_active": f"cn={PUBLIC_READ_GROUPS[0]},ou=adhoc,ou=managedgroups,dc=redhat,dc=com",
    "is_staff": f"cn={SERVICE_MANAGE_GROUP},ou=adhoc,ou=managedgroups,dc=redhat,dc=com",
    "is_superuser": f"cn={SERVICE_MANAGE_GROUP},ou=adhoc,ou=managedgroups,dc=redhat,dc=com",
}

# --- Database ---

DATABASES = {
    "default": {
        "NAME": get_env("OSIDB_DB_NAME", default="osidb"),
        "USER": get_env("OSIDB_DB_USER"),
        "PASSWORD": get_env("OSIDB_DB_PASSWORD"),
        "HOST": get_env("OSIDB_DB_HOST"),
        "PORT": get_env("OSIDB_DB_PORT", default="5432"),
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
    },
    "read-replica-1": {
        "NAME": get_env("OSIDB_DB_NAME", default="osidb"),
        "USER": get_env("OSIDB_DB_USER"),
        "PASSWORD": get_env("OSIDB_DB_PASSWORD"),
        "HOST": get_env("OSIDB_DB_HOST_RO"),
        "PORT": get_env("OSIDB_DB_PORT", default="5432"),
        "ENGINE": "psqlextra.backend",
        "OPTIONS": {
            "sslmode": "require",
            # prevent libpq from automatically trying to connect to the db via GSSAPI
            "gssencmode": "disable",
            # this is a hack due to our inability to set a custom parameter either at
            # the database or role level in managed databases such as AWS RDS
            "options": "-c osidb.acl=00000000-0000-0000-0000-000000000000",
        },
        "CONN_MAX_AGE": 120,
    },
}

DATABASE_ROUTERS = ["osidb.routers.AffectV1ReplicaRouter"]

# --- Static files ---

STATIC_ROOT = "/opt/app-root/static/"
STATIC_URL = "/static/"

# --- Celery / Redis ---

REDIS_PASSWORD = get_env("OSIDB_REDIS_PASSWORD")
CELERY_BROKER_URL = CELERY_RESULT_BACKEND = f"rediss://:{REDIS_PASSWORD}@redis:6379/"
CELERY_BROKER_USE_SSL = CELERY_REDIS_BACKEND_USE_SSL = CELERY_RHUBARB_BACKEND_KWARGS = {
    "ssl_keyfile": "/opt/app-root/etc/redis/certs/osidb-redis.key",
    "ssl_certfile": "/opt/app-root/etc/redis/certs/osidb-redis.crt",
    "ssl_ca_certs": "/opt/app-root/etc/redis/certs/osidb-redis-ca.crt",
    "ssl_cert_reqs": ssl.CERT_REQUIRED,
}

# --- Kerberos + LDAP Auth ---

INSTALLED_APPS += [
    "kaminarimon",
]
AUTHENTICATION_BACKENDS += [
    "kaminarimon.backend.LDAPRemoteUser",
    # TODO: remove and replace by krb auth for admin interface
    "django_auth_ldap.backend.LDAPBackend",
]
KRB5_HOSTNAME = get_env("KRB5_HOSTNAME")

# --- External services ---

ERRATA_TOOL_SERVER = get_env("ET_URL")
ERRATA_TOOL_XMLRPC_BASE_URL = f"{ERRATA_TOOL_SERVER}/errata/errata_service"

# --- Collectors ---

# Execute once an hour
CISA_COLLECTOR_CRONTAB = crontab(minute=0)

# --- Logging ---

# Use either logstash logging or basic file logging based
# on the instance configuration
if get_env("MPP_LOGSTASH_LOGGING_ENABLED", is_bool=True, default="False"):
    LOGSTASH_PORT = 5140
    LOGSTASH_HOST = "logstash"

    # Setup logging to logstash via TCP socket
    LOGGING["handlers"]["celery"] = {
        "class": "osidb.helpers.JSONSocketHandler",
        "formatter": "verbose_celery",
        "host": LOGSTASH_HOST,
        "port": LOGSTASH_PORT,
        "logfile": "celery.log",
    }
    LOGGING["handlers"]["console"] = {
        "level": "INFO",
        "class": "osidb.helpers.JSONSocketHandler",
        "formatter": "verbose",
        "host": LOGSTASH_HOST,
        "port": LOGSTASH_PORT,
        "logfile": "django.log",
    }

elif get_env("MPP_LOGFILE_LOGGING_ENABLED", is_bool=True, default="False"):
    # Setup rotation logging into filesystem
    LOG_FILE_SIZE = 1024 * 1024 * 100  # 100mb
    LOG_FILE_COUNT = 3

    LOGGING["handlers"]["celery"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "verbose_celery",
        "filename": f"/var/log/{ENV}-celery.log",
        "maxBytes": LOG_FILE_SIZE,
        "backupCount": LOG_FILE_COUNT,
    }
    LOGGING["handlers"]["console"] = {
        "level": "INFO",
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "verbose",
        "filename": f"/var/log/{ENV}-django.log",
        "maxBytes": LOG_FILE_SIZE,
        "backupCount": LOG_FILE_COUNT,
    }

# Setup logging for Bugzilla
LOGGING["loggers"]["bugzilla"] = {
    "handlers": ["console"],
    "level": "DEBUG",
    "propagate": False,
}

# --- CORS ---

if get_env("OSIDB_CORS_LITERAL_ORIGINS_ONLY", is_bool=True, default="False"):
    CORS_ALLOWED_ORIGINS = get_env(
        "OSIDB_CORS_ALLOWED_ORIGINS", default="[]", is_json=True
    )
    CORS_ALLOWED_ORIGIN_REGEXES = []
