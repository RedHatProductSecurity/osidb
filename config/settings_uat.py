import ssl

import ldap
from django_auth_ldap.config import GroupOfUniqueNamesType, LDAPSearch, LDAPSearchUnion

from .settings import *

# django secret key provided by ansible vault
SECRET_KEY = get_env("DJANGO_SECRET_KEY")

# We trust OpenShift's HAProxy to strip the X-Forwarded-Proto header and to set it to "https" if
# the request came over HTTPS from the client to HAProxy.
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Minimal group for read access of public flaws in OSIDB
# TODO: In the future we might simply use a proxy group in which
# membership is based off of one or more LDAP groups
# e.g. (|(memberOf=group-a)(memberOf=group-b))
PUBLIC_READ_GROUPS = ["osidb-stage-public-read", "red-hat-product-security"]
# Minimal group for write access of public flaws in OSIDB
PUBLIC_WRITE_GROUP = "osidb-stage-public-write"
# Minimal group for read access of embargoed flaws in OSIDB
EMBARGO_READ_GROUP = "osidb-stage-embargo-read"
# Minimal group for write access of embargoed flaws in OSIDB
EMBARGO_WRITE_GROUP = "osidb-stage-embargo-write"
# Minimal group for read access of internal flaws in OSIDB
INTERNAL_READ_GROUP = "osidb-stage-internal-read"
# Minimal group for write access of internal flaws in OSIDB
INTERNAL_WRITE_GROUP = "osidb-stage-internal-write"
# Contains all non-admin groups
ALL_GROUPS = [
    *PUBLIC_READ_GROUPS,
    PUBLIC_WRITE_GROUP,
    EMBARGO_READ_GROUP,
    EMBARGO_WRITE_GROUP,
    INTERNAL_READ_GROUP,
    INTERNAL_WRITE_GROUP,
]
# Minimal group for managing the OSIDB service
SERVICE_MANAGE_GROUP = "osidb-stage-manage"

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

DATABASES = {
    "default": {
        "NAME": "osidb_uat",  # get_env("OSIDB_DB_NAME", default="osidb_uat"),
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
}

STATIC_ROOT = "/opt/app-root/static/"
STATIC_URL = "/static/"

# Celery settings

REDIS_PASSWORD = get_env("OSIDB_REDIS_PASSWORD")
CELERY_BROKER_URL = CELERY_RESULT_BACKEND = f"rediss://:{REDIS_PASSWORD}@redis:6379/"
CELERY_BROKER_USE_SSL = CELERY_REDIS_BACKEND_USE_SSL = CELERY_RHUBARB_BACKEND_KWARGS = {
    "ssl_keyfile": "/opt/app-root/etc/redis/certs/osidb-redis.key",
    "ssl_certfile": "/opt/app-root/etc/redis/certs/osidb-redis.crt",
    "ssl_ca_certs": "/opt/app-root/etc/redis/certs/osidb-redis-ca.crt",
    "ssl_cert_reqs": ssl.CERT_REQUIRED,
}

# Kerberos + LDAP Auth
INSTALLED_APPS += [
    "kaminarimon",
]
AUTHENTICATION_BACKENDS += [
    "kaminarimon.backend.LDAPRemoteUser",
    # TODO: remove and replace by krb auth for admin interface
    "django_auth_ldap.backend.LDAPBackend",
]
KRB5_HOSTNAME = get_env("KRB5_HOSTNAME")

# Execute once an hour in uat to be consistent with production
CISA_COLLECTOR_CRONTAB = crontab(minute=0)

# Setup rotation logging into filesystem
LOG_FILE_SIZE = 1024 * 1024 * 10  # 10mb
LOG_FILE_COUNT = 3

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
        "filename": "/var/log/uat-celery.log",
        "maxBytes": LOG_FILE_SIZE,
        "backupCount": LOG_FILE_COUNT,
    }
    LOGGING["handlers"]["console"] = {
        "level": "INFO",
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "verbose",
        "filename": "/var/log/uat-django.log",
        "maxBytes": LOG_FILE_SIZE,
        "backupCount": LOG_FILE_COUNT,
    }


# Setup logging for Bugzilla
LOGGING["loggers"]["bugzilla"] = {
    "handlers": ["console"],
    "level": "DEBUG",
    "propagate": False,
}
