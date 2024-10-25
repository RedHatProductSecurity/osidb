import ldap
from django_auth_ldap.config import GroupOfNamesType, LDAPSearch

from .settings import *

# SECURITY WARNING: keep the secret key used in production/stage secret!
SECRET_KEY = get_random_secret_key()  # pragma: allowlist secret

# Minimal group for read access of public flaws in OSIDB
PUBLIC_READ_GROUPS = ["data-prodsec"]
# Minimal group for write access of public flaws in OSIDB
PUBLIC_WRITE_GROUP = "data-prodsec-write"
# Minimal group for read access of embargoed flaws in OSIDB
EMBARGO_READ_GROUP = "data-topsecret"
# Minimal group for write access of embargoed flaws in OSIDB
EMBARGO_WRITE_GROUP = "data-topsecret-write"
# Minimal group for read access of internal flaws in OSIDB
INTERNAL_READ_GROUP = "data-internal-read"
# Minimal group for write access of internal flaws in OSIDB
INTERNAL_WRITE_GROUP = "data-internal-write"

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
SERVICE_MANAGE_GROUP = "osidb-service-manage"

DEBUG = True

ALLOWED_HOSTS = ["*"]

INTERNAL_IPS = ["127.0.0.1", "::1"]

AUTHENTICATION_BACKENDS += ("django_auth_ldap.backend.LDAPBackend",)

AUTH_LDAP_BIND_DN = "cn=admin,dc=redhat,dc=com"
AUTH_LDAP_BIND_PASSWORD = "adminpassword"
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "ou=users,dc=redhat,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"
)

AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "ou=users,dc=redhat,dc=com",
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

AUTH_LDAP_REQUIRE_GROUP = "cn=active,ou=users,dc=redhat,dc=com"

AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_active": "cn=active,ou=users,dc=redhat,dc=com",
    "is_staff": f"cn={SERVICE_MANAGE_GROUP},ou=users,dc=redhat,dc=com",
    "is_superuser": f"cn={SERVICE_MANAGE_GROUP},ou=users,dc=redhat,dc=com",
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
    }
}

STATIC_ROOT = "/var/www/osidb/static/"
STATIC_URL = "/static/"

INSTALLED_APPS += ["osidb.tests"]

# Setup rotation logging into filesystem
LOG_FILE_SIZE_1KB = 1024 * 3  # 1kb
LOG_FILE_SIZE_1MB = LOG_FILE_SIZE_1KB * LOG_FILE_SIZE_1KB
LOG_FILE_SIZE_10MB = LOG_FILE_SIZE_1MB * 10
LOG_FILE_COUNT = 3
LOG_FILE_PATH = "/opt/app-root/src/log"

# LOGGING["handlers"]["celery"] = {
#     "class": "logging.handlers.RotatingFileHandler",
#     "formatter": "verbose_celery",
#     "filename": f"{LOG_FILE_PATH}/local-celery.log",
#     "maxBytes": LOG_FILE_SIZE_1KB,
#     "backupCount": LOG_FILE_COUNT,
# }
# LOGGING["handlers"]["console"] = {
#     "level": "INFO",
#     "class": "logging.handlers.RotatingFileHandler",
#     "formatter": "verbose",
#     "filename": f"{LOG_FILE_PATH}/local-django.log",
#     "maxBytes": LOG_FILE_SIZE_1KB,
#     "backupCount": LOG_FILE_COUNT,
# }
from logging.handlers import DEFAULT_TCP_LOGGING_PORT, SocketHandler

from osidb.helpers import JSONSocketHandler

LOGGING["handlers"]["celery"] = {
    "class": "osidb.helpers.JSONSocketHandler",
    "formatter": "verbose_celery",
    "host": "logstash",  # The IP of the log receiver
    "port": "5140",  # The port of the log receiver
    "logfile": "celery.log",
    # "fallback_logfile": f"{LOG_FILE_PATH}/local-celery.log"
    # "filename": f"{LOG_FILE_PATH}/local-django.log",
    # "maxBytes": LOG_FILE_SIZE_1KB,
    # "backupCount": LOG_FILE_COUNT,
}
LOGGING["handlers"]["console"] = {
    "level": "INFO",
    "class": "osidb.helpers.JSONSocketHandler",
    "formatter": "verbose",
    "host": "logstash",  # The IP of the log receiver
    "port": "5140",  # The port of the log receiver
    "logfile": "django.log",
    # "fallback_logfile": f"{LOG_FILE_PATH}/local-django.log"
    # "filename": f"{LOG_FILE_PATH}/local-django.log",
    # "maxBytes": LOG_FILE_SIZE_1KB,
    # "backupCount": LOG_FILE_COUNT,
}
# LOGGING["handlers"]["console"] = {
#     "level": "INFO",
#     "class": "osidb.helpers.JSONSocketHandler",
#     "formatter": "verbose",
#     "host": "log-listener",  # The IP of the log receiver
#     "port": "5141",  # The port of the log receiver
#     # "filename": f"{LOG_FILE_PATH}/local-django.log",
#     # "maxBytes": LOG_FILE_SIZE_1KB,
#     # "backupCount": LOG_FILE_COUNT,
# }
