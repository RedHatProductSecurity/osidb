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
PUBLIC_READ_GROUPS = ["osidb-prod-public-read", "red-hat-product-security"]
# Minimal group for write access of public flaws in OSIDB
PUBLIC_WRITE_GROUP = "osidb-prod-public-write"
# Minimal group for read access of embargoed flaws in OSIDB
EMBARGO_READ_GROUP = "osidb-prod-embargo-read"
# Minimal group for write access of embargoed flaws in OSIDB
EMBARGO_WRITE_GROUP = "osidb-prod-embargo-write"
# Minimal group for managing the OSIDB service
SERVICE_MANAGE_GROUP = "osidb-prod-manage"

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
        "NAME": get_env("OSIDB_DB_NAME", default="osidb"),
        "USER": get_env("OSIDB_DB_USER"),
        "PASSWORD": get_env("OSIDB_DB_PASSWORD"),
        "HOST": get_env("OSIDB_DB_HOST"),
        "PORT": get_env("OSIDB_DB_PORT", default="5432"),
        "ENGINE": "psqlextra.backend",
        "OPTIONS": {"sslmode": "require"},
    }
}

LOGOUT_REDIRECT_URL = "/"
LOGIN_REDIRECT_URL = "/"

STATIC_ROOT = "/opt/app-root/static/"
STATIC_URL = "/static/"

# Celery settings

REDIS_PASSWORD = get_env("OSIDB_REDIS_PASSWORD")
CELERY_BROKER_URL = CELERY_RESULT_BACKEND = f"rediss://:{REDIS_PASSWORD}@redis:6379/"
CELERY_BROKER_USE_SSL = {
    "ssl_keyfile": "/opt/app-root/etc/redis/certs/osidb-redis.key",
    "ssl_certfile": "/opt/app-root/etc/redis/certs/osidb-redis.crt",
    "ssl_ca_certs": "/opt/app-root/etc/redis/certs/osidb-redis-ca.crt",
    "ssl_cert_reqs": ssl.CERT_REQUIRED,
}
CELERY_REDIS_BACKEND_USE_SSL = {
    "ssl_keyfile": "/opt/app-root/etc/redis/certs/osidb-redis.key",
    "ssl_certfile": "/opt/app-root/etc/redis/certs/osidb-redis.crt",
    "ssl_ca_certs": "/opt/app-root/etc/redis/certs/osidb-redis-ca.crt",
    "ssl_cert_reqs": ssl.CERT_REQUIRED,
}

# Kerberos + LDAP Auth
INSTALLED_APPS += [
    "krb5_auth",
]
AUTHENTICATION_BACKENDS += [
    "krb5_auth.backend.LDAPRemoteUser",
    # TODO: remove and replace by krb auth for admin interface
    "django_auth_ldap.backend.LDAPBackend",
]
KRB5_HOSTNAME = "osidb.prodsec.redhat.com"

ERRATA_TOOL_SERVER = "https://errata.engineering.redhat.com"
ERRATA_TOOL_XMLRPC_BASE_URL = f"{ERRATA_TOOL_SERVER}/errata/errata_service"
