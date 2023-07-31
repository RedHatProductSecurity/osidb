import ldap
from django_auth_ldap.config import GroupOfNamesType, LDAPSearch

from .settings import *

# SECURITY WARNING: keep the secret key used in production/stage secret!
SECRET_KEY = get_random_secret_key()  # pragma: allowlist secret

# When testing email functionality locally, you can start a debugging SMTP server that
# prints out the received emails with:
# python -m smtpd -n -c DebuggingServer localhost:1025
# with podman-compose add a service such as:
#  osidb-mail:
#    container_name: osidb-mail
#    image: osidb
#    command: python3 -m smtpd -n -c DebuggingServer localhost:1025
#    ports:
#      - "1025:1025"
EMAIL_PORT = 1025
EMAIL_HOST = "localhost"
EMAIL_USE_TLS = False

# Minimal group for read access of public flaws in OSIDB
PUBLIC_READ_GROUPS = ["data-prodsec"]
# Minimal group for write access of public flaws in OSIDB
PUBLIC_WRITE_GROUP = "data-prodsec-write"
# Minimal group for read access of embargoed flaws in OSIDB
EMBARGO_READ_GROUP = "data-topsecret"
# Minimal group for write access of embargoed flaws in OSIDB
EMBARGO_WRITE_GROUP = "data-topsecret-write"
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

AUTH_LDAP_REQUIRE_GROUP = f"cn={PUBLIC_READ_GROUPS[0]},ou=users,dc=redhat,dc=com"

AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_active": f"cn={PUBLIC_READ_GROUPS[0]},ou=users,dc=redhat,dc=com",
    "is_staff": f"cn={SERVICE_MANAGE_GROUP},ou=users,dc=redhat,dc=com",
    "is_superuser": f"cn={SERVICE_MANAGE_GROUP},ou=users,dc=redhat,dc=com",
}

# Completely redefine instead of reusing certain parts
# Since name / user / password / etc. are all different
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
    }
}

LOGOUT_REDIRECT_URL = "/"  # this is the name of the url
LOGIN_REDIRECT_URL = "/"  # this is the name of the url

STATIC_ROOT = "/var/www/osidb/static/"
STATIC_URL = "/static/"

INSTALLED_APPS += ["osidb.tests"]
