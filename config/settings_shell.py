from config.settings import *

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

DATABASES = {
    "default": {
        "NAME": get_env("OSIDB_DB_NAME", default="osidb"),
        "USER": get_env("OSIDB_DB_USER", default="osidb_manage_user"),
        "PASSWORD": get_env("OSIDB_DB_PASSWORD"),
        "HOST": get_env("OSIDB_DB_HOST", default="localhost"),
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
    }
}

STATIC_ROOT = "/opt/app-root/static/"
STATIC_URL = "/static/"

# Email configuration

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
