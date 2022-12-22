from config.settings import *

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

DATABASES = {
    "default": {
        "NAME": get_env("OSIDB_DB_NAME", default="osidb"),
        "USER": get_env("OSIDB_DB_USER", default="osidb_manage_user"),
        "PASSWORD": get_env("OSIDB_DB_PASSWORD"),
        "HOST": get_env("OSIDB_DB_HOST", default="localhost"),
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
    }
}
