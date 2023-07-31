from config.settings import *

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

# Use the same env vars, but provide a default if unset
DATABASES["default"]["USER"] = get_env("OSIDB_DB_USER", default="osidb_manage_user")
DATABASES["default"]["HOST"] = get_env("OSIDB_DB_HOST", default="localhost")
