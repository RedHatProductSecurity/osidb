from os import getenv

from osidb.helpers import get_execution_env

bind = "0.0.0.0:8000"
worker_class = "gthread"
workers = 3
threads = 10
proc_name = "osidb"
timeout = 300
reuse_port = True

errorlog = "-"

# Set GUNICORN_FORWARDED_ALLOW_IPS environment variable to the HAProxy IP/subnet.
# Examples: "10.0.1.12", "10.0.0.0/8", "127.0.0.1"
execution_env = get_execution_env()
if execution_env in ["stage", "prod", "uat"]:
    # Production environments: restrict to specific proxy IPs (configured via env var)
    # Default to localhost to force explicit configuration
    forwarded_allow_ips = getenv("GUNICORN_FORWARDED_ALLOW_IPS", "127.0.0.1")
else:
    # Local/dev/ci environments: allow all for development convenience
    forwarded_allow_ips = getenv("GUNICORN_FORWARDED_ALLOW_IPS", "*")

# the gunicorn default for worker_tmp_dir is /tmp which may not reliably
# exist in deployment environments, setting to shm filesystem avoids this
worker_tmp_dir = "/dev/shm"

if execution_env in ["stage", "prod", "ci"]:
    preload_app = True
    graceful_timeout = 800  # if a restart must happen then let it be graceful
    keepalive = 60  # specifically this should be a value *smaller* then nginx setting
else:
    # Support hot-reloading of Gunicorn / Django when files change in dev/local/shell
    reload = True
