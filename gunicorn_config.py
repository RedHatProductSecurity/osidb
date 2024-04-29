from config import get_env

bind = "0.0.0.0:8000"
worker_class = "gthread"
workers = 3
threads = 10
proc_name = "osidb"
timeout = 300
reuse_port = True

errorlog = "-"
# Make sure wsgi.url_scheme gets set to HTTPS, by trusting the X_FORWARDED_PROTO header set by the proxy
forwarded_allow_ips = "*"

# the gunicorn default for worker_tmp_dir is /tmp which may not reliably
# exist in deployment environments, setting to shm filesystem avoids this
worker_tmp_dir = "/dev/shm"

if get_env() in ["stage", "prod", "ci"]:
    preload_app = True
    graceful_timeout = 800  # if a restart must happen then let it be graceful
    keepalive = 60  # specifically this should be a value larger then nginx setting
else:
    # Support hot-reloading of Gunicorn / Django when files change in dev/local/shell
    reload = True
