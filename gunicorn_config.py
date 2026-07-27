from osidb.helpers import get_execution_env
from osidb.telemetry import configure_telemetry

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

if get_execution_env() in ["stage", "prod", "ci"]:
    preload_app = True
    graceful_timeout = 800  # if a restart must happen then let it be graceful
    # Prevent HAProxy from sending packets to a closed connection
    # where the worker has definitely timed out.
    keepalive = timeout + 1
else:
    # Support hot-reloading of Gunicorn / Django when files change in dev/local/shell
    reload = True


def post_fork(server, worker):
    # Runs once per worker right after fork, for both preload_app=True and
    # False. Configuring telemetry here (rather than at wsgi/asgi import
    # time) avoids setting up the OTLP exporter's background thread/gRPC
    # channel in the preloaded master process, where it wouldn't survive
    # the subsequent fork into workers. (Django's own instrumentation is
    # registered earlier, in wsgi.py, since it must run before
    # get_wsgi_application() builds WSGIHandler.)
    try:
        configure_telemetry()
    except Exception:
        # Don't take a worker down over telemetry; run without it instead.
        worker.log.exception("Failed to configure telemetry")
