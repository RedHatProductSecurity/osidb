bind = "0.0.0.0:8000"
workers = 12
worker_class = "gevent"
proc_name = "osidb"
timeout = 300


def post_fork(server, worker):
    from psycogreen.gevent import patch_psycopg

    patch_psycopg()
    worker.log.info("Made psycopg2 green")


errorlog = "-"
# Make sure wsgi.url_scheme gets set to HTTPS, by trusting the X_FORWARDED_PROTO header set by the proxy
forwarded_allow_ips = "*"
