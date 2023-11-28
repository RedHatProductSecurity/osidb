bind = "0.0.0.0:8000"
worker_class = "gthread"
workers = 3
threads = 10
proc_name = "osidb"
timeout = 300
graceful_timeout = 800
reuse_port = True
preload_app = True

errorlog = "-"
# Make sure wsgi.url_scheme gets set to HTTPS, by trusting the X_FORWARDED_PROTO header set by the proxy
forwarded_allow_ips = "*"
