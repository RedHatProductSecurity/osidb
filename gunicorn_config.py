bind = "0.0.0.0:8000"
workers = 4
proc_name = "osidb"
timeout = 300

accesslog = "-"
errorlog = "-"
# Make sure wsgi.url_scheme gets set to HTTPS, by trusting the X_FORWARDED_PROTO header set by the proxy
forwarded_allow_ips = "*"
