#!/usr/bin/env bash

rm -f /tmp/celery_worker.pid
exec ddtrace-run celery -A config worker --pidfile /tmp/celery_worker.pid -f celery.log --loglevel DEBUG --concurrency=5 -E -Q default
