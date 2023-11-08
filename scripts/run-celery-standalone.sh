#!/usr/bin/env bash

rm -f /tmp/celery_worker.pid
celery -A config worker --pidfile /tmp/celery_worker.pid -f celery.log --loglevel DEBUG -P gevent --concurrency=1 -Q slow,fast -E --max-tasks-per-child=200
