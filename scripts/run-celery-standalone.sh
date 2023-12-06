#!/usr/bin/env bash

rm -f /tmp/celery_worker.pid
exec celery -A config worker --pidfile /tmp/celery_worker.pid -f celery.log --loglevel DEBUG --concurrency=3 -Q slow,fast -E
