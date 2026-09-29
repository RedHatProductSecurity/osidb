#!/usr/bin/env bash

rm -f /tmp/celery_worker.pid
# During migration: consume from both low and collectors queues to avoid task loss
exec celery -A config worker --pool=gevent --pidfile /tmp/celery_worker.pid -f celery.log --loglevel DEBUG --concurrency=50 -E -Q low,collectors
