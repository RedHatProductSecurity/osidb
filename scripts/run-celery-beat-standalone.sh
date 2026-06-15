#!/usr/bin/env bash

rm -f /tmp/celery_beat.pid
exec ddtrace-run celery -A config beat -S redbeat.RedBeatScheduler
