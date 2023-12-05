#!/usr/bin/env bash

rm -f /tmp/celery_beat.pid
exec celery -A config beat -S redbeat.RedBeatScheduler
