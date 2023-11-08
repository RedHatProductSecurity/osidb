#!/usr/bin/env bash

rm -f /tmp/celery_beat.pid
celery -A config beat
