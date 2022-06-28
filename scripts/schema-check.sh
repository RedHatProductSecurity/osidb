#!/usr/bin/env bash
make check-venv-active
./manage.py spectacular --file openapi.yml --settings=config.settings_local &> /dev/null && git diff --quiet openapi.yml &> /dev/null
