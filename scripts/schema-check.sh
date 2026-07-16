#!/usr/bin/env bash
if [[ -z "${TOX_ENV_NAME}" ]]; then
    make check-venv-active
fi
./manage.py spectacular --file openapi.yml --settings=config.settings_local &> /dev/null && git diff --quiet openapi.yml &> /dev/null