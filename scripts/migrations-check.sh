#!/usr/bin/env bash
make check-venv-active
./manage.py makemigrations --check --dry-run --settings=config.settings_ci &> /dev/null
