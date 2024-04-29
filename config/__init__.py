from __future__ import absolute_import

import os

import django

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
# flake8 code F401 (unused import) being ignored as
# this piece of code is necessary for celery to work
from .celery import app as celery_app  # noqa: F401

django.setup()
__all__ = ["osidb"]


def get_env() -> str:
    # return "config.settings.env" -> ["config", "settings", "env"] -> "env"
    return os.getenv("DJANGO_SETTINGS_MODULE", "").split("_")[-1]
