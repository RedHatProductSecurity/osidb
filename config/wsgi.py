"""
WSGI config for config project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/howto/deployment/wsgi/
"""

import os

import psycogreen.gevent
from django.core.wsgi import get_wsgi_application
from gevent import monkey

# Apply psycogreen to make psycopg2 play nicely with gevent
# TODO: remove when switching to psycopg3
psycogreen.gevent.patch_psycopg()

# Use gevent to patch Django as well
monkey.patch_all()

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_wsgi_application()
