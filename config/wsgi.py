"""
WSGI config for config project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

from osidb.telemetry import instrument_django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Must run before get_wsgi_application() builds WSGIHandler, see
# instrument_django()'s docstring.
instrument_django()

application = get_wsgi_application()
