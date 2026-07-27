"""
ASGI config for config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

from osidb.telemetry import instrument_django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Must run before get_asgi_application() builds the handler, see
# instrument_django()'s docstring.
instrument_django()

application = get_asgi_application()
