"""
Former OSIM API endpoints marked as deprecated
"""

import logging

from drf_spectacular.utils import extend_schema

from apps.workflows import api

logger = logging.getLogger(__name__)


@extend_schema(deprecated=True)
class index(api.index):
    """deprecated osim index API endpoint"""


@extend_schema(deprecated=True)
class healthy(api.healthy):
    """deprecated osim unauthenticated health check API endpoint"""


@extend_schema(deprecated=True)
class adjust(api.adjust):
    """deprecated osim adjustion API endpoint"""


@extend_schema(deprecated=True)
class promote(api.promote):
    """deprecated osim promote API endpoint"""


@extend_schema(deprecated=True)
class reject(api.reject):
    """deprecated osim reject API endpoint"""


@extend_schema(deprecated=True)
class classification(api.classification):
    """deprecated osim classification API endpoint"""


@extend_schema(deprecated=True)
class workflows(api.workflows):
    """deprecated osim info API endpoint"""
