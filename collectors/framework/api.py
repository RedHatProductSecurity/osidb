"""
collector API endpoints
"""
import logging

from drf_spectacular.utils import extend_schema
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from osidb.api_views import RudimentaryUserPathLoggingMixin

from .models import CollectorFramework

logger = logging.getLogger(__name__)


class index(RudimentaryUserPathLoggingMixin, APIView):
    """index API endpoint"""

    @extend_schema(
        responses={
            200: {
                "type": "object",
                "properties": {
                    "index": {"type": "array", "items": {"type": "string"}},
                },
            }
        }
    )
    def get(self, request, *args, **kwargs):
        """index API endpoint listing available collector API endpoints"""
        logger.info("getting index")
        from .urls import urlpatterns

        return Response(
            {
                "index": [f"/{url.pattern}" for url in urlpatterns],
            }
        )


class healthy(RudimentaryUserPathLoggingMixin, APIView):
    """unauthenticated collector health check API endpoint"""

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        """
        unauthenticated health check API endpoint
        """
        logger.info("getting health status")
        return Response()


class status(RudimentaryUserPathLoggingMixin, APIView):
    """collector status API endpoint"""

    @extend_schema(
        responses={
            200: {
                "type": "object",
                "properties": {
                    "collectors": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "string",
                                    "enum": ["EMPTY", "PARTIAL", "COMPLETE"],
                                },
                                "depends_on": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "error": {"type": "object", "nullable": True},
                                "is_complete": {"type": "boolean"},
                                "is_up2date": {"type": "boolean"},
                                "data_models": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "state": {
                                    "type": "string",
                                    "enum": ["PENDING", "BLOCKED", "READY", "RUNNING"],
                                },
                                "updated_until": {
                                    "type": "string",
                                    "format": "date-time",
                                },
                            },
                        },
                    },
                },
            }
        }
    )
    def get(self, request, *args, **kwargs):
        """
        get the overall status of all collectors and the collected data
        """
        logger.info("getting collector status")

        return Response(
            {
                "collectors": {
                    # TODO implement collector serializer
                    name: {
                        "data": collector.data_state,
                        "depends_on": collector.depends_on,
                        "error": collector.error,
                        "is_complete": collector.is_complete,
                        "is_up2date": collector.is_up2date,
                        "data_models": collector.data_models,
                        "state": collector.collector_state,
                        "updated_until": collector.updated_until_dt,
                    }
                    # the official collectors are always in the tasks directory
                    for name, collector in CollectorFramework.collectors().items()
                    if "tasks" in name
                },
            }
        )
