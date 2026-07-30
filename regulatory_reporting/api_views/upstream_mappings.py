from django.shortcuts import get_object_or_404
from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticatedOrReadOnly

from osidb.api_views import RudimentaryUserPathLoggingMixin, get_valid_http_methods
from osidb.models import Flaw
from regulatory_reporting.models.upstream import FlawUpstreamMapping
from regulatory_reporting.serializers.upstream import FlawUpstreamMappingSerializer


class FlawUpstreamMappingListCreateView(
    RudimentaryUserPathLoggingMixin,
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    viewsets.GenericViewSet,
):
    """
    API endpoint for listing and creating flaw-to-upstream mappings
    """

    http_method_names = get_valid_http_methods(
        viewsets.GenericViewSet, excluded=["put", "patch", "delete"]
    )
    serializer_class = FlawUpstreamMappingSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get_flaw(self):
        return get_object_or_404(Flaw, uuid=self.kwargs["flaw_uuid"])

    def get_queryset(self):
        return FlawUpstreamMapping.objects.filter(flaw=self.get_flaw())

    def perform_create(self, serializer):
        serializer.save(flaw=self.get_flaw())


class FlawUpstreamMappingDetailView(
    RudimentaryUserPathLoggingMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """
    API endpoint for updating and deleting a single flaw-to-upstream mapping.
    """

    http_method_names = get_valid_http_methods(
        viewsets.GenericViewSet, excluded=["get", "post", "patch"]
    )
    queryset = FlawUpstreamMapping.objects.all()
    serializer_class = FlawUpstreamMappingSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    lookup_url_kwarg = "mapping_uuid"
    lookup_field = "uuid"
