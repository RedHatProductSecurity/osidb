from rest_framework.viewsets import ReadOnlyModelViewSet

from apps.taskman.filters import FlawTaskFilterSet
from apps.taskman.models import FlawTask
from apps.taskman.serializers import FlawTaskSerializer
from osidb.helpers import get_valid_http_methods


class FlawTaskView(ReadOnlyModelViewSet):
    queryset = FlawTask.objects.select_related("owner__profile", "flaw")
    serializer_class = FlawTaskSerializer
    filterset_class = FlawTaskFilterSet
    http_method_names = get_valid_http_methods(ReadOnlyModelViewSet)
