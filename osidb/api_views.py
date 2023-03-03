"""
implement osidb rest api views
"""

import logging
from urllib.parse import urljoin

import pkg_resources
from django.conf import settings
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from packageurl import PackageURL
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet, ViewSet

from .constants import OSIDB_API_VERSION, PYPI_URL, URL_REGEX
from .filters import AffectFilter, FlawFilter, TrackerFilter
from .models import Affect, Flaw, Tracker
from .serializer import (
    AffectSerializer,
    FlawSerializer,
    TrackerSerializer,
    UserSerializer,
)
from .validators import CVE_RE_STR

logger = logging.getLogger(__name__)


@api_view(["GET"])
@permission_classes((AllowAny,))
def healthy(request: Request) -> Response:
    """unauthenticated view providing healthcheck on osidb service"""
    return Response()


class StatusView(APIView):
    """authenticated view containing status osidb service"""

    permission_classes = [IsAuthenticatedOrReadOnly]

    @extend_schema(
        responses={
            200: {
                "type": "object",
                "properties": {
                    "osidb_service": {"type": "object"},
                    "osidb_data": {
                        "type": "object",
                        "properties": {"flaw_count": {"type": "integer"}},
                    },
                },
            }
        }
    )
    def get(self, request, *args, **kwargs):
        """HTTP get /status"""
        return Response(
            {
                "osidb_service": {},
                "osidb_data": {"flaw_count": Flaw.objects.all().count()},
            }
        )


class ManifestView(APIView):
    """authenticated view containing project manifest information"""

    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request, *args, **kwargs):
        """HTTP get /manifest"""
        SKIP = ["prodsec"]  # packages to remain unlisted
        packages = []

        for pkg in pkg_resources.working_set:
            if pkg.key not in SKIP:
                home_page = next(
                    (
                        line
                        for line in pkg._get_metadata(pkg.PKG_INFO)
                        if line.startswith("Home-page")
                    ),
                    "",
                )
                home_page_url = URL_REGEX.search(home_page)
                home_page_url = home_page_url.group(0) if home_page_url else None
                purl = PackageURL(type="pypi", name=pkg.key, version=pkg.version)
                # PyPI treats '-' and '_' as the same character and is not case sensitive. A PyPI package
                # name must be lowercased with underscores replaced with a dash (e.g. 'apscheduler'). A
                # project name may contain the original case and underscores (e.g. 'APScheduler').
                entry = {
                    "pkg_name": pkg.key,
                    "project_name": pkg.project_name,
                    "version": pkg.version,
                    "source": urljoin(PYPI_URL, pkg.project_name),
                    "home_page": home_page_url,
                    "purl": purl.to_string(),
                }
                packages.append(entry)

        return Response({"packages": packages})


def get_valid_http_methods(cls: ViewSet, excluded: list[str] = None) -> list[str]:
    """
    Removes blacklisted and unsafe HTTP methods from a view if necessary.
    Optionally also removes given excluded methods.

    Blacklisted HTTP methods can be defined in the django settings, unsafe HTTP
    methods will be removed if the app is running in read-only mode, by setting
    the OSIDB_READONLY_MODE env variable to "1".

    :param cls: The ViewSet class from which http_method_names are inherited
    :param excluded: A list of exlicitly excluded HTTP methods.
    :return: A list of valid HTTP methods that a ViewSet will accept
    """
    base_methods = cls.http_method_names
    excluded_methods = [] if excluded is None else excluded
    unsafe_methods = (
        "patch",
        "post",
        "put",
        "delete",
        "connect",
        "trace",
    )
    valid_methods = []
    for method in base_methods:
        if method in excluded_methods:
            continue
        if method in settings.BLACKLISTED_HTTP_METHODS:
            continue
        if settings.READONLY_MODE and method in unsafe_methods:
            continue
        valid_methods.append(method)
    return valid_methods


# reused below among multiple CRUD methods
id_param = OpenApiParameter(
    "id",
    type=str,
    location=OpenApiParameter.PATH,
    description=(
        "A string representing either the internal OSIDB UUID of the Flaw resource "
        "or the CVE number corresponding to a Flaw"
    ),
)


@extend_schema_view(
    list=extend_schema(
        parameters=[
            OpenApiParameter(
                "include_fields",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Include only specified fields in the response. "
                    "Multiple values may be separated by commas. Dot notation "
                    "can be used to filter on related model fields. "
                    "Example: `include_fields=uuid,affects.uuid,affects.trackers.uuid`"
                ),
            ),
            OpenApiParameter(
                "exclude_fields",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Exclude specified fields from the response. "
                    "Multiple values may be separated by commas. Dot notation "
                    "can be used to filter on related model fields. "
                    "Example: `exclude_fields=uuid,affects.uuid,affects.trackers.uuid`"
                ),
            ),
            OpenApiParameter(
                "include_meta_attr",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Specify which keys from meta_attr field should be retrieved, "
                    "multiple values may be separated by commas. "
                    "Dot notation can be used to specify meta_attr keys on related models. "
                    "Example: `include_meta_attr=bz_id,affects.ps_module,affects.trackers.bz_id`"
                    "Use wildcards eg. `include_meta_attr=*,affects.*,affects.trackers.*` "
                    "for retrieving all the keys from meta_attr. "
                    "Omit this parameter to not include meta_attr fields at all. "
                ),
            ),
            OpenApiParameter(
                "flaw_meta_type",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Include flaw metas with specified type only, "
                    "multiple values may be separated by commas. "
                ),
            ),
            OpenApiParameter(
                "tracker_ids",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Filter only Flaws which are related to specified Trackers (through "
                    "Affects). Multiple tracker IDs may be separated by commas. Also only "
                    "Affects that have the specified Trackers related will be shown."
                ),
            ),
        ],
    ),
    retrieve=extend_schema(
        responses=FlawSerializer,
        parameters=[
            OpenApiParameter(
                "include_fields",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Include only specified fields in the response. "
                    "Multiple values may be separated by commas. Dot notation "
                    "can be used to filter on related model fields. "
                    "Example: `include_fields=uuid,affects.uuid,affects.trackers.uuid`"
                ),
            ),
            OpenApiParameter(
                "exclude_fields",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Exclude specified fields from the response. "
                    "Multiple values may be separated by commas. Dot notation "
                    "can be used to filter on related model fields. "
                    "Example: `exclude_fields=uuid,affects.uuid,affects.trackers.uuid`"
                ),
            ),
            OpenApiParameter(
                "include_meta_attr",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Specify which keys from meta_attr field should be retrieved, "
                    "multiple values may be separated by commas. "
                    "Dot notation can be used to specify meta_attr keys on related models. "
                    "Example: `include_meta_attr=bz_id,affects.ps_module,affects.trackers.bz_id`"
                    "Use wildcards eg. `include_meta_attr=*,affects.*,affects.trackers.*` "
                    "for retrieving all the keys from meta_attr. "
                    "Omit this parameter to not include meta_attr fields at all. "
                ),
            ),
            OpenApiParameter(
                "flaw_meta_type",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Include flaw metas with specified type only, "
                    "multiple values may be separated by commas. "
                ),
            ),
            OpenApiParameter(
                "tracker_ids",
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
                description=(
                    "Filter only Flaws which are related to specified Trackers (through "
                    "Affects). Multiple tracker IDs may be separated by commas. Also only "
                    "Affects that have the specified Trackers related will be shown."
                ),
            ),
            id_param,
        ],
    ),
    destroy=extend_schema(
        responses=FlawSerializer,
        parameters=[id_param],
    ),
    update=extend_schema(
        responses=FlawSerializer,
        parameters=[id_param],
    ),
)
class FlawView(ModelViewSet):
    queryset = Flaw.objects.all()
    serializer_class = FlawSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = FlawFilter
    lookup_url_kwarg = "id"
    # there is neigher a way to really delete a flaw in Bugzilla
    # nor a defined procedure to make a flaw being considered deleted
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete"])
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get_object(self):
        # from https://www.django-rest-framework.org/api-guide/generic-views/#methods
        """get flaw object instance"""
        queryset = self.get_queryset()
        pk = self.kwargs[self.lookup_url_kwarg]
        if CVE_RE_STR.match(pk):
            obj = get_object_or_404(queryset, cve_id=pk)
        else:
            obj = get_object_or_404(queryset, uuid=pk)
        self.check_object_permissions(self.request, obj)
        return obj

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        response.data = {
            "uuid": response.data["uuid"],
            "state": response.data["state"],
        }
        response["Location"] = f"/api/{OSIDB_API_VERSION}/flaws/{response.data['uuid']}"
        return response


@extend_schema(
    responses={
        200: {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "email": {"type": "string"},
                "groups": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "profile": {
                    "type": "object",
                    "properties": {
                        "bz_user_id": {"type": "string"},
                        "jira_user_id": {"type": "string"},
                    },
                },
            },
        }
    }
)
@api_view(["GET"])
@permission_classes((IsAuthenticatedOrReadOnly,))
def whoami(request: Request) -> Response:
    """View that provides information about the currently logged-in user"""
    return Response(UserSerializer(request.user).data)


class AffectView(ModelViewSet):
    queryset = Affect.objects.all()
    serializer_class = AffectSerializer
    filterset_class = AffectFilter
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]

    def perform_destroy(self, instance):
        """
        override the default behavior to proxy the delete to Bugzilla
        """
        flaw = instance.flaw
        instance.delete()

        # serialize Bugzilla API key and check it was provided
        serializer = self.get_serializer(data=self.request.data)
        bz_api_key = serializer.initial_data.get("bz_api_key")
        if bz_api_key is None:
            raise ValidationError({"bz_api_key": "Field is required"})

        flaw.save(bz_api_key=bz_api_key)


# until we implement tracker write operations
# we have to consider them as read-only
class TrackerView(ReadOnlyModelViewSet):
    queryset = Tracker.objects.all()
    serializer_class = TrackerSerializer
    filterset_class = TrackerFilter
    http_method_names = get_valid_http_methods(ReadOnlyModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
