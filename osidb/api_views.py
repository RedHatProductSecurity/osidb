"""
implement osidb rest api views
"""

import logging
from typing import Type
from urllib.parse import urljoin

import pkg_resources
from django.conf import settings
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from packageurl import PackageURL
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet, ViewSet, ViewSetMixin

from .constants import OSIDB_API_VERSION, PYPI_URL, URL_REGEX
from .filters import (
    AffectCVSSFilter,
    AffectFilter,
    FlawAcknowledgmentFilter,
    FlawCommentFilter,
    FlawCVSSFilter,
    FlawFilter,
    FlawPackageVersionFilter,
    FlawReferenceFilter,
    TrackerFilter,
)
from .models import Affect, AffectCVSS, Flaw, Tracker
from .serializer import (
    AffectCVSSPostSerializer,
    AffectCVSSPutSerializer,
    AffectCVSSSerializer,
    AffectPostSerializer,
    AffectSerializer,
    FlawAcknowledgmentPostSerializer,
    FlawAcknowledgmentPutSerializer,
    FlawAcknowledgmentSerializer,
    FlawCommentPostSerializer,
    FlawCommentSerializer,
    FlawCVSSPostSerializer,
    FlawCVSSPutSerializer,
    FlawCVSSSerializer,
    FlawPackageVersionPostSerializer,
    FlawPackageVersionPutSerializer,
    FlawPackageVersionSerializer,
    FlawPostSerializer,
    FlawReferencePostSerializer,
    FlawReferencePutSerializer,
    FlawReferenceSerializer,
    FlawSerializer,
    TrackerPostSerializer,
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


include_fields_param = OpenApiParameter(
    "include_fields",
    type={"type": "array", "items": {"type": "string"}},
    location=OpenApiParameter.QUERY,
    description=(
        "Include only specified fields in the response. "
        "Multiple values may be separated by commas. Dot notation "
        "can be used to filter on related model fields. "
        "Example: `include_fields=field,related_model_field.field`"
    ),
)


exclude_fields_param = OpenApiParameter(
    "exclude_fields",
    type={"type": "array", "items": {"type": "string"}},
    location=OpenApiParameter.QUERY,
    description=(
        "Exclude specified fields from the response. "
        "Multiple values may be separated by commas. Dot notation "
        "can be used to filter on related model fields. "
        "Example: `exclude_fields=field,related_model_field.field`"
    ),
)

include_meta_attr = OpenApiParameter(
    "include_meta_attr",
    type={"type": "array", "items": {"type": "string"}},
    location=OpenApiParameter.QUERY,
    description=(
        "Specify which keys from meta_attr field should be retrieved, "
        "multiple values may be separated by commas. "
        "Dot notation can be used to specify meta_attr keys on related models. "
        "Example: `include_meta_attr=key,related_model.key`"
        "Use wildcards eg. `include_meta_attr=*,related_model.*` "
        "for retrieving all the keys from meta_attr. "
        "Omit this parameter to not include meta_attr fields at all. "
    ),
)

flaw_id = OpenApiParameter(
    "flaw_id",
    type=str,
    location=OpenApiParameter.PATH,
    description=(
        "A string representing either the internal OSIDB UUID of the Flaw resource "
        "or the CVE number corresponding to a Flaw"
    ),
)

bz_api_key_param = OpenApiParameter(
    name="Bugzilla-Api-Key",
    required=True,
    type=str,
    location=OpenApiParameter.HEADER,
    description="User generated api key for Bugzilla authentication.",
)

jira_api_key_param = OpenApiParameter(
    name="Jira-Api-Key",
    required=True,
    type=str,
    location=OpenApiParameter.HEADER,
    description="User generated api key for Jira authentication.",
)


def jira_api_key_extend_schema_view(
    cls: Type[ViewSetMixin],
) -> Type[ViewSetMixin]:
    """
    Decorator which adds `Jira-Api-Key` header parameter description
    into the schema for `create` and `update` methods
    """
    return (
        extend_schema_view(
            create=extend_schema(parameters=[jira_api_key_param]),
            update=extend_schema(parameters=[jira_api_key_param]),
        )
    )(cls)


def bz_api_key_extend_schema_view(
    cls: Type[ViewSetMixin],
) -> Type[ViewSetMixin]:
    """
    Decorator which adds `Bugzilla-Api-Key` header parameter description
    into the schema for `create` and `update` methods
    """
    return (
        extend_schema_view(
            create=extend_schema(parameters=[bz_api_key_param]),
            update=extend_schema(parameters=[bz_api_key_param]),
        )
    )(cls)


def include_meta_attr_extend_schema_view(cls: Type[ViewSetMixin]) -> Type[ViewSetMixin]:
    """
    Decorator which adds `include_meta_attr` query parameter description into the schema
    for `list` and `retrieve` methods
    """
    return (
        extend_schema_view(
            list=extend_schema(parameters=[include_meta_attr]),
            retrieve=extend_schema(parameters=[include_meta_attr]),
        )
    )(cls)


def include_exclude_fields_extend_schema_view(
    cls: Type[ViewSetMixin],
) -> Type[ViewSetMixin]:
    """
    Decorator which adds `include_fields` and `exclude_fields` query parameters description
    into the schema for `list` and `retrieve` methods
    """
    return (
        extend_schema_view(
            list=extend_schema(parameters=[include_fields_param, exclude_fields_param]),
            retrieve=extend_schema(
                parameters=[include_fields_param, exclude_fields_param]
            ),
        )
    )(cls)


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@bz_api_key_extend_schema_view
@jira_api_key_extend_schema_view
@extend_schema_view(
    list=extend_schema(
        parameters=[
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
            OpenApiParameter(
                "is_major_incident",
                type=OpenApiTypes.BOOL,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss2",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss2_score",
                type=OpenApiTypes.FLOAT,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss3",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss3_score",
                type=OpenApiTypes.FLOAT,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "nvd_cvss2",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "nvd_cvss3",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
        ],
    ),
    retrieve=extend_schema(
        responses=FlawSerializer,
        parameters=[
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
    create=extend_schema(
        request=FlawPostSerializer,
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
    queryset = Flaw.objects.prefetch_related("affects", "affects__trackers").all()
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


class SubFlawViewDestroyMixin:
    @extend_schema(
        responses={
            200: {},
        }
    )
    def destroy(self, request, *args, **kwargs):
        """
        Destroy the instance and proxy the delete to Bugzilla
        """
        bz_api_key = request.META.get("HTTP_BUGZILLA_API_KEY")
        if not bz_api_key:
            raise ValidationError({"Bugzilla-Api-Key": "This HTTP header is required."})
        instance = self.get_object()
        flaw = instance.flaw
        instance.delete()
        flaw.save(bz_api_key=bz_api_key)
        return Response(status=HTTP_200_OK)


class SubFlawViewGetMixin:
    def get_flaw(self):
        """
        Gets the flaw instance associated with the requested model instance.
        """
        pk = self.kwargs["flaw_id"]
        if CVE_RE_STR.match(pk):
            obj = get_object_or_404(Flaw, cve_id=pk)
        else:
            obj = get_object_or_404(Flaw, uuid=pk)
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        """
        Returns the requested model instances only for the specified flaw.
        """
        if getattr(self, "swagger_fake_view", False):
            # Required for autogeneration of parameters to openapi.yml because
            # get_queryset depends on "flaw" not available at schema generation
            # time. Documented in
            # https://drf-spectacular.readthedocs.io/en/latest/faq.html#my-get-queryset-depends-on-some-attributes-not-available-at-schema-generation-time
            return self.serializer_class.Meta.model.objects.none()
        flaw = self.get_flaw()
        return self.serializer_class.Meta.model.objects.filter(flaw=flaw)

    def get_serializer(self, *args, **kwargs):
        """
        Updates the serializer to contain also the flaw uuid.
        """
        if "data" in kwargs:
            # request.data can be immutable, depending on media type
            data = kwargs["data"].copy()
            # flaw is provided in URL, not in the request, so inject it for
            # the serializer and its validation
            data["flaw"] = str(self.get_flaw().uuid)
            kwargs["data"] = data
        return super().get_serializer(*args, **kwargs)


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawAcknowledgmentPostSerializer,
    ),
    update=extend_schema(
        request=FlawAcknowledgmentPutSerializer,
    ),
)
class FlawAcknowledgmentView(
    SubFlawViewDestroyMixin, SubFlawViewGetMixin, ModelViewSet
):
    serializer_class = FlawAcknowledgmentSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = FlawAcknowledgmentFilter


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawReferencePostSerializer,
    ),
    update=extend_schema(
        request=FlawReferencePutSerializer,
    ),
)
class FlawReferenceView(SubFlawViewDestroyMixin, SubFlawViewGetMixin, ModelViewSet):
    serializer_class = FlawReferenceSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = FlawReferenceFilter


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawCVSSPostSerializer,
    ),
    update=extend_schema(
        request=FlawCVSSPutSerializer,
    ),
)
class FlawCVSSView(SubFlawViewGetMixin, SubFlawViewDestroyMixin, ModelViewSet):
    serializer_class = FlawCVSSSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = FlawCVSSFilter


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


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        description="Create a new comment for a given flaw. Beware that freshly created comments "
        "are not guaranteed to keep their original UUIDs, especially if multiple "
        "comments are created simultaneously.",
        request=FlawCommentPostSerializer,
        parameters=[
            flaw_id,
        ],
    ),
    list=extend_schema(
        description="List existing comments for a given flaw. Beware that freshly created comments "
        "are not guaranteed to keep their original UUIDs, especially if multiple "
        "comments are created simultaneously.",
        parameters=[
            flaw_id,
            OpenApiParameter(
                "order",
                type=int,
                location=OpenApiParameter.QUERY,
                description=(
                    "Retrieve only FlawComment resource with the specified order number. "
                    "Regular flaw comments are numbered from 1 up."
                ),
            ),
        ],
    ),
    retrieve=extend_schema(
        description="Retrieve a single existing comments for a given flaw. Beware that freshly "
        "created comments are not guaranteed to keep their original UUIDs, especially "
        "if multiple comments are created simultaneously.",
        parameters=[
            flaw_id,
            OpenApiParameter(
                "comment_id",
                type=str,
                location=OpenApiParameter.PATH,
                description=(
                    "A string representing the internal OSIDB UUID of the FlawComment resource."
                ),
            ),
        ],
    ),
)
class FlawCommentView(SubFlawViewGetMixin, ModelViewSet):
    serializer_class = FlawCommentSerializer
    filterset_class = FlawCommentFilter
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete", "put"])
    permission_classes = [IsAuthenticatedOrReadOnly]
    lookup_url_kwarg = "comment_id"


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawPackageVersionPostSerializer,
    ),
    update=extend_schema(
        request=FlawPackageVersionPutSerializer,
    ),
)
class FlawPackageVersionView(
    SubFlawViewGetMixin, SubFlawViewDestroyMixin, ModelViewSet
):
    serializer_class = FlawPackageVersionSerializer
    filterset_class = FlawPackageVersionFilter
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@bz_api_key_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=AffectPostSerializer,
    ),
    list=extend_schema(
        parameters=[
            OpenApiParameter(
                "flaw__is_major_incident",
                type=OpenApiTypes.BOOL,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss2",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss2_score",
                type=OpenApiTypes.FLOAT,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss3",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
            OpenApiParameter(
                "cvss3_score",
                type=OpenApiTypes.FLOAT,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
        ],
    ),
)
class AffectView(SubFlawViewDestroyMixin, ModelViewSet):
    queryset = Affect.objects.all()
    serializer_class = AffectSerializer
    filterset_class = AffectFilter
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=AffectCVSSPostSerializer,
    ),
    update=extend_schema(
        request=AffectCVSSPutSerializer,
    ),
)
class AffectCVSSView(ModelViewSet):
    serializer_class = AffectCVSSSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = AffectCVSSFilter

    def get_affect(self):
        """
        Gets the affect associated with the given affect cvss.
        """
        _id = self.kwargs["affect_id"]
        obj = get_object_or_404(Affect, uuid=_id)
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        """
        Returns affect cvss scores only for the specified affect.
        """
        # This solves the issue described in the section "My get_queryset()
        # depends on some attributes not available at schema generation time" in
        # https://drf-spectacular.readthedocs.io/en/latest/faq.html
        if getattr(self, "swagger_fake_view", False):
            return AffectCVSS.objects.none()

        affect = self.get_affect()
        return AffectCVSS.objects.filter(affect=affect)

    def get_serializer(self, *args, **kwargs):
        """
        Updates the serializer to contain also the affect uuid.
        """
        if "data" in kwargs:
            data = kwargs["data"].copy()
            data["affect"] = str(self.get_affect().uuid)
            kwargs["data"] = data
        return super().get_serializer(*args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        Destroy the instance and proxy the delete to Bugzilla.
        """
        bz_api_key = request.META.get("HTTP_BUGZILLA_API_KEY")
        if not bz_api_key:
            raise ValidationError({"Bugzilla-Api-Key": "This HTTP header is required."})

        instance = self.get_object()
        affect = instance.affect
        instance.delete()
        affect.save(bz_api_key=bz_api_key)
        return Response(status=HTTP_200_OK)


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@bz_api_key_extend_schema_view
@jira_api_key_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=TrackerPostSerializer,
    ),
    list=extend_schema(
        parameters=[
            OpenApiParameter(
                "affects__flaw__is_major_incident",
                type=OpenApiTypes.BOOL,
                location=OpenApiParameter.QUERY,
                deprecated=True,
            ),
        ],
    ),
)
class TrackerView(ModelViewSet):
    queryset = Tracker.objects.all()
    serializer_class = TrackerSerializer
    filterset_class = TrackerFilter
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete"])
    permission_classes = [IsAuthenticatedOrReadOnly]
