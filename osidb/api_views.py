"""
implement osidb rest api views
"""

import logging
from datetime import datetime
from typing import Any, Type, cast
from urllib.parse import urljoin

import pghistory
import pkg_resources
import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from djangoql.serializers import SuggestionsAPISerializer
from djangoql.views import SuggestionsAPIView
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiRequest,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from packageurl import PackageURL
from rest_framework import status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
)
from rest_framework.views import APIView
from rest_framework.viewsets import (
    ModelViewSet,
    ReadOnlyModelViewSet,
    ViewSet,
    ViewSetMixin,
)
from rest_framework_simplejwt.views import TokenObtainPairView

from apps.workflows.workflow import WorkflowModel
from collectors.jiraffe.constants import HTTPS_PROXY, JIRA_SERVER
from osidb.core import set_user_acls
from osidb.helpers import get_bugzilla_api_key
from osidb.integrations import IntegrationRepository, IntegrationSettings
from osidb.models import Affect, AffectCVSS, Flaw, FlawLabel, Tracker
from osidb.models.flaw.cvss import FlawCVSS

from .constants import OSIDB_API_VERSION, PYPI_URL, URL_REGEX
from .filters import (
    AffectCVSSFilter,
    AffectFilter,
    AlertFilter,
    FlawAcknowledgmentFilter,
    FlawCommentFilter,
    FlawCVSSFilter,
    FlawFilter,
    FlawPackageVersionFilter,
    FlawQLSchema,
    FlawReferenceFilter,
    TrackerFilter,
)
from .mixins import Alert
from .serializer import (
    AffectBulkPostPutResponseSerializer,
    AffectBulkPutSerializer,
    AffectCVSSPostSerializer,
    AffectCVSSPutSerializer,
    AffectCVSSSerializer,
    AffectCVSSV2PostSerializer,
    AffectCVSSV2PutSerializer,
    AffectCVSSV2Serializer,
    AffectPostSerializer,
    AffectSerializer,
    AlertSerializer,
    AuditSerializer,
    FlawAcknowledgmentPostSerializer,
    FlawAcknowledgmentPutSerializer,
    FlawAcknowledgmentSerializer,
    FlawCollaboratorPostSerializer,
    FlawCollaboratorSerializer,
    FlawCommentPostSerializer,
    FlawCommentSerializer,
    FlawCVSSPostSerializer,
    FlawCVSSPutSerializer,
    FlawCVSSSerializer,
    FlawCVSSV2PostSerializer,
    FlawCVSSV2PutSerializer,
    FlawCVSSV2Serializer,
    FlawLabelSerializer,
    FlawPackageVersionPostSerializer,
    FlawPackageVersionPutSerializer,
    FlawPackageVersionSerializer,
    FlawPostSerializer,
    FlawReferencePostSerializer,
    FlawReferencePutSerializer,
    FlawReferenceSerializer,
    FlawSerializer,
    IntegrationTokenGetSerializer,
    IntegrationTokenPatchSerializer,
    TrackerPostSerializer,
    TrackerSerializer,
    UserSerializer,
)
from .validators import CVE_RE_STR

# Use only for RudimentaryUserPathLoggingMixin
api_logger = logging.getLogger("api_req")


@api_view(["GET"])
@permission_classes((AllowAny,))
def healthy(request: Request) -> Response:
    """unauthenticated view providing healthcheck on osidb service"""
    return Response()


class RudimentaryUserPathLoggingMixin:
    # Provides rudimentary visibility into API requests, users, time of processing via logging.
    # This is a stop-gap solution and not fit for enhancement.
    # Logs must be sent and stored securely w.r.t. the data sent there:
    # - username
    # - HTTP method and path
    # - how long the request took
    # - time of event (added implicitly by the logger)
    # (This is not a docstring so as not to pollute the generated schema.)

    def initialize_request(self, request, *args, **kwargs):
        """
        Log beginning of API request.
        """

        request = super().initialize_request(request, *args, **kwargs)

        if getattr(self, "swagger_fake_view", False):
            return request

        try:
            # Different sources suggest different behavior of request.user.
            # Local testing shows that str(request.user) is always nonempty
            # (AnonymousUser or the username).
            # However, as this is not fully explored and probably not worth it,
            # allow seeing unexpected states in the logs.
            if request.user and request.user.is_authenticated and request.user.username:
                user = f"USER:{request.user.username}"
            elif request.user and request.user.is_authenticated:
                # Probably shouldn't happen.
                user = f"USER_AUTH_NOUSERNAME:{str(request.user)}"
            elif request.user and request.user.username:
                user = f"USER_UNAUTH:{request.user.username}"
            elif request.user:
                user = f"USER_UNAUTH_NOUSERNAME:{str(request.user)}"
            else:
                user = f"USER_NONE:{repr(request.user)}"
        except:  # noqa: E722 Using bare except on purpose
            # Probably only happens when generating schema,
            # preempting that using getattr(self, "swagger_fake_view", False)
            # is much more performant, but leaving this try/except
            # so that the logging doesn't break normal operation
            # in an unexpected cornercase (not enough time to investigate deeply).
            user = "USER_EXCEPTION"

        method = request.method.upper()
        path = request.get_full_path()

        request._rudimentary_user_path_logging = {
            "method": method,
            "path": path,
            "start": datetime.now(),
            "user": user,
        }

        log_message = f"{user} at {method} {path}"
        api_logger.info(log_message)

        return request

    def finalize_response(self, request, response, *args, **kwargs):
        """
        Log end of API request.
        """
        response = super().finalize_response(request, response, *args, **kwargs)

        if getattr(self, "swagger_fake_view", False):
            return response

        end = datetime.now()

        timediff = end - request._rudimentary_user_path_logging["start"]
        ms_number = timediff.total_seconds() * 1000
        ms_formatted = "{:6.0f}".format(ms_number)

        user = request._rudimentary_user_path_logging["user"]
        method = request._rudimentary_user_path_logging["method"]
        path = request._rudimentary_user_path_logging["path"]

        log_message = f"END in {ms_formatted} ms {user} at {method} {path}"
        api_logger.info(log_message)

        return response


class StatusView(RudimentaryUserPathLoggingMixin, APIView):
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


class ManifestView(RudimentaryUserPathLoggingMixin, APIView):
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

include_history_param = OpenApiParameter(
    "include_history",
    type=bool,
    required=False,
    location=OpenApiParameter.QUERY,
    description=(
        "Indicates whether the response should include the "
        "model's change history. Set to 'true' to include "
        "historical changes. Default: false."
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
    required=False,
    type=str,
    location=OpenApiParameter.HEADER,
    description="User generated api key for Bugzilla authentication.",
)

jira_api_key_param = OpenApiParameter(
    name="Jira-Api-Key",
    required=False,
    type=str,
    location=OpenApiParameter.HEADER,
    description="User generated api key for Jira authentication.",
)

query_api_param = OpenApiParameter(
    name="query",
    required=False,
    type=str,
    location=OpenApiParameter.QUERY,
    description=(
        "Advanced filter with special syntax. "
        "See https://github.com/ivelum/djangoql for more information."
    ),
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


def include_history_extend_schema_view(
    cls: Type[ViewSetMixin],
) -> Type[ViewSetMixin]:
    """
    Decorator which adds `include_history` query parameter description
    into the schema for `list` and `retrieve` methods
    """
    return (
        extend_schema_view(
            list=extend_schema(parameters=[include_history_param]),
            retrieve=extend_schema(parameters=[include_history_param]),
        )
    )(cls)


def query_extend_schema_view(
    cls: Type[ViewSetMixin],
) -> Type[ViewSetMixin]:
    """
    Decorator which adds `query` query parameter description into the schema
    for `list` and `retrieve` methods
    """
    return (
        extend_schema_view(
            list=extend_schema(parameters=[query_api_param]),
            retrieve=extend_schema(parameters=[query_api_param]),
        )
    )(cls)


@extend_schema(exclude=True)
@permission_classes((IsAuthenticatedOrReadOnly,))
class FlawSuggestionsView(RudimentaryUserPathLoggingMixin, APIView):
    def get(self, request):
        view = SuggestionsAPIView.as_view(
            schema=FlawQLSchema(Flaw),
        )
        return view(request)


@extend_schema(exclude=True)
@permission_classes((IsAuthenticatedOrReadOnly,))
class FlawIntrospectionView(RudimentaryUserPathLoggingMixin, APIView):
    def get(self, request):
        return Response(
            SuggestionsAPISerializer(
                request.build_absolute_uri("suggestions")
            ).serialize(
                FlawQLSchema(Flaw),
            )
        )


@query_extend_schema_view
@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@include_history_extend_schema_view
@bz_api_key_extend_schema_view
@jira_api_key_extend_schema_view
@extend_schema_view(
    list=extend_schema(
        parameters=[
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
        parameters=[
            id_param,
            OpenApiParameter(
                "create_jira_task",
                type={"type": "boolean"},
                location=OpenApiParameter.QUERY,
                description=(
                    "If set to true, it will trigger the creation of a Jira task if "
                    "the flaw doesn't already have one associated."
                ),
            ),
        ],
    ),
)
class FlawView(RudimentaryUserPathLoggingMixin, ModelViewSet):
    queryset = Flaw.objects.prefetch_related(
        "acknowledgments",
        "affects",
        "affects__cvss_scores",
        "affects__trackers",
        "affects__trackers__errata",
        "affects__trackers__affects",
        "comments",
        "cvss_scores",
        "package_versions",
        "references",
        "labels",
    ).all()
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
        }
        response["Location"] = f"/api/{OSIDB_API_VERSION}/flaws/{response.data['uuid']}"
        return response


class SubFlawViewDestroyMixin:
    @extend_schema(
        responses={
            200: {},
        },
        parameters=[bz_api_key_param],
    )
    def destroy(self, request, *args, **kwargs):
        """
        Destroy the instance and proxy the delete to Bugzilla
        """
        bz_api_key = get_bugzilla_api_key(request)
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


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawAcknowledgmentPostSerializer,
        parameters=[bz_api_key_param],
    ),
    update=extend_schema(
        request=FlawAcknowledgmentPutSerializer,
        parameters=[bz_api_key_param],
    ),
)
class FlawAcknowledgmentView(
    RudimentaryUserPathLoggingMixin,
    SubFlawViewDestroyMixin,
    SubFlawViewGetMixin,
    ModelViewSet,
):
    serializer_class = FlawAcknowledgmentSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = FlawAcknowledgmentFilter


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawReferencePostSerializer,
        parameters=[bz_api_key_param],
    ),
    update=extend_schema(
        request=FlawReferencePutSerializer,
        parameters=[bz_api_key_param],
    ),
)
class FlawReferenceView(
    RudimentaryUserPathLoggingMixin,
    SubFlawViewDestroyMixin,
    SubFlawViewGetMixin,
    ModelViewSet,
):
    serializer_class = FlawReferenceSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = FlawReferenceFilter


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawCVSSPostSerializer,
        parameters=[bz_api_key_param],
    ),
    update=extend_schema(
        request=FlawCVSSPutSerializer,
        parameters=[bz_api_key_param],
    ),
)
class FlawCVSSView(
    RudimentaryUserPathLoggingMixin,
    SubFlawViewGetMixin,
    SubFlawViewDestroyMixin,
    ModelViewSet,
):
    serializer_class = FlawCVSSSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = FlawCVSSFilter

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        request.data.pop("issuer", None)
        return super().create(request, *args, **kwargs)

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        request.data.pop("issuer", None)
        cvss: FlawCVSS = self.get_object()
        if cvss.issuer == FlawCVSS.CVSSIssuer.REDHAT:
            return super().update(request, *args, **kwargs)
        return Response(FlawCVSSSerializer(cvss).data)

    @extend_schema(
        responses={
            200: {},
        },
        parameters=[bz_api_key_param],
    )
    def destroy(self, request, *args, **kwargs):
        cvss: FlawCVSS = self.get_object()
        if cvss.issuer == FlawCVSS.CVSSIssuer.REDHAT:
            return super().destroy(request, *args, **kwargs)
        return Response(status=HTTP_200_OK)


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawCVSSV2PostSerializer,
    ),
    update=extend_schema(
        request=FlawCVSSV2PutSerializer,
    ),
    destroy=extend_schema(
        parameters=[bz_api_key_param],
    ),
)
class FlawCVSSV2View(
    RudimentaryUserPathLoggingMixin,
    SubFlawViewGetMixin,
    SubFlawViewDestroyMixin,
    ModelViewSet,
):
    serializer_class = FlawCVSSV2Serializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = FlawCVSSFilter

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        cvss: FlawCVSS = self.get_object()
        if cvss.issuer != FlawCVSS.CVSSIssuer.REDHAT:
            raise ValidationError({"issuer": "Only Red Hat CVSS scores can be edited"})
        return super().update(request, *args, **kwargs)

    def destroy(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        cvss: FlawCVSS = self.get_object()
        if cvss.issuer != FlawCVSS.CVSSIssuer.REDHAT:
            raise ValidationError({"issuer": "Only Red Hat CVSS scores can be edited"})
        return super().destroy(request, *args, **kwargs)


@extend_schema(
    responses={
        204: {},
        400: {},
        404: {},
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticatedOrReadOnly])
def flaw_available(request: Request, *args, **kwargs) -> Response:
    """
    Report whether a flaw is available for public consumption purposes
    based on the following criteria:
    1) The work on the flaw is done, or the flaw is public:
        - 204 status (yes, flaw is available for public consumption)
    2) The work on the flaw is not done yet, or the flaw doesn't exist in the DB:
        - 404 status (no, flaw is unavailable for public consumption)
    3) Invalid CVE ID:
        - 400 status

    The intention is that this API is consumed by an agent that publishes pages
    with information about individual CVEs. As long as this API returns 404,
    the agent waits and doesn't publish the CVE page. Once this API first returns 204,
    the agent stops polling this API and publishes the CVE page. The consumers of such
    CVE pages are then informed about the CVE in such a way that the general affectedness
    ("Does the CVE affect products shipped by the organization that publishes the CVE
    page, or not?") most likely doesn't change. So this is to prevent public confusion
    during the early stages of security analysis where the preliminary analysis might
    switch between "this CVE affects our products" and "this CVE doesn't affect our products".
    """

    cve_id = kwargs["cve_id"]
    if not CVE_RE_STR.match(cve_id):
        return Response(status=HTTP_400_BAD_REQUEST)

    try:
        set_user_acls(settings.ALL_GROUPS)
        flaw = Flaw.objects.get(cve_id=cve_id)
        set_user_acls([])
    except Flaw.DoesNotExist:
        set_user_acls([])
        return Response(status=HTTP_404_NOT_FOUND)

    if (
        flaw.is_public
        or flaw.workflow_state == WorkflowModel.WorkflowState.REJECTED
        or flaw.workflow_state == WorkflowModel.WorkflowState.DONE
    ):
        return Response(status=HTTP_204_NO_CONTENT)

    return Response(status=HTTP_404_NOT_FOUND)


@extend_schema(responses={200: OpenApiResponse(response=UserSerializer)})
@api_view(["GET"])
@permission_classes((IsAuthenticatedOrReadOnly,))
def whoami(request: Request) -> Response:
    """View that provides information about the currently logged-in user"""
    return Response(UserSerializer(request.user).data)


@extend_schema(
    methods=["GET"],
    responses={200: OpenApiResponse(response=IntegrationTokenGetSerializer)},
)
@extend_schema(
    methods=["PATCH"],
    request=OpenApiRequest(request=IntegrationTokenPatchSerializer),
    responses={204: {}},
)
@api_view(["GET", "PATCH"])
def integration_tokens(request: Request) -> Response:
    """
    Set third-party integration tokens for the current user.
    """
    integration_settings = IntegrationSettings()
    integration_repo = IntegrationRepository(integration_settings)
    current_user = cast(User, request.user)

    if request.method == "GET":
        data = {
            "jira": integration_repo.read_jira_token(current_user.username),
            "bugzilla": integration_repo.read_bz_token(current_user.username),
        }
        serializer = IntegrationTokenGetSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        response = Response(data=serializer.validated_data, status=HTTP_200_OK)
    else:
        serializer = IntegrationTokenPatchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        if jira_token := validated_data.get("jira"):
            integration_repo.upsert_jira_token(current_user.username, jira_token)
        if bz_token := validated_data.get("bugzilla"):
            integration_repo.upsert_bz_token(current_user.username, bz_token)
        response = Response(status=HTTP_204_NO_CONTENT)
    return response


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        description="Create a new comment for a given flaw. Beware that freshly created comments "
        "are not guaranteed to keep their original UUIDs, especially if multiple "
        "comments are created simultaneously.",
        request=FlawCommentPostSerializer,
        parameters=[
            flaw_id,
            bz_api_key_param,
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
class FlawCommentView(
    RudimentaryUserPathLoggingMixin, SubFlawViewGetMixin, ModelViewSet
):
    serializer_class = FlawCommentSerializer
    filterset_class = FlawCommentFilter
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete", "put"])
    permission_classes = [IsAuthenticatedOrReadOnly]
    lookup_url_kwarg = "comment_id"

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Create a new comment, ignoring the creator field in the request body."""
        # Remove creator field from request data if present
        request.data.pop("creator", None)
        # Set creator field to current user safely
        request.data["creator"] = getattr(request.user, "email", "")
        return super().create(request, *args, **kwargs)


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=FlawPackageVersionPostSerializer,
        parameters=[bz_api_key_param],
    ),
    update=extend_schema(
        request=FlawPackageVersionPutSerializer,
        parameters=[bz_api_key_param],
    ),
)
class FlawPackageVersionView(
    RudimentaryUserPathLoggingMixin,
    SubFlawViewGetMixin,
    SubFlawViewDestroyMixin,
    ModelViewSet,
):
    serializer_class = FlawPackageVersionSerializer
    filterset_class = FlawPackageVersionFilter
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@include_history_extend_schema_view
@bz_api_key_extend_schema_view
@jira_api_key_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=AffectPostSerializer,
    ),
)
class AffectView(
    RudimentaryUserPathLoggingMixin, SubFlawViewDestroyMixin, ModelViewSet
):
    queryset = Affect.objects.prefetch_related(
        "alerts",
        "cvss_scores",
        "cvss_scores__alerts",
        "trackers",
        "trackers__errata",
        "trackers__affects",
        "trackers__alerts",
    ).all()
    serializer_class = AffectSerializer
    filterset_class = AffectFilter
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]

    @extend_schema(
        request=AffectBulkPutSerializer(many=True),
        responses=AffectBulkPostPutResponseSerializer,
        parameters=[bz_api_key_param, jira_api_key_param],
    )
    @action(methods=["PUT"], detail=False, url_path="bulk")
    def bulk_put(self, request, *args, **kwargs):
        """
        Bulk update endpoint. Expects a list of dict Affect objects.
        """

        bz_api_key = get_bugzilla_api_key(request)
        # TODO sometime: Some of these actions probably belong to another layer, perhaps serializer.

        queryset = self.filter_queryset(self.get_queryset())

        # first, perform validations
        flaws = set()
        uuids = set()
        validated_serializers = []
        for datum in request.data:
            try:
                uuid = datum["uuid"]
            except KeyError:
                raise ValidationError({"uuid": "This field is required."})

            if uuid in uuids:
                raise ValidationError(
                    {"uuid": "Multiple objects with the same uuid provided."}
                )
            else:
                uuids.add(uuid)

            try:
                flaw_uuid = datum["flaw"]
            except KeyError:
                raise ValidationError({"flaw": "This field is required."})

            flaws.add(flaw_uuid)

            instance = get_object_or_404(queryset, uuid=uuid)
            serializer = self.get_serializer(instance, data=datum)
            serializer.is_valid(raise_exception=True)
            validated_serializers.append(serializer)

        if len(flaws) > 1:
            raise ValidationError(
                {"flaw": "Provided affects belong to multiple flaws."}
            )

        # Second, save the updated affects to the database, but not sync with BZ.
        ret = []
        for serializer in validated_serializers:
            # Make the serializer skip the sync for each affect
            serializer.save(skip_bz_sync=True)
            ret.append(serializer.data)

        # Third, proxy the update to Bugzilla
        flaw = Flaw.objects.get(uuid=next(iter(flaws)))
        flaw.save(bz_api_key=bz_api_key)

        return Response({"results": ret})

    @extend_schema(
        request=AffectPostSerializer(many=True),
        responses=AffectBulkPostPutResponseSerializer,
        parameters=[bz_api_key_param],
    )
    @bulk_put.mapping.post
    def bulk_post(self, request, *args, **kwargs):
        """
        Bulk create endpoint. Expects a list of dict Affect objects.
        """

        bz_api_key = get_bugzilla_api_key(request)

        # TODO sometime: Some of these actions probably belong to another layer, perhaps serializer.

        # first, perform validations
        flaws = set()
        validated_serializers = []
        for datum in request.data:
            try:
                flaw_uuid = datum["flaw"]
            except KeyError:
                raise ValidationError({"flaw": "This field is required."})

            flaws.add(flaw_uuid)

            serializer = self.get_serializer(data=datum)
            serializer.is_valid(raise_exception=True)
            validated_serializers.append(serializer)

        if len(flaws) > 1:
            raise ValidationError(
                {"flaw": "Provided affects belong to multiple flaws."}
            )

        # Second, save the updated affects to the database, but not sync with BZ.
        ret = []
        for serializer in validated_serializers:
            # Make the serializer skip the sync for each affect
            serializer.save(skip_bz_sync=True)
            ret.append(serializer.data)

        # Third, proxy the update to Bugzilla
        flaw = Flaw.objects.get(uuid=next(iter(flaws)))
        flaw.save(bz_api_key=bz_api_key)

        return Response({"results": ret})

    @extend_schema(
        methods=["DELETE"],
        responses={
            200: {},
        },
        # Ignored because of https://github.com/tfranzel/drf-spectacular/issues/379
        # and https://swagger.io/docs/specification/describing-request-body/#:~:text=GET%2C-,DELETE,-and%20HEAD%20are
        request={"type": "array", "items": {"type": "string"}},
        parameters=[bz_api_key_param],
    )
    @bulk_put.mapping.delete
    def bulk_delete(self, request, *args, **kwargs):
        """
        Bulk delete endpoint. Expects a list of Affect uuids.
        """

        bz_api_key = get_bugzilla_api_key(request)

        flaws = set()
        uuids = set()
        for uuid in request.data:
            if uuid in uuids:
                raise ValidationError(
                    {"uuid": "Multiple objects with the same uuid provided."}
                )
            else:
                uuids.add(uuid)

            try:
                affect_obj = Affect.objects.get(uuid=uuid)
            except Affect.DoesNotExist:
                raise ValidationError({"uuid": "Affect matching query does not exist."})

            flaw_obj = affect_obj.flaw
            flaws.add(flaw_obj.uuid)
            if len(flaws) > 1:
                raise ValidationError(
                    {
                        "uuid": "Affect object UUIDs belonging to multiple Flaws provided."
                    }
                )

            # Relying on the whole transaction being aborted if a validation fails along the way.
            affect_obj.delete()
        flaw = Flaw.objects.get(uuid=next(iter(flaws)))
        flaw.save(bz_api_key=bz_api_key)

        return Response(status=HTTP_200_OK)


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=AffectCVSSPostSerializer,
        parameters=[bz_api_key_param],
    ),
    update=extend_schema(
        request=AffectCVSSPutSerializer,
        parameters=[bz_api_key_param],
    ),
)
class AffectCVSSView(RudimentaryUserPathLoggingMixin, ModelViewSet):
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

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        request.data.pop("issuer", None)
        return super().create(request, *args, **kwargs)

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        request.data.pop("issuer", None)
        cvss: AffectCVSS = self.get_object()
        if cvss.issuer == AffectCVSS.CVSSIssuer.REDHAT:
            return super().update(request, *args, **kwargs)
        return Response(AffectCVSSPutSerializer(cvss).data)

    @extend_schema(
        responses={
            200: {},
        },
        parameters=[bz_api_key_param],
    )
    def destroy(self, request, *args, **kwargs):
        """
        Destroy the instance and proxy the delete to Bugzilla.
        """
        bz_api_key = get_bugzilla_api_key(request)

        instance: AffectCVSS = self.get_object()
        if instance.issuer == AffectCVSS.CVSSIssuer.REDHAT:
            affect = instance.affect
            instance.delete()
            affect.save(bz_api_key=bz_api_key)
        return Response(status=HTTP_200_OK)


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=AffectCVSSV2PostSerializer,
    ),
    update=extend_schema(
        request=AffectCVSSV2PutSerializer,
    ),
    destroy=extend_schema(
        parameters=[bz_api_key_param],
    ),
)
class AffectCVSSV2View(RudimentaryUserPathLoggingMixin, ModelViewSet):
    serializer_class = AffectCVSSV2Serializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]
    filterset_class = AffectCVSSFilter

    def get_affect(self):
        _id = self.kwargs["affect_id"]
        obj = get_object_or_404(Affect, uuid=_id)
        return obj

    def get_queryset(self):
        # This solves the issue described in the section "My get_queryset()
        # depends on some attributes not available at schema generation time" in
        # https://drf-spectacular.readthedocs.io/en/latest/faq.html
        if getattr(self, "swagger_fake_view", False):
            return AffectCVSS.objects.none()

        affect = self.get_affect()
        return AffectCVSS.objects.filter(affect=affect)

    def get_serializer(self, *args, **kwargs):
        if "data" in kwargs:
            data = kwargs["data"].copy()
            data["affect"] = str(self.get_affect().uuid)
            kwargs["data"] = data
        return super().get_serializer(*args, **kwargs)

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        cvss: AffectCVSS = self.get_object()
        if cvss.issuer != AffectCVSS.CVSSIssuer.REDHAT:
            raise ValidationError({"issuer": "Only Red Hat CVSS scores can be edited"})
        return super().update(request, *args, **kwargs)

    def destroy(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        cvss: AffectCVSS = self.get_object()
        if cvss.issuer != AffectCVSS.CVSSIssuer.REDHAT:
            raise ValidationError({"issuer": "Only Red Hat CVSS scores can be edited"})
        return super().destroy(request, *args, **kwargs)


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@bz_api_key_extend_schema_view
@jira_api_key_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=TrackerPostSerializer,
    ),
)
class TrackerView(RudimentaryUserPathLoggingMixin, ModelViewSet):
    queryset = Tracker.objects.prefetch_related("alerts", "errata", "affects").all()
    serializer_class = TrackerSerializer
    filterset_class = TrackerFilter
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete"])
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get_serializer_class(self):
        if self.action == "create":
            return TrackerPostSerializer
        return self.serializer_class


@include_exclude_fields_extend_schema_view
@extend_schema_view(
    list=extend_schema(
        description="List existing alerts for all models.",
        parameters=[
            OpenApiParameter(
                "name",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description=(
                    "Retrieve only Alerts with the specified name, which is given by the "
                    "model's validation process."
                ),
            ),
            OpenApiParameter(
                "parent_uuid",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description=(
                    "Retrieve only Alerts related to a model with the given UUID."
                ),
            ),
            OpenApiParameter(
                "parent_model",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                # See osidb/helpers.py::get_mixin_subclases for getting all models
                # which inherit from AlertMixin
                enum=[
                    "flaw",
                    "affect",
                    "flawcvss",
                    "affectcvss",
                    "flawcomment",
                    "flawacknowledgment",
                    "flawreference",
                    "package",
                    "snippet",
                    "tracker",
                ],
                description=(
                    "Retrieve only Alerts related to the specified model, e.g. flaw or affect."
                ),
            ),
        ],
    ),
)
class AlertView(RudimentaryUserPathLoggingMixin, ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    filterset_class = AlertFilter
    http_method_names = get_valid_http_methods(
        ModelViewSet, excluded=["patch", "post", "put", "delete"]
    )
    permission_classes = [IsAuthenticatedOrReadOnly]


@extend_schema_view(
    create=extend_schema(
        request=FlawCollaboratorPostSerializer,
    ),
    update=extend_schema(
        request=FlawCollaboratorPostSerializer,
    ),
)
class FlawLabelView(
    RudimentaryUserPathLoggingMixin,
    SubFlawViewGetMixin,
    ModelViewSet,
):
    serializer_class = FlawCollaboratorSerializer
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.type == FlawLabel.FlawLabelType.PRODUCT_FAMILY:
            raise PermissionDenied(
                {"label": "Product family labels cannot be deleted."}
            )
        return super().destroy(request, *args, **kwargs)


class LabelView(
    RudimentaryUserPathLoggingMixin,
    ReadOnlyModelViewSet,
):
    queryset = FlawLabel.objects.all()
    serializer_class = FlawLabelSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]


# TODO: this view is temporary/undocumented and only applies to accessing JIRA stage and someday should be removed
@extend_schema(exclude=True)
class JiraStageForwarderView(RudimentaryUserPathLoggingMixin, APIView):
    """authenticated view which performs http forwarding specifically for Jira stage"""

    proxies = {"https": HTTPS_PROXY}
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request, *args, **kwargs):
        """perform JIRA stage HTTP GET"""

        path_value = request.GET.get("path")
        target_url = f"{JIRA_SERVER}{path_value}"
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "User-Agent": "OSIM",
        }
        params = request.GET.copy()
        jira_api_key = request.headers.get("Jira-Api-Key")
        if jira_api_key:
            headers["Authorization"] = f"Bearer {jira_api_key}"
        else:
            raise ValidationError({"Jira-Api-Key": "This HTTP header is required."})

        response = requests.get(
            target_url,
            proxies=self.proxies,
            params=params,
            headers=headers,
            timeout=30,
        )
        return Response(response.json(), status=response.status_code)

    def post(self, request, *args, **kwargs):
        """perform JIRA stage HTTP POST"""

        path_value = request.GET.get("path")
        target_url = f"{JIRA_SERVER}{path_value}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "User-Agent": "OSIM",
        }
        params = request.GET.copy()
        jira_api_key = request.headers.get("Jira-Api-Key")
        if jira_api_key:
            headers["Authorization"] = f"Bearer {jira_api_key}"
        else:
            raise ValidationError({"Jira-Api-Key": "This HTTP header is required."})

        response = requests.post(
            target_url,
            data=request.body,
            proxies=self.proxies,
            params=params,
            headers=headers,
            timeout=60,
        )
        return Response(response.json(), status=response.status_code)

    def put(self, request, *args, **kwargs):
        """perform JIRA stage HTTP PUT"""

        path_value = request.GET.get("path")
        target_url = f"{JIRA_SERVER}{path_value}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "User-Agent": "OSIM",
        }
        jira_api_key = request.headers.get("Jira-Api-Key")
        if jira_api_key:
            headers["Authorization"] = f"Bearer {jira_api_key}"
        else:
            raise ValidationError({"Jira-Api-Key": "This HTTP header is required."})

        response = requests.put(
            target_url,
            data=request.body,
            proxies=self.proxies,
            headers=headers,
            timeout=60,
        )

        return Response(
            response.json() if response.text else None, status=response.status_code
        )

    def options(self, request, *args, **kwargs):
        """always return same OPTIONS"""
        allowed_methods = ["GET", "POST"]

        headers = {
            "Allow": ", ".join(allowed_methods),
            "Access-Control-Allow-Methods": ", ".join(allowed_methods),
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
        # Return a response with the allowed methods and headers
        return Response(status=200, headers=headers)


class AuditView(RudimentaryUserPathLoggingMixin, ModelViewSet):
    """basic view of audit history events"""

    queryset = pghistory.models.Events.objects.all().order_by("-pgh_created_at")
    serializer_class = AuditSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["pgh_slug", "pgh_label", "pgh_obj_model", "pgh_created_at"]
    http_method_names = get_valid_http_methods(
        ModelViewSet, excluded=["delete", "post", "update"]
    )
    permission_classes = [IsAuthenticatedOrReadOnly]


# NOTE: Purpose of this custom class is for Kerberos authenticated
# GET method to be able to appear in the OpenAPI schema.
# We use Kerberos only for stage/production instances and the
# local instances are using the POST method with credentials.
# However this way only the POST method shows in the OpenAPI schema
# which is stored in the repository. Using this custom class we
# are able to show Kerberos auth GET method as well. Of course
# since Kerberos auth is not possible on local instance, endpoint
# will return 405 METHOD NOT ALLOWED code with the warning message
# stating that the Kerberos is not enabled and you should use the
# POST method with the credentials instead.
class OsidbTokenObtainPairView(TokenObtainPairView):
    @extend_schema(
        responses={
            200: {
                "type": "object",
                "properties": {
                    "refresh": {"type": "string"},
                    "access": {"type": "string"},
                },
            }
        },
        description=(
            "Takes a kerberos ticket and returns an access and refresh JWT pair."
        ),
        auth=[{"KerberosAuthentication": []}],
    )
    def get(self, request, *args, **kwargs):
        return Response(
            data={
                "detail": (
                    "Kerberos authentication is not enabled. "
                    "Use POST method with credentials instead."
                )
            },
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )
