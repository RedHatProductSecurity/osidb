"""
implement osidb rest api views
"""
import logging
from typing import Type
from urllib.parse import urljoin

import pkg_resources
import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from packageurl import PackageURL
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet, ViewSet, ViewSetMixin

from collectors.jiraffe.constants import HTTPS_PROXY, JIRA_SERVER

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
    FlawReferenceFilter,
    TrackerFilter,
)
from .mixins import Alert
from .models import Affect, AffectCVSS, Flaw, Tracker
from .serializer import (
    AffectBulkPutResponseSerializer,
    AffectCVSSPostSerializer,
    AffectCVSSPutSerializer,
    AffectCVSSSerializer,
    AffectPostSerializer,
    AffectSerializer,
    AlertSerializer,
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
        parameters=[id_param],
    ),
)
class FlawView(ModelViewSet):
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
@jira_api_key_extend_schema_view
@extend_schema_view(
    create=extend_schema(
        request=AffectPostSerializer,
    ),
)
class AffectView(SubFlawViewDestroyMixin, ModelViewSet):
    queryset = Affect.objects.prefetch_related(
        "cvss_scores",
        "trackers",
        "trackers__errata",
        "trackers__affects",
    ).all()
    serializer_class = AffectSerializer
    filterset_class = AffectFilter
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]

    @extend_schema(
        request=AffectSerializer(many=True),
        responses=AffectBulkPutResponseSerializer,
    )
    @action(methods=["PUT"], detail=False, url_path="bulk")
    def put(self, request, *args, **kwargs):
        """
        Bulk update endpoint. Expects a list of dict Affect objects.
        """

        bz_api_key = request.META.get("HTTP_BUGZILLA_API_KEY")
        if not bz_api_key:
            raise ValidationError({"Bugzilla-Api-Key": "This HTTP header is required."})

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

        def dummy(*args, **kwargs):
            pass

        # Second, save the updated affects to the database, but not sync with BZ.
        ret = []
        for serializer in validated_serializers:
            # NOTE This takes about 300 milliseconds on local laptop per instance.

            # Make the serializer's and model's mixins and .bzsync() not make requests to bugzilla.
            # Leave the jira token as is, so that AffectSerializer.update() can still update
            # Trackers in Jira as necessary.
            serializer.get_bz_api_key = dummy
            self.perform_update(serializer)

            ret.append(serializer.data)

        # Third, proxy the update to Bugzilla
        flaw = Flaw.objects.get(uuid=next(iter(flaws)))
        flaw.save(bz_api_key=bz_api_key)

        return Response({"results": ret})


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

    @extend_schema(
        responses={
            200: {},
        }
    )
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
)
class TrackerView(ModelViewSet):
    queryset = Tracker.objects.prefetch_related("errata", "affects").all()
    serializer_class = TrackerSerializer
    filterset_class = TrackerFilter
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete"])
    permission_classes = [IsAuthenticatedOrReadOnly]


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
class AlertView(ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    filterset_class = AlertFilter
    http_method_names = get_valid_http_methods(
        ModelViewSet, excluded=["patch", "post", "put", "delete"]
    )
    permission_classes = [IsAuthenticatedOrReadOnly]


# TODO: this view is temporary/undocumented and only applies to accessing JIRA stage and someday should be removed
@extend_schema(exclude=True)
class JiraStageForwarderView(APIView):
    """authenticated view which performs http forwarding specifically for Jira stage"""

    proxies = {"https": HTTPS_PROXY}

    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request, *args, **kwargs):
        """perform JIRA stage HTTP GET"""

        path_value = request.GET.get("path")
        target_url = f"{JIRA_SERVER}{path_value}"
        headers = {
            "Accept": "application/json",
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

    def create(self, request, *args, **kwargs):
        """perform JIRA stage HTTP POST"""

        path_value = request.GET.get("path")
        target_url = f"{JIRA_SERVER}{path_value}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        params = request.GET.copy()
        jira_api_key = request.headers.get("Jira-Api-Key")
        if jira_api_key:
            headers["Authorization"] = f"Bearer {jira_api_key}"
        else:
            raise ValidationError({"Jira-Api-Key": "This HTTP header is required."})

        response = requests.post(
            target_url,
            data=request.POST,
            proxies=self.proxies,
            params=params,
            headers=headers,
            timeout=30,
        )
        return Response(response.json, status=response.status_code)

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
