"""
implement osidb rest api views
"""

import logging
from collections import defaultdict
from datetime import datetime
from importlib.metadata import distributions
from types import SimpleNamespace
from typing import Any, Type, cast
from urllib.parse import urljoin
from uuid import uuid4

import pghistory
import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
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
from packaging.utils import canonicalize_name
from pghistory.models import Events
from rest_framework import status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.mixins import ListModelMixin
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_503_SERVICE_UNAVAILABLE,
)
from rest_framework.utils.urls import remove_query_param, replace_query_param
from rest_framework.views import APIView
from rest_framework.viewsets import (
    GenericViewSet,
    ModelViewSet,
    ReadOnlyModelViewSet,
    ViewSet,
    ViewSetMixin,
)
from rest_framework_simplejwt.views import TokenObtainPairView

from collectors.jiraffe.constants import HTTPS_PROXY, JIRA_SERVER
from osidb.helpers import bypass_rls, get_bugzilla_api_key, get_flaw_or_404
from osidb.integrations import IntegrationRepository, IntegrationSettings
from osidb.models import (
    Affect,
    AffectCVSS,
    AffectV1,
    Flaw,
    PsUpdateStream,
    Tracker,
)
from osidb.models.audit_history import (
    audit_rows_with_context,
    audit_table_for_model,
    normalize_pgh_context,
    pgh_data_from_row,
    registered_audit_tables,
)
from osidb.models.audit_history import (
    pgh_diff as build_pgh_diff,
)
from osidb.models.flaw.comment import FlawComment
from osidb.models.flaw.cvss import FlawCVSS
from osidb.sync_manager import SyncManager

from .constants import OSIDB_API_VERSION, PYPI_URL
from .filters import (
    AffectCVSSFilter,
    AffectFilter,
    AffectV1Filter,
    AlertFilter,
    FlawAcknowledgmentFilter,
    FlawCommentFilter,
    FlawCVSSFilter,
    FlawFilter,
    FlawPackageVersionFilter,
    FlawQLSchema,
    FlawReferenceFilter,
    FlawV1Filter,
    SyncManagerFilter,
    TrackerFilter,
    TrackerV1Filter,
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
    AffectV1Serializer,
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
    FlawPutSerializer,
    FlawReferencePostSerializer,
    FlawReferencePutSerializer,
    FlawReferenceSerializer,
    FlawSerializer,
    FlawV1Serializer,
    HistoryMixinSerializer,
    IncidentRequestSerializer,
    IntegrationTokenGetSerializer,
    IntegrationTokenPatchSerializer,
    SyncManagerSerializer,
    TrackerPostSerializer,
    TrackerSerializer,
    TrackerV1Serializer,
    UserSerializer,
)

_PREVIOUS_ROW_NOT_LOADED = object()


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

        for pkg in distributions():
            pkg_key = canonicalize_name(pkg.name)
            if pkg_key not in SKIP:
                home_page_url = pkg.metadata.get("home-page")

                purl = PackageURL(type="pypi", name=pkg_key, version=pkg.version)
                # PyPI treats '-' and '_' as the same character and is not case sensitive. A PyPI package
                # name must be lowercased with underscores replaced with a dash (e.g. 'apscheduler'). A
                # project name may contain the original case and underscores (e.g. 'APScheduler').
                entry = {
                    "pkg_name": pkg_key,
                    "project_name": pkg.name,
                    "version": pkg.version,
                    "source": urljoin(PYPI_URL, pkg.name),
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
    deprecated=True,
    description=(
        "Deprecated. Use the /audit endpoint instead. "
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

query_id_type_param = OpenApiParameter(
    name="id_type",
    required=False,
    type=str,
    enum=["uuid", "cve_id"],
    location=OpenApiParameter.QUERY,
    description=(
        "Specify which ID type to return. This is either internal OSIDB UUID of a Flaw "
        "or the CVE number of a Flaw"
    ),
)

# Manual schema specification since the auto-schema generation gets override by the class
flaw_index_response_schema = {
    "type": "object",
    "required": ["results"],
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "minItems": 2,
                "maxItems": 2,
                "items": {"type": "string"},
            },
        },
    },
}


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


class BulkHistoryMixin(ReadOnlyModelViewSet):
    # Mixin to provide bulk history caching for views that support include_history parameter.

    # This mixin provides optimized list() and retrieve() methods that bulk-fetch all history
    # events for objects and their related models in a single query, avoiding the N+1 query
    # problem when serializing with include_history=true.

    def _build_history_cache(self, objects):
        """
        Build a history cache for objects and their related models.

        Takes a list of objects (already evaluated with prefetch cache)
        and bulk-fetches all history events in a single query.

        Events.objects.references() automatically fetches events for both
        the objects and all their related objects (affects, cvss scores, etc.)

        Returns a dict mapping "app.ModelName:pk" to list of Events.
        """
        history_map = {}

        if objects:
            history_map = self._build_concrete_history_cache(objects)
            if history_map is None:
                history_map = {}
                all_history_events = Events.objects.references(*objects)
                for event in all_history_events:
                    key = f"{event.pgh_obj_model}:{event.pgh_obj_id}"
                    if key not in history_map:
                        history_map[key] = []
                    history_map[key].append(event)

        return history_map

    def _build_concrete_history_cache(self, objects):
        """
        Build history for serializers that expose HistoryMixinSerializer.

        Serializer declarations decide which nested serializers can expose
        history. Reading concrete audit tables keeps the API shape while
        avoiding the broad pghistory references aggregate.
        """
        serializer_class = self.get_serializer_class()
        objects_by_model = defaultdict(list)
        include_fields, include_nested = self._history_requested_fields(
            "include_fields"
        )
        exclude_fields, exclude_nested = self._history_requested_fields(
            "exclude_fields", default_empty=True
        )

        if not self._collect_history_objects(
            serializer_class,
            objects,
            objects_by_model,
            include_fields,
            include_nested,
            exclude_fields,
            exclude_nested,
        ):
            return None

        history_map = {}
        for model_class, model_objects in objects_by_model.items():
            self._add_model_history(history_map, model_class, model_objects)
        return history_map

    def _collect_history_objects(
        self,
        serializer_class,
        objects,
        objects_by_model,
        include_fields,
        include_nested,
        exclude_fields,
        exclude_nested,
    ):
        if not issubclass(serializer_class, HistoryMixinSerializer):
            return False

        object_list = list(objects)
        objects_by_model[serializer_class.get_history_model()].extend(object_list)

        for relation in serializer_class.get_history_relations():
            if not self._history_field_included(
                relation.field_name, include_fields, exclude_fields
            ):
                continue

            related_objects = []
            for obj in object_list:
                related_objects.extend(relation.accessor(obj))

            child_include_fields, child_include_nested = self._history_child_fields(
                relation.field_name, include_nested, default_empty=False
            )
            child_exclude_fields, child_exclude_nested = self._history_child_fields(
                relation.field_name, exclude_nested, default_empty=True
            )
            self._collect_history_objects(
                relation.serializer_class,
                related_objects,
                objects_by_model,
                child_include_fields,
                child_include_nested,
                child_exclude_fields,
                child_exclude_nested,
            )

        return True

    def _history_requested_fields(self, param_name, default_empty=False):
        request = getattr(self, "request", None)
        if request is None:
            return (set() if default_empty else None), {}

        raw = request.query_params.get(param_name)
        if not raw:
            return (set() if default_empty else None), {}

        fields = set()
        nested = defaultdict(list)
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            field_name, separator, child_field = item.partition(".")
            fields.add(field_name)
            if separator:
                nested[field_name].append(child_field)
        return fields, nested

    def _history_child_fields(self, field_name, nested_fields, default_empty=False):
        child_values = nested_fields.get(field_name, [])
        if not child_values:
            return (set() if default_empty else None), {}

        fields = set()
        nested = defaultdict(list)
        for item in child_values:
            child_name, separator, grandchild = item.partition(".")
            fields.add(child_name)
            if separator:
                nested[child_name].append(grandchild)
        return fields, nested

    def _history_field_included(self, field_name, include_fields, exclude_fields):
        # Explicit includes take precedence over excludes.
        if include_fields is not None and field_name not in include_fields:
            return False
        return not (
            field_name in exclude_fields
            and (include_fields is None or field_name not in include_fields)
        )

    def _add_model_history(self, history_map, model_class, objects):
        object_ids = [obj.pk for obj in objects if obj.pk is not None]
        if not object_ids:
            return

        audit_table = audit_table_for_model(model_class)
        if audit_table is None:
            return

        rows = audit_rows_with_context(
            audit_table["model"]
            .objects.filter(pgh_obj_id__in=object_ids)
            .order_by("pgh_obj_id", "pgh_id"),
            audit_table,
        )

        previous_data_by_obj_id = {}
        for row in rows:
            key = f"{audit_table['object_label']}:{row['pgh_obj_id']}"
            pgh_data = pgh_data_from_row(audit_table, row)
            previous_data = previous_data_by_obj_id.get(row["pgh_obj_id"], {})
            history_map.setdefault(key, []).append(
                SimpleNamespace(
                    pgh_created_at=row["pgh_created_at"],
                    pgh_slug=f"{audit_table['audit_label']}:{row['pgh_id']}",
                    pgh_label=row["pgh_label"],
                    pgh_context=normalize_pgh_context(row.get("pgh_context")),
                    pgh_diff=build_pgh_diff(previous_data, pgh_data),
                )
            )
            previous_data_by_obj_id[row["pgh_obj_id"]] = pgh_data

    def list(self, request, *args, **kwargs):
        # Override list to bulk-fetch history for all objects.
        # This prevents N+1 queries when requesting history for multiple objects.

        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            objects = page
        else:
            objects = queryset

        if request.query_params.get("include_history", False):
            objects_list = list(objects)
            history_cache = self._build_history_cache(objects_list)
            context = self.get_serializer_context()
            context["history_cache"] = history_cache
            serializer = self.get_serializer(objects_list, many=True, context=context)
        else:
            serializer = self.get_serializer(objects, many=True)

        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        # Override retrieve to bulk-fetch history for a single object and its related models.
        # This prevents N+1 queries when requesting history for an object with many related models.

        instance = self.get_object()

        if request.query_params.get("include_history", False):
            history_cache = self._build_history_cache([instance])
            context = self.get_serializer_context()
            context["history_cache"] = history_cache
            serializer = self.get_serializer(instance, context=context)
        else:
            serializer = self.get_serializer(instance)

        return Response(serializer.data)


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
        responses=FlawPutSerializer,
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
class FlawView(RudimentaryUserPathLoggingMixin, BulkHistoryMixin, ModelViewSet):
    queryset = Flaw.objects.all()
    serializer_class = FlawSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = FlawFilter
    lookup_url_kwarg = "id"
    # there is neigher a way to really delete a flaw in Bugzilla
    # nor a defined procedure to make a flaw being considered deleted
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete"])
    permission_classes = [IsAuthenticatedOrReadOnly]

    _BASE_PREFETCH_RELATED = (
        "acknowledgments",
        "comments",
        "cvss_scores",
        "package_versions",
        "references",
        "labels_v2",
        "alerts",
        "upstream_data",
    )
    _AFFECTS_PREFETCH_RELATED = (
        "affects",
        "affects__cvss_scores",
        "affects__tracker",
        "affects__tracker__errata",
        "affects__tracker__affects",
        "affects__alerts",
        "affects__tracker__alerts",
    )
    _AFFECTS_PREFETCH_RELATED_FOR_TRACKERS = (
        "affects",
        "affects__tracker",
    )

    _PREFETCH_RELATED_BY_FIELD = {
        "acknowledgments": ("acknowledgments",),
        "comments": ("comments",),
        "cvss_scores": ("cvss_scores",),
        "package_versions": ("package_versions",),
        "references": ("references",),
        "labels": ("labels_v2",),
        "alerts": ("alerts",),
        "upstream_data": ("upstream_data",),
        # "affects" and "trackers" handled explicitly below because they are more nuanced.
    }

    def _exclude_fields_contains(self, field_name: str) -> bool:
        request = getattr(self, "request", None)
        if request is None:
            return False

        exclude_fields_param = request.query_params.get("exclude_fields") or ""
        exclude_fields = {
            s for f in exclude_fields_param.split(",") if (s := f.strip())
        }
        return field_name in exclude_fields

    def _include_fields_top_level(self) -> set[str] | None:
        """
        Return top-level fields requested via include_fields.

        Examples:
          - include_fields=uuid,cve_id -> {"uuid", "cve_id"}
          - include_fields=affects.uuid,uuid -> {"affects", "uuid"}
        """
        request = getattr(self, "request", None)
        if request is None:
            return None

        include_fields_param = request.query_params.get("include_fields")
        if not include_fields_param:
            return None

        include_fields = {
            s for f in include_fields_param.split(",") if (s := f.strip())
        }

        top_level = set()
        for f in include_fields:
            top_level.add(f.split(".", maxsplit=1)[0])
        return top_level

    def get_queryset(self):
        queryset = Flaw.objects.all()
        include_fields = self._include_fields_top_level()

        # Avoid prefetching affects for actions that don't need them.
        if self.action in ("create", "destroy", "update"):
            return queryset

        # Prefetch only what we need. If include_fields is not provided, behave like
        # the default API response and prefetch common relations.
        prefetch_related: list[str] = []
        if include_fields is None:
            prefetch_related.extend(self._BASE_PREFETCH_RELATED)
        else:
            for field_name in include_fields:
                prefetch_related.extend(
                    self._PREFETCH_RELATED_BY_FIELD.get(field_name, ())
                )

        # Avoid expensive affects prefetch when affects are excluded from the response.
        # (exclude_fields is handled at serializer-level; this makes DB fetching match it.)
        if not self._exclude_fields_contains("affects"):
            if include_fields is None or "affects" in include_fields:
                prefetch_related.extend(self._AFFECTS_PREFETCH_RELATED)
            elif "trackers" in include_fields:
                # "trackers" is computed from affects; only prefetch what's needed for that.
                prefetch_related.extend(self._AFFECTS_PREFETCH_RELATED_FOR_TRACKERS)

        if prefetch_related:
            queryset = queryset.prefetch_related(*prefetch_related)
        return queryset.all()

    def get_object(self):
        # from https://www.django-rest-framework.org/api-guide/generic-views/#methods
        """get flaw object instance"""
        queryset = self.get_queryset()
        pk = self.kwargs[self.lookup_url_kwarg]

        obj = get_flaw_or_404(pk, queryset=queryset)
        return obj

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        response.data = {
            "uuid": response.data["uuid"],
        }
        response["Location"] = f"/api/{OSIDB_API_VERSION}/flaws/{response.data['uuid']}"
        return response

    @extend_schema(
        parameters=[query_id_type_param],
        responses={200: flaw_index_response_schema},
    )
    @action(detail=False, methods=["get"])
    def index(self, request, *args, **kwargs):
        """
        Simple API endpoint to return ID and local update time pairs
        """
        id_type = request.query_params.get("id_type", "uuid")

        # Default to using UUID unless CVE ID is requested
        if id_type == "cve_id":
            queryset = Flaw.objects.exclude(cve_id__isnull=True).values_list(
                "cve_id", "local_updated_dt"
            )
        else:
            queryset = Flaw.objects.values_list("uuid", "local_updated_dt")

        return Response({"results": queryset})


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
class FlawV1View(FlawView):
    """View for the flaw model adapted to affects v1"""

    serializer_class = FlawV1Serializer
    queryset = Flaw.objects.prefetch_related(
        "acknowledgments",
        "alerts",
        "comments",
        "cvss_scores",
        "package_versions",
        "references",
        "labels",
        "upstream_data",
    ).all()
    filterset_class = FlawV1Filter


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
        obj = get_flaw_or_404(pk)
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
@bypass_rls
def flaw_available(request: Request, *args, **kwargs) -> Response:
    """
    Report whether a flaw is available for public consumption purposes
    based on the following criteria:
    1) The work on the flaw is done, or the flaw is public, or the flaw doesn't exist in the DB:
        - 204 status (yes, flaw is available for public consumption)
    2) The work on the flaw is not done yet:
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

    Also an important point is that the client processes CVEs that never get saved to OSIDB's
    DB (because of internal function `should_create_snippet`), yet the client must
    publish information about all CVEs. By returning 204 when the flaw doesn't exist in OSIDB's
    DB, it allows the client to take the output of this API endpoint as actionable advice:
    When 204, publish the CVE page (either using OSIDB data or using other data), when
    404, do not publish the CVE page (because the Vulnerability Management team still works
    on the CVE).

    That also means the client that uses this API endpoint must implement a grace period
    to allow OSIDB to ingest the CVE and decide whether to save it to the DB, to prevent
    the client publishing a CVE sooner than OSIDB processes it and potentially returns 404 for it.
    """

    cve_id = kwargs["cve_id"]

    try:
        flaw = Flaw.objects.get_by_identifier(cve_id)
    except Flaw.DoesNotExist:
        return Response(status=HTTP_204_NO_CONTENT)
    except ValidationError:
        return Response(status=HTTP_400_BAD_REQUEST)

    if flaw.is_public or flaw.workflow_state == "DONE":
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
    responses={
        200: OpenApiResponse(response=IntegrationTokenGetSerializer),
        503: {
            "type": "object",
            "properties": {
                "detail": {"type": "string"},
            },
            "description": "Vault integration is disabled",
        },
    },
)
@extend_schema(
    methods=["PATCH"],
    request=OpenApiRequest(request=IntegrationTokenPatchSerializer),
    responses={
        204: {},
        503: {
            "type": "object",
            "properties": {
                "detail": {"type": "string"},
            },
            "description": "Vault integration is disabled",
        },
    },
)
@api_view(["GET", "PATCH"])
def integration_tokens(request: Request) -> Response:
    """
    Set third-party integration tokens for the current user.
    """
    integration_settings = IntegrationSettings()
    integration_repo = IntegrationRepository(integration_settings)
    current_user = cast(User, request.user)

    if integration_repo.client is None:
        return Response(
            {
                "detail": "Vault integration is disabled because required credentials are not provided"
            },
            status=HTTP_503_SERVICE_UNAVAILABLE,
        )

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


def _prepare_affect_for_bulk(instance, flaw, ps_update_stream_map):
    """
    Run all the pre-save processing that Affect.save() and pre_save signals
    normally perform, preparing the instance for bulk_create without actually
    saving it.

    *flaw* is the pre-fetched parent Flaw and *ps_update_stream_map* is a
    ``{name: PsUpdateStream}`` dict (with ``ps_module`` already
    select_related), both passed in to avoid N+1 queries.

    Raises ValidationError if the instance is invalid.
    """
    # Pin the cached FK so Django never lazy-loads it again.
    instance.flaw = flaw

    # --- Affect.save() pre-processing ---
    if instance.purl and not instance.ps_component:
        try:
            maybe_ps_component = instance.ps_component_from_purl()
            if maybe_ps_component:
                instance.ps_component = maybe_ps_component
        except ValueError:
            pass

    if instance.is_resolved:
        instance.resolved_dt = timezone.now().replace(microsecond=0)
    else:
        instance.resolved_dt = None

    ps_update_stream_obj = ps_update_stream_map.get(instance.ps_update_stream)
    if ps_update_stream_obj and ps_update_stream_obj.ps_module:
        instance.ps_module = ps_update_stream_obj.ps_module.name
    else:
        instance.ps_module = None

    # --- pre_save signal: mirror_parent_cve_id ---
    instance.cve_id = flaw.cve_id

    # --- pre_save signal: remove_not_affected_justification ---
    if instance.affectedness != Affect.AffectAffectedness.NOTAFFECTED:
        instance.not_affected_justification = ""

    # --- pre_save signal: update_denormalized_labels_on_affect_change ---
    instance.update_denormalized_labels()

    # --- TrackingMixin: set timestamps for a new instance ---
    now = timezone.now().replace(microsecond=0)
    instance.created_dt = now
    instance.updated_dt = now

    # --- AlertMixin: set last_validated_dt and run validation ---
    instance.last_validated_dt = timezone.now()
    instance.validate(raise_validation_error=True)


def _run_post_save_effects_for_bulk(created_affects, flaw):
    """
    Run the post_save side-effects that are normally triggered by signals
    after each individual Affect.save().  Called once after bulk_create.
    """
    from osidb.models import FlawCollaborator

    for affect in created_affects:
        FlawCollaborator.objects.create_from_affect(affect)


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
    RudimentaryUserPathLoggingMixin,
    BulkHistoryMixin,
    SubFlawViewDestroyMixin,
    ModelViewSet,
):
    queryset = Affect.objects.prefetch_related(
        "alerts",
        "cvss_scores",
        "cvss_scores__alerts",
        "tracker",
        "tracker__errata",
        "tracker__affects",
        "tracker__alerts",
    ).all()
    serializer_class = AffectSerializer
    filterset_class = AffectFilter
    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]

    @staticmethod
    def _actor(user) -> str:
        return getattr(user, "email", "") or getattr(user, "username", "")

    def perform_create(self, serializer):
        actor = self._actor(self.request.user)
        serializer.save(created_by=actor, updated_by=actor)

    def perform_update(self, serializer):
        actor = self._actor(self.request.user)
        serializer.save(updated_by=actor)

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
        actor = self._actor(request.user)
        ret = []
        errors = []
        for serializer in validated_serializers:
            # Make the serializer skip the sync for each affect
            try:
                serializer.save(skip_bz_sync=True, updated_by=actor)
                ret.append(serializer.data)
            except ValidationError as e:
                instance = serializer.instance
                error_detail = (
                    e.message_dict
                    if hasattr(e, "message_dict")
                    else {"non_field_errors": e.messages}
                )
                errors.append(
                    {
                        "input": {
                            "uuid": str(instance.uuid),
                            "ps_update_stream": instance.ps_update_stream,
                            "ps_component": instance.ps_component,
                            "purl": instance.purl,
                            "ps_module": instance.ps_module,
                        },
                        "errors": error_detail,
                    }
                )

        # Third, proxy the update to Bugzilla
        flaw = Flaw.objects.get(uuid=next(iter(flaws)))
        if ret:
            flaw.save(bz_api_key=bz_api_key)

        return Response({"results": ret, "failed": errors})

    @extend_schema(
        request=AffectPostSerializer(many=True),
        responses=AffectBulkPostPutResponseSerializer,
        parameters=[bz_api_key_param],
    )
    @bulk_put.mapping.post
    def bulk_post(self, request, *args, **kwargs):
        """
        Bulk create endpoint. Expects a list of dict Affect objects.

        Valid affects are created via bulk_create; invalid or duplicate
        entries are skipped and reported in the ``failed`` list.
        """
        bz_api_key = get_bugzilla_api_key(request)

        # --- Pre-scan: collect flaw UUIDs and enforce constraints ---
        flaw_uuids = set()
        for datum in request.data:
            try:
                flaw_uuids.add(datum["flaw"])
            except (KeyError, TypeError):
                raise ValidationError({"flaw": "This field is required."})

        if len(flaw_uuids) > 1:
            raise ValidationError(
                {"flaw": "Provided affects belong to multiple flaws."}
            )

        if not flaw_uuids:
            raise ValidationError({"flaw": "This field is required."})

        flaw_uuid = next(iter(flaw_uuids))
        flaw = get_object_or_404(Flaw, uuid=flaw_uuid)

        # Prefetch all PsUpdateStreams referenced in the batch (+ their PsModule)
        stream_names = {
            d.get("ps_update_stream")
            for d in request.data
            if isinstance(d, dict) and d.get("ps_update_stream")
        }
        ps_update_stream_map = {
            obj.name: obj
            for obj in PsUpdateStream.objects.filter(
                name__in=stream_names
            ).select_related("ps_module")
        }

        # --- Phase 1 + 2: validate, build and prepare each instance ---
        prepared_instances = []
        errors = []

        for idx, datum in enumerate(request.data):
            serializer = self.get_serializer(data=datum)
            if not serializer.is_valid():
                errors.append({"index": idx, "errors": serializer.errors})
                continue

            validated_data = serializer.validated_data
            if "acl_read" not in validated_data or "acl_write" not in validated_data:
                validated_data = serializer.embargoed2acls(validated_data)

            try:
                instance = Affect(**validated_data)
                instance.uuid = uuid4()
                actor = self._actor(request.user)
                instance.created_by = actor
                instance.updated_by = actor
                _prepare_affect_for_bulk(instance, flaw, ps_update_stream_map)
            except ValidationError as e:
                error_detail = (
                    e.message_dict
                    if hasattr(e, "message_dict")
                    else {"non_field_errors": e.messages}
                )
                errors.append({"index": idx, "errors": error_detail})
                continue

            prepared_instances.append((idx, datum, instance))

        if not prepared_instances:
            return Response(
                {"results": [], "failed": errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # --- Phase 3: bulk insert, let Postgres skip duplicates ---
        instances = [inst for _, _, inst in prepared_instances]
        submitted_uuids = {inst.uuid for inst in instances}

        Affect.objects.bulk_create(instances, ignore_conflicts=True)

        # Refetch by pre-generated UUIDs to find which ones Postgres kept.
        created = list(Affect.objects.filter(uuid__in=submitted_uuids))
        created_uuids = {a.uuid for a in created}

        for idx, datum, inst in prepared_instances:
            if inst.uuid not in created_uuids:
                errors.append(
                    {
                        "index": idx,
                        "input": datum,
                        "errors": {
                            "non_field_errors": [
                                "Affect already exists for this flaw/stream/component."
                            ]
                        },
                    }
                )

        # --- Phase 4: post-save effects ---
        _run_post_save_effects_for_bulk(created, flaw)
        flaw.save(bz_api_key=bz_api_key)

        ret = self.get_serializer(created, many=True).data
        return Response({"results": ret, "failed": errors})

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


@extend_schema(description="Read-only view for affects v1")
@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
@include_history_extend_schema_view
class AffectV1View(BulkHistoryMixin, ReadOnlyModelViewSet):
    queryset = AffectV1.objects.filter(embargoed=False)
    serializer_class = AffectV1Serializer
    filterset_class = AffectV1Filter
    permission_classes = [IsAuthenticatedOrReadOnly]


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
class AffectCVSSView(RudimentaryUserPathLoggingMixin, ReadOnlyModelViewSet):
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


@include_meta_attr_extend_schema_view
@include_exclude_fields_extend_schema_view
class TrackerV1View(TrackerView):
    """View for the tracker model adapted to affects v1"""

    queryset = Tracker.objects.prefetch_related("alerts", "errata").all()
    serializer_class = TrackerV1Serializer
    http_method_names = get_valid_http_methods(
        ModelViewSet, excluded=["delete", "post", "put"]
    )
    filterset_class = TrackerV1Filter


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
        from osidb.models import FlawLabelV2

        if instance.type == FlawLabelV2.LabelType.PRODUCT_FAMILY:
            raise PermissionDenied(
                {"label": "Product family labels cannot be deleted."}
            )
        return super().destroy(request, *args, **kwargs)


class LabelView(
    RudimentaryUserPathLoggingMixin,
    ListModelMixin,
    GenericViewSet,
):
    serializer_class = FlawLabelSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    lookup_field = "uuid"

    _DEFINITION_MODELS = None

    @classmethod
    def _get_definition_models(cls):
        if cls._DEFINITION_MODELS is None:
            from osidb.models import (
                BULabelDefinition,
                CollaboratorLabelDefinition,
                FlawLabelV2,
                ProductFamilyLabelDefinition,
            )

            cls._DEFINITION_MODELS = [
                (CollaboratorLabelDefinition, FlawLabelV2.LabelType.CONTEXT_BASED),
                (ProductFamilyLabelDefinition, FlawLabelV2.LabelType.PRODUCT_FAMILY),
                (BULabelDefinition, FlawLabelV2.LabelType.BU),
            ]
        return cls._DEFINITION_MODELS

    def get_queryset(self):
        results = []
        for model, label_type in self._get_definition_models():
            for d in model.objects.all():
                results.append({"name": d.name, "type": label_type})
        return results

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "uuid",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="A UUID string identifying this flaw label.",
            )
        ]
    )
    def retrieve(self, request, uuid=None, *args, **kwargs):
        for model, label_type in self._get_definition_models():
            try:
                d = model.objects.get(uuid=uuid)
                serializer = self.get_serializer({"name": d.name, "type": label_type})
                return Response(serializer.data)
            except model.DoesNotExist:
                continue
        from django.http import Http404

        raise Http404


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


class AuditView(RudimentaryUserPathLoggingMixin, ReadOnlyModelViewSet):
    queryset = pghistory.models.Events.objects.all().order_by("-pgh_created_at")
    serializer_class = AuditSerializer
    filter_backends = (DjangoFilterBackend,)
    # NOTE: we probably could do without pgh_slug, but it's kept for
    # backwards-compatibility reasons
    filterset_fields = [
        "pgh_slug",
        "pgh_label",
        "pgh_obj_model",
        "pgh_created_at",
        "pgh_obj_id",
    ]
    permission_classes = [IsAuthenticatedOrReadOnly]
    lookup_field = "pgh_slug"
    # allow dots and colons in pgh_slug (e.g. "osidb.FlawAudit:2035413"); default [^/.]+
    # would only capture up to the first dot.
    lookup_value_regex = "[^/]+"

    def list(self, request, *args, **kwargs):
        limit = self._get_limit(request)
        offset = self._get_offset(request)
        count = self._audit_count(request.query_params)
        rows = self._audit_rows(request.query_params, limit, offset)
        previous_rows = self._previous_rows_for_rows(rows)
        events = [
            self._event_from_row(
                audit_table,
                row,
                previous_rows.get((audit_table["audit_label"], row["pgh_id"])),
            )
            for audit_table, row in rows
        ]

        return Response(
            {
                "count": count,
                "next": self._get_next_link(request, limit, offset, count),
                "previous": self._get_previous_link(request, limit, offset),
                "results": events,
            }
        )

    def retrieve(self, request, *args, **kwargs):
        event = self._event_by_slug(kwargs[self.lookup_field])
        if event is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(event)

    def _get_limit(self, request):
        default_limit = settings.REST_FRAMEWORK.get("PAGE_SIZE") or 100
        hard_limit = settings.REST_FRAMEWORK.get("MAX_PAGE_SIZE") or default_limit
        try:
            limit = int(request.query_params.get("limit", default_limit))
        except (TypeError, ValueError):
            limit = default_limit
        return max(0, min(limit, hard_limit))

    def _get_offset(self, request):
        try:
            return max(0, int(request.query_params.get("offset", 0)))
        except (TypeError, ValueError):
            return 0

    def _get_next_link(self, request, limit, offset, count):
        if not limit or offset + limit >= count:
            return None

        url = request.build_absolute_uri()
        url = replace_query_param(url, "limit", limit)
        return replace_query_param(url, "offset", offset + limit)

    def _get_previous_link(self, request, limit, offset):
        if not limit or offset <= 0:
            return None

        url = request.build_absolute_uri()
        url = replace_query_param(url, "limit", limit)
        previous_offset = max(offset - limit, 0)
        if previous_offset == 0:
            return remove_query_param(url, "offset")
        return replace_query_param(url, "offset", previous_offset)

    def _audit_count(self, params):
        pgh_slug = params.get("pgh_slug")
        if pgh_slug:
            return 1 if self._row_by_slug(pgh_slug, params) else 0

        count = 0
        for audit_table in registered_audit_tables():
            if (
                params.get("pgh_obj_model")
                and params["pgh_obj_model"] != audit_table["object_label"]
            ):
                continue
            # Exact counts on unfiltered audit feeds are expensive on large audit tables,
            # but are preserved for API compatibility with the existing /audit contract.
            count += self._audit_queryset(audit_table, params).count()
        return count

    def _audit_rows(self, params, limit, offset):
        rows = []
        pgh_slug = params.get("pgh_slug")
        if pgh_slug:
            if not limit or offset:
                return []
            event = self._row_by_slug(pgh_slug, params)
            return [event] if event else []

        for audit_table in registered_audit_tables():
            if (
                params.get("pgh_obj_model")
                and params["pgh_obj_model"] != audit_table["object_label"]
            ):
                continue

            window = limit + offset
            if not window:
                continue

            rows.extend(
                (audit_table, row)
                for row in audit_rows_with_context(
                    self._audit_queryset(audit_table, params).order_by("-pgh_id")[
                        :window
                    ],
                    audit_table,
                )
            )

        rows.sort(key=lambda item: item[1]["pgh_created_at"], reverse=True)
        return rows[offset : offset + limit]

    def _audit_queryset(self, audit_table, params):
        filters = {}
        if params.get("pgh_label"):
            filters["pgh_label"] = params["pgh_label"]
        if params.get("pgh_obj_id"):
            filters["pgh_obj_id"] = params["pgh_obj_id"]
        if params.get("pgh_created_at"):
            filters["pgh_created_at"] = params["pgh_created_at"]
        return audit_table["model"].objects.filter(**filters)

    def _event_by_slug(self, pgh_slug):
        row = self._row_by_slug(pgh_slug)
        if row is None:
            return None
        return self._event_from_row(*row)

    def _row_by_slug(self, pgh_slug, params=None):
        if ":" not in pgh_slug:
            return None

        audit_label, pgh_id = pgh_slug.rsplit(":", 1)
        try:
            pgh_id = int(pgh_id)
        except ValueError:
            return None

        for audit_table in registered_audit_tables():
            if audit_table["audit_label"] != audit_label:
                continue
            if (
                params
                and params.get("pgh_obj_model")
                and params["pgh_obj_model"] != audit_table["object_label"]
            ):
                return None

            row = next(
                audit_rows_with_context(
                    self._audit_queryset(audit_table, params or {}).filter(
                        pgh_id=pgh_id
                    )[:1],
                    audit_table,
                ),
                None,
            )
            if row is None:
                return None
            return audit_table, row
        return None

    def _event_from_row(self, audit_table, row, previous=_PREVIOUS_ROW_NOT_LOADED):
        pgh_data = pgh_data_from_row(audit_table, row)
        if previous is _PREVIOUS_ROW_NOT_LOADED:
            previous = self._previous_row(audit_table, row)
        previous_data = pgh_data_from_row(audit_table, previous) if previous else {}

        return {
            "pgh_created_at": row["pgh_created_at"],
            "pgh_slug": f"{audit_table['audit_label']}:{row['pgh_id']}",
            "pgh_obj_model": audit_table["object_label"],
            "pgh_obj_id": row["pgh_obj_id"],
            "pgh_label": row["pgh_label"],
            "pgh_context": normalize_pgh_context(row.get("pgh_context")),
            "pgh_diff": build_pgh_diff(previous_data, pgh_data),
            "pgh_data": pgh_data,
        }

    def _previous_row(self, audit_table, row):
        """pg_diff is not physically stored, previous edit on field is needed for that"""
        return (
            audit_table["model"]
            .objects.filter(pgh_obj_id=row["pgh_obj_id"], pgh_id__lt=row["pgh_id"])
            .order_by("-pgh_id")
            .values(*audit_table["columns"])
            .first()
        )

    def _previous_rows_for_rows(self, rows):
        rows_by_audit_label = defaultdict(list)
        audit_tables_by_label = {}
        for audit_table, row in rows:
            audit_label = audit_table["audit_label"]
            audit_tables_by_label[audit_label] = audit_table
            rows_by_audit_label[audit_label].append(row)

        previous_rows = {}
        for audit_label, audit_rows in rows_by_audit_label.items():
            audit_table = audit_tables_by_label[audit_label]
            max_pgh_id_by_obj_id = defaultdict(int)
            for row in audit_rows:
                max_pgh_id_by_obj_id[row["pgh_obj_id"]] = max(
                    max_pgh_id_by_obj_id[row["pgh_obj_id"]], row["pgh_id"]
                )

            filters = Q()
            for pgh_obj_id, pgh_id in max_pgh_id_by_obj_id.items():
                filters |= Q(pgh_obj_id=pgh_obj_id, pgh_id__lt=pgh_id)

            candidates_by_obj_id = defaultdict(list)
            for previous in (
                audit_table["model"]
                .objects.filter(filters)
                .order_by("pgh_obj_id", "-pgh_id")
                .values(*audit_table["columns"])
            ):
                candidates_by_obj_id[previous["pgh_obj_id"]].append(previous)

            for row in audit_rows:
                previous = next(
                    (
                        candidate
                        for candidate in candidates_by_obj_id[row["pgh_obj_id"]]
                        if candidate["pgh_id"] < row["pgh_id"]
                    ),
                    None,
                )
                if previous:
                    previous_rows[(audit_label, row["pgh_id"])] = previous

        return previous_rows


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


@extend_schema(
    methods=["POST"],
    request=OpenApiRequest(request=IncidentRequestSerializer),
    responses={200: {}},
)
class IncidentRequestView(
    RudimentaryUserPathLoggingMixin,
    SubFlawViewGetMixin,
    APIView,
):
    def post(self, request, *args, **kwargs):
        flaw = self.get_flaw()
        serializer = IncidentRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        FlawComment.objects.create(
            creator=getattr(request.user, "email", ""),
            is_private=True,
            text=serializer.validated_data["comment"],
            flaw=flaw,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        flaw.major_incident_state = serializer.validated_data["kind"]
        flaw.save()
        return Response()


# AI-Generated: GPT-5.2
@extend_schema(description="Read-only view for sync managers")
class SyncManagerViewSet(RudimentaryUserPathLoggingMixin, ReadOnlyModelViewSet):
    serializer_class = SyncManagerSerializer
    queryset = SyncManager.objects.all().order_by("-last_scheduled_dt", "-id")
    filterset_class = SyncManagerFilter
