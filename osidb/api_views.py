"""
implement osidb rest api views
"""

import logging
from urllib.parse import urljoin

import pkg_resources
from django.conf import settings
from django.core.exceptions import BadRequest
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from packageurl import PackageURL
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from .constants import OSIDB_API_VERSION, PYPI_URL, URL_REGEX
from .core import generate_acls
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


def get_valid_http_methods(cls):
    """
    Removes blacklisted and unsafe HTTP methods from a view if necessary.

    Blacklisted HTTP methods can be defined in the django settings, unsafe HTTP
    methods will be removed if the app is running in read-only mode, by setting
    the OSIDB_READONLY_MODE env variable to "1".

    :param cls: The ViewSet class from which http_method_names are inherited
    :return: A list of valid HTTP methods that a ViewSet will accept
    """
    base_methods = cls.http_method_names
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
        if method in settings.BLACKLISTED_HTTP_METHODS:
            continue
        if settings.READONLY_MODE and method in unsafe_methods:
            continue
        valid_methods.append(method)
    return valid_methods


###################
# API VIEW MIXINS #
###################


class ModelViewSetMixin(ModelViewSet):
    # general mixin class defining some common attributes and concepts
    #
    # TODO this is not a proper class doc string as it would generate
    # a ton of unrelated API endpoint descriptions in OpenAPI schema

    http_method_names = get_valid_http_methods(ModelViewSet)
    permission_classes = [IsAuthenticatedOrReadOnly]

    def perform_save(self, serializer, **kwargs) -> None:
        """
        common functionality to perform create and update
        """
        serializer.save(**kwargs)

    def perform_create(self, serializer) -> None:
        """
        perform create by save
        """
        self.perform_save(serializer)

    def perform_update(self, serializer) -> None:
        """
        perform update by save
        """
        self.perform_save(serializer)


class ValidateModelViewSetMixin(ModelViewSetMixin):
    # mixin class defining mechanism of API validations
    # which are unlike model validations tied to query itself
    #
    # TODO this is not a proper class doc string as it would generate
    # a ton of unrelated API endpoint descriptions in OpenAPI schema

    _mandatory_attrs = None
    _mandatory_params = None

    def _validate_mandatory_attrs(self):
        """
        validate that all mandatory data attributes were provided
        """
        if self._mandatory_attrs is None:
            return

        for attr in self._mandatory_attrs:
            if self.request.data.get(attr) is None:
                raise BadRequest(f"Mandatory data attribute missing: {attr}")

    def _validate_mandatory_params(self):
        """
        validate that all mandatory query params were provided
        """
        if self._mandatory_params is None:
            return

        for param in self._mandatory_params:
            if self.request.query_params.get(param) is None:
                raise BadRequest(f"Mandatory query parameter missing: {param}")

    def validate(self) -> None:
        """
        validate query
        raises BadRequest
        """
        for validation_name in [
            item for item in dir(self) if item.startswith("_validate_")
        ]:
            # run every defined validation
            getattr(self, validation_name)()

    def create(self, request, *args, **kwargs) -> Response:
        """
        create model instance if valid
        """
        self.validate()
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs) -> Response:
        """
        update model instance if valid
        """
        self.validate()
        return super().update(request, *args, **kwargs)


class ACLModelViewSet(ValidateModelViewSetMixin):
    # model view class for entities with LDAP based ACLs
    #
    # TODO this is not a proper class doc string as it would generate
    # a ton of unrelated API endpoint descriptions in OpenAPI schema

    # ALCs are nothing we can be just guessing or setting to a default value but we
    # want a complete information from the user on what visibility/access to set
    _mandatory_attrs = ["acl_read", "acl_write"]

    def _validate_acl_member(self):
        """
        validate that the current user is member of all LDAP groups (s)he provides
        with the access so there is no access expansion beyond the user permissions
        """
        acl_read = self.request.data.get("acl_read")
        acl_write = self.request.data.get("acl_write")

        # existence check is out of scope
        if not acl_read or not acl_write:
            return

        acls = [group.name for group in self.request.user.groups.all()]
        for acl in acl_read + acl_write:
            # this is a temporary safeguard with a very simple philosophy that one cannot
            # give access to something (s)he does not have access to but possibly in the future
            # we will want some more clever handling like ProdSec can grant anything etc.
            if acl not in acls:
                raise BadRequest(
                    f"Cannot provide access for the LDAP group without being a member: {acl}"
                )

    def perform_save(self, serializer, **kwargs):
        """
        enrich the save parameters with the pre-processed ACLs
        """
        super().perform_save(
            serializer,
            # in the outer we use human-readable LDAP groups names but
            # inside we use the ACL hashes which are actually stored in DB
            acl_read=generate_acls(self.request.data["acl_read"]),
            acl_write=generate_acls(self.request.data["acl_write"]),
            **kwargs,
        )


class BugzillaModelViewSet(ACLModelViewSet):
    # model view class for entities which Bugzilla is the authoritative source of
    # because their handling has some specific common requirements or restrictions
    #
    # TODO this is not a proper class doc string as it would generate
    # a ton of unrelated API endpoint descriptions in OpenAPI schema

    # extend the mandatory parameters with the Bugzilla API key
    # which is required to keep the Bugzilla audit log correct
    # as the change is done by the user and not the service
    _mandatory_params = ["bz_api_key"]


#############
# API VIEWS #
#############


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
    create=extend_schema(
        responses=FlawSerializer,
        parameters=[
            OpenApiParameter(
                "bz_api_key",
                type={"type": "string"},
                location=OpenApiParameter.QUERY,
                required=True,
                description=(
                    "Bugzilla API key of the account performing the operation"
                ),
            ),
        ],
    ),
    update=extend_schema(
        responses=FlawSerializer,
        parameters=[
            id_param,
            OpenApiParameter(
                "bz_api_key",
                type={"type": "string"},
                location=OpenApiParameter.QUERY,
                required=True,
                description=(
                    "Bugzilla API key of the account performing the operation"
                ),
            ),
        ],
    ),
)
class FlawView(BugzillaModelViewSet):
    queryset = Flaw.objects.all()
    serializer_class = FlawSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = FlawFilter
    lookup_url_kwarg = "id"

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

    def destroy(self, *args, **kwargs):
        # TODO in Bugzilla it is not possible to delete an already existing flaw
        # so deal with it when it is no more the authoritative source of the flaw data
        raise NotImplementedError(
            "Bugzilla nature does not allow to delete an existing flaw "
            "and OSIDB is not yet the authoritative source of the flaw data"
        )


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


@extend_schema_view(
    create=extend_schema(
        responses=AffectSerializer,
        parameters=[
            OpenApiParameter(
                "bz_api_key",
                type={"type": "string"},
                location=OpenApiParameter.QUERY,
                required=True,
                description=(
                    "Bugzilla API key of the account performing the operation"
                ),
            ),
        ],
    ),
    update=extend_schema(
        responses=AffectSerializer,
        parameters=[
            OpenApiParameter(
                "bz_api_key",
                type={"type": "string"},
                location=OpenApiParameter.QUERY,
                required=True,
                description=(
                    "Bugzilla API key of the account performing the operation"
                ),
            ),
        ],
    ),
)
class AffectView(BugzillaModelViewSet):
    queryset = Affect.objects.all()
    serializer_class = AffectSerializer
    filterset_class = AffectFilter


class TrackerView(ModelViewSetMixin):
    queryset = Tracker.objects.all()
    serializer_class = TrackerSerializer
    filterset_class = TrackerFilter

    def perform_save(self, *args, **kwargs) -> None:
        """
        this is not yet implemented in OSIDB - no sync to backends
        """
        raise NotImplementedError(
            "Tracker write operations are not yet supported in OSIDB"
        )

    def destroy(self, *args, **kwargs):
        """
        delete operation is temporarily restricted
        """
        self.perform_save()
