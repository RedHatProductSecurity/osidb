from datetime import date, datetime
from typing import Any

from django.core.validators import EMPTY_VALUES
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from osidb.api_views import RudimentaryUserPathLoggingMixin
from osidb.constants import DATETIME_FMT
from osidb.filters import OSIDBFilterSet
from osidb.helpers import bypass_rls
from osidb.mixins import ACLMixinVisibility
from osidb.models import Flaw, Impact, Tracker

from .aggregation import (
    BUCKET_DIMENSIONS,
    DEFAULT_BOUNDS,
    FLAW_DIMENSIONS,
    TRACKER_DIMENSIONS,
    count_flaws_by,
    count_trackers_by,
)
from .constants import MAX_BUCKET_BOUNDS, StatsAppSettings
from .filters import StatsFlawFilter, StatsTrackerFilter
from .serializers import StatsFlawsResponseSerializer, StatsTrackersResponseSerializer


def parse_group_by(request: Request, dimension_list: list[str]) -> list[str]:
    """Parse and validate the required ``group_by`` param; order is preserved."""
    raw: str = request.query_params.get("group_by", "")
    dimensions = [dimension for part in raw.split(",") if (dimension := part.strip())]
    if not dimensions:
        raise ValidationError({"group_by": "This query parameter is required."})

    invalid = [dimension for dimension in dimensions if dimension not in dimension_list]
    if invalid:
        raise ValidationError(
            {"group_by": f"Unsupported dimension(s): {', '.join(invalid)}."}
        )

    return list(dict.fromkeys(dimensions))


def parse_bounds(request: Request) -> list[int]:
    """
    Parse the optional ``age_bucket_bounds`` param into positive, strictly
    ascending day cut points; defaults to DEFAULT_BOUNDS.

    E.g.
    ``"7,30,90"`` -> ``[7, 30, 90]`` (buckets 0-7, 8-30, 31-90, 91+),
    ``"30"`` -> ``[30]`` (buckets 0-30, 31+).
    """
    raw: str | None = request.query_params.get("age_bucket_bounds")
    if not raw:
        return DEFAULT_BOUNDS

    try:
        bounds = [int(bound) for part in raw.split(",") if (bound := part.strip())]
    except ValueError:
        raise ValidationError(
            {"age_bucket_bounds": "Must be a comma-separated list of integers."}
        )
    if (
        not bounds
        or len(bounds) > MAX_BUCKET_BOUNDS
        or any(bound <= 0 for bound in bounds)
        or bounds != sorted(set(bounds))
    ):
        raise ValidationError(
            {
                "age_bucket_bounds": (
                    f"Must be 1 to {MAX_BUCKET_BOUNDS} positive, strictly "
                    "ascending integers."
                )
            }
        )
    return bounds


def serialize_applied_filters(generic_filter: OSIDBFilterSet) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    for name, value in generic_filter.form.cleaned_data.items():
        if value in EMPTY_VALUES:
            continue

        if isinstance(value, (list, tuple)):
            filters[name] = [str(item) for item in value]
        elif isinstance(value, (datetime, date)):
            filters[name] = value.isoformat()
        else:
            filters[name] = value
    return filters


def _in_param(
    name: str, description: str, enum: list[str] | None = None
) -> OpenApiParameter:
    """A comma-separated ``__in`` / ``__not_in`` filter parameter."""
    item: dict[str, Any] = {"type": "string"}
    if enum:
        item["enum"] = enum
    return OpenApiParameter(
        name,
        type={"type": "array", "items": item},
        location=OpenApiParameter.QUERY,
        required=False,
        description=description,
        style="form",
        explode=False,
    )


def _empty_param(name: str, description: str) -> OpenApiParameter:
    """A boolean ``__isempty`` filter parameter."""
    return OpenApiParameter(
        name,
        type={"type": "boolean"},
        location=OpenApiParameter.QUERY,
        required=False,
        description=description,
        style="form",
        explode=False,
    )


STATS_FLAW_PARAMETERS: list[OpenApiParameter] = [
    OpenApiParameter(
        "group_by",
        type={"type": "array", "items": {"type": "string", "enum": FLAW_DIMENSIONS}},
        location=OpenApiParameter.QUERY,
        required=True,
        description=(
            "Required. Comma-separated dimensions to group by. "
            f"Allowed: {', '.join(FLAW_DIMENSIONS)}."
        ),
        style="form",
        explode=False,
    ),
    OpenApiParameter(
        "age_bucket_bounds",
        type=str,
        location=OpenApiParameter.QUERY,
        required=False,
        description=(
            "Comma-separated, strictly ascending positive day cut points for "
            "age_bucket / embargo_duration_bucket. Default: 7,30,90."
        ),
    ),
    _in_param(
        "visibility__in",
        "Keep only flaws with these visibilities.",
        ACLMixinVisibility.values,
    ),
    _in_param(
        "visibility__not_in",
        "Drop flaws with these visibilities.",
        ACLMixinVisibility.values,
    ),
    _in_param("impact__in", "Keep only these impacts.", Impact.values),
    _in_param("impact__not_in", "Drop these impacts.", Impact.values),
    _in_param("workflow_state__in", "Keep only these workflow states."),
    _in_param("workflow_state__not_in", "Drop these workflow states."),
    _empty_param(
        "workflow_state__isempty", "Filter for empty or non-empty workflow states."
    ),
    _in_param("workflow_name__in", "Keep only these workflow names."),
    _in_param("workflow_name__not_in", "Drop these workflow names."),
    _empty_param(
        "workflow_name__isempty", "Filter for empty or non-empty workflow names."
    ),
    _in_param("ps_product__in", "Keep flaws with >=1 affect in these products."),
    _in_param("ps_product__not_in", "Drop flaws with >=1 affect in these products."),
]


STATS_TRACKER_PARAMETERS: list[OpenApiParameter] = [
    OpenApiParameter(
        "group_by",
        type={"type": "array", "items": {"type": "string", "enum": TRACKER_DIMENSIONS}},
        location=OpenApiParameter.QUERY,
        required=True,
        description=(
            "Required. Comma-separated dimensions to group by. "
            f"Allowed: {', '.join(TRACKER_DIMENSIONS)}."
        ),
        style="form",
        explode=False,
    ),
    _in_param(
        "visibility__in",
        "Keep only trackers with these visibilities.",
        ACLMixinVisibility.values,
    ),
    _in_param(
        "visibility__not_in",
        "Drop trackers with these visibilities.",
        ACLMixinVisibility.values,
    ),
    _in_param(
        "ps_product__in", "Keep trackers with ps streams containing these products."
    ),
    _in_param(
        "ps_product__not_in", "Drop trackers with ps streams containing these products."
    ),
]


EXPERIMENTAL_MESSAGE = (
    "This endpoint is experimental and may change or be removed without notice. "
    "Do not build hard dependencies on its shape or behavior."
)


class StatsDisabled(APIException):
    status_code = 423
    default_detail = "Stats API is disabled."
    default_code = "stats_disabled"


class StatsFlawsView(RudimentaryUserPathLoggingMixin, GenericAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Flaw.objects.all()
    filter_backends = [DjangoFilterBackend]
    filterset_class = StatsFlawFilter
    serializer_class = StatsFlawsResponseSerializer

    @extend_schema(
        summary="[Experimental] Aggregated flaw statistics",
        description=f"**Experimental.** {EXPERIMENTAL_MESSAGE}",
        parameters=STATS_FLAW_PARAMETERS,
        responses={200: StatsFlawsResponseSerializer},
    )
    @bypass_rls
    def get(self, request: Request) -> Response:
        # SECURITY: this runs under bypass_rls, so embargoed flaws are always in
        # scope. The response MUST stay aggregate-only (grouped counts + meta) and
        # MUST NOT include per-flaw fields; doing so would expose embargoed data to
        # unprivileged callers. Change the response shape only with that in mind.
        # See FLAW_DIMENSIONS in aggregation.py and the safety-contract tests.
        if not StatsAppSettings().enabled:
            raise StatsDisabled()

        dimensions = parse_group_by(request, FLAW_DIMENSIONS)
        bounds = parse_bounds(request)
        now = timezone.now()

        flaw_filter = self.filterset_class(
            request.query_params, queryset=self.get_queryset(), request=request
        )
        if not flaw_filter.is_valid():
            raise ValidationError(flaw_filter.errors)
        queryset = flaw_filter.qs

        groups = count_flaws_by(queryset, dimensions, bounds, now)

        meta: dict[str, Any] = {
            "total_flaws": queryset.distinct().count(),
            "sum_group_counts": sum(group["count"] for group in groups),
            "group_by": dimensions,
            "filters": serialize_applied_filters(flaw_filter),
            "generated_at": now.strftime(DATETIME_FMT),
        }
        if any(d in BUCKET_DIMENSIONS for d in dimensions):
            meta["age_bucket_bounds"] = bounds

        response = Response({"groups": groups, "meta": meta})
        # 299 = Miscellaneous Persistent Warning; flags the endpoint as unstable
        response["Warning"] = f'299 - "Experimental: {EXPERIMENTAL_MESSAGE}"'
        return response


class StatsTrackerView(RudimentaryUserPathLoggingMixin, GenericAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Tracker.objects.all()
    filter_backends = [DjangoFilterBackend]
    filterset_class = StatsTrackerFilter
    serializer_class = StatsTrackersResponseSerializer

    @extend_schema(
        summary="[Experimental] Aggregated tracker statistics",
        description=f"**Experimental.** {EXPERIMENTAL_MESSAGE}",
        parameters=STATS_TRACKER_PARAMETERS,
        responses={200: StatsTrackersResponseSerializer},
    )
    @bypass_rls
    def get(self, request: Request) -> Response:
        # SECURITY: this runs under bypass_rls, so embargoed trackers are always in
        # scope. The response MUST stay aggregate-only (grouped counts + meta) and
        # MUST NOT include per-tracker fields; doing so would expose embargoed data to
        # unprivileged callers. Change the response shape only with that in mind.
        # See TRACKER_DIMENSIONS in aggregation.py and the safety-contract tests.
        if not StatsAppSettings().enabled:
            raise StatsDisabled()

        dimensions = parse_group_by(request, TRACKER_DIMENSIONS)

        tracker_filter = self.filterset_class(
            request.query_params, queryset=self.get_queryset(), request=request
        )
        if not tracker_filter.is_valid():
            raise ValidationError(tracker_filter.errors)
        queryset = tracker_filter.qs

        groups = count_trackers_by(queryset, dimensions)

        meta: dict[str, Any] = {
            "total_trackers": queryset.distinct().count(),
            "sum_group_counts": sum(group["count"] for group in groups),
            "group_by": dimensions,
            "filters": serialize_applied_filters(tracker_filter),
            "generated_at": timezone.now().strftime(DATETIME_FMT),
        }

        response = Response({"groups": groups, "meta": meta})
        # 299 = Miscellaneous Persistent Warning; flags the endpoint as unstable
        response["Warning"] = f'299 - "Experimental: {EXPERIMENTAL_MESSAGE}"'
        return response
