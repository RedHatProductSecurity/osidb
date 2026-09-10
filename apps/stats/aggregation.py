from datetime import datetime, timedelta
from typing import Any, Callable

from django.db.models import (
    Case,
    CharField,
    Count,
    DateTimeField,
    DurationField,
    ExpressionWrapper,
    F,
    QuerySet,
    Value,
    When,
)

from osidb.models import PsModule

DEFAULT_BOUNDS: list[int] = [7, 30, 90]
# label for flaws whose affects map to no known product (or that have no affects)
UNMAPPED_PS_PRODUCT: str = "No product"
BUCKET_DIMENSIONS: list[str] = ["age_bucket", "embargo_duration_bucket"]
# SECURITY: the stats view runs under bypass_rls, so every dimension value here
# is exposed to ALL authenticated users, embargoed flaws included. Only add
# NON-IDENTIFYING, low-cardinality fields (categorical/bucketed). NEVER add
# identifiers or free text (cve_id, title, description, ps_component, ...) — that
# would let an unprivileged caller enumerate embargoed flaws via count=1 groups.
# Changing this set is a security decision; the pinning test must be updated too.
DIMENSIONS: list[str] = [
    "impact",
    "workflow_state",
    "workflow_name",
    "ps_product",
] + BUCKET_DIMENSIONS


def bucket_labels(bounds: list[int]) -> list[str]:
    """
    Build contiguous bucket labels from ascending day cut points, plus an
    open-ended tail. E.g. ``[7, 30, 90]`` -> ``["0-7", "8-30", "31-90", "91+"]``.
    """
    labels = [f"{0 if i == 0 else bounds[i - 1] + 1}-{b}" for i, b in enumerate(bounds)]
    return labels + [f"{bounds[-1] + 1}+"]


def _annotate_dimensions(
    queryset: QuerySet, dimensions: list[str], bounds: list[int], now: datetime
) -> QuerySet:
    if "ps_product" in dimensions:
        products = dict(PsModule.objects.values_list("name", "ps_product__short_name"))
        queryset = queryset.annotate(
            ps_product=Case(
                *(
                    When(affects__ps_module=module, then=Value(product))
                    for module, product in products.items()
                ),
                default=Value(UNMAPPED_PS_PRODUCT),
                output_field=CharField(),
            )
        )
    labels = bucket_labels(bounds)
    if "age_bucket" in dimensions:
        queryset = queryset.annotate(
            age_bucket=Case(
                *(
                    When(created_dt__gte=now - timedelta(days=b), then=Value(label))
                    for b, label in zip(bounds, labels)
                ),
                default=Value(labels[-1]),
                output_field=CharField(),
            )
        )
    if "embargo_duration_bucket" in dimensions:
        queryset = queryset.annotate(
            _embargo_duration=ExpressionWrapper(
                Case(
                    When(embargoed=True, then=Value(now)),
                    default=F("unembargo_dt"),
                    output_field=DateTimeField(),
                )
                - F("created_dt"),
                output_field=DurationField(),
            ),
            embargo_duration_bucket=Case(
                *(
                    When(_embargo_duration__lte=timedelta(days=b), then=Value(label))
                    for b, label in zip(bounds, labels)
                ),
                default=Value(labels[-1]),
                output_field=CharField(),
            ),
        )
    return queryset


def _sort_key(
    dimensions: list[str], bounds: list[int]
) -> Callable[[dict[str, Any]], tuple]:
    order = {label: i for i, label in enumerate(bucket_labels(bounds))}

    def key(row: dict[str, Any]) -> tuple:
        # buckets sort by chronological index, other dimensions by string value
        return tuple(
            order.get(row[dimension], len(order))
            if dimension in BUCKET_DIMENSIONS
            else row[dimension]
            for dimension in dimensions
        )

    return key


def count_flaws_by(
    queryset: QuerySet, dimensions: list[str], bounds: list[int], now: datetime
) -> list[dict[str, Any]]:
    """COUNT(DISTINCT flaw) grouped by dimensions, deterministically ordered."""
    groups = (
        _annotate_dimensions(queryset, dimensions, bounds, now)
        .values(*dimensions)
        .annotate(count=Count("pk", distinct=True))
    )
    return sorted(groups, key=_sort_key(dimensions, bounds))
