from django.db.models import QuerySet

from osidb.filters import (
    CharInFilter,
    ChoiceInFilter,
    OSIDBFilterSet,
)
from osidb.mixins import ACLMixinVisibility
from osidb.models import Impact, PsModule


class StatsFlawFilter(OSIDBFilterSet):
    visibility__in = ChoiceInFilter(
        field_name="visibility", lookup_expr="in", choices=ACLMixinVisibility.choices
    )
    visibility__not_in = ChoiceInFilter(
        field_name="visibility",
        lookup_expr="in",
        choices=ACLMixinVisibility.choices,
        exclude=True,
    )
    workflow_state__in = CharInFilter(field_name="workflow_state", lookup_expr="in")
    workflow_state__not_in = CharInFilter(
        field_name="workflow_state", lookup_expr="in", exclude=True
    )
    workflow_name__in = CharInFilter(field_name="workflow_name", lookup_expr="in")
    workflow_name__not_in = CharInFilter(
        field_name="workflow_name", lookup_expr="in", exclude=True
    )
    impact__in = ChoiceInFilter(
        field_name="impact", lookup_expr="in", choices=Impact.choices
    )
    impact__not_in = ChoiceInFilter(
        field_name="impact", lookup_expr="in", choices=Impact.choices, exclude=True
    )
    ps_product__in = CharInFilter(method="filter_ps_product_in")
    ps_product__not_in = CharInFilter(method="filter_ps_product_not_in")

    @staticmethod
    def _modules_for(products: list[str]) -> QuerySet:
        return PsModule.objects.filter(ps_product__short_name__in=products).values_list(
            "name", flat=True
        )

    def filter_ps_product_in(
        self, queryset: QuerySet, name: str, value: list[str]
    ) -> QuerySet:
        if not value:
            return queryset
        return queryset.filter(
            affects__ps_module__in=self._modules_for(value)
        ).distinct()

    def filter_ps_product_not_in(
        self, queryset: QuerySet, name: str, value: list[str]
    ) -> QuerySet:
        if not value:
            return queryset
        return queryset.exclude(affects__ps_module__in=self._modules_for(value))
