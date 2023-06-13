"""
Implement filters for OSIDB REST API results
"""

from django.db.models import Q
from django_filters.rest_framework import (
    BaseInFilter,
    BooleanFilter,
    CharFilter,
    DateTimeFilter,
    FilterSet,
    NumberFilter,
    OrderingFilter,
)

from .models import Affect, Flaw, FlawComment, Tracker, search_helper

LT_GT_LOOKUP_EXPRS = ["lt", "gt"]
LTE_GTE_LOOKUP_EXPRS = ["lte", "gte"]
DATE_LOOKUP_EXPRS = ["date__exact", "date__lte", "date__gte"]


class CharInFilter(BaseInFilter, CharFilter):
    """
    Filter for char csv
    """

    pass


class DistinctFilterSet(FilterSet):
    """
    Custom FilterSet which enforces the distinct for field names that starts
    with specified prefixes so filtering on related models would not cause
    duplicates results.

    Each subclassed FilterSet should define its own `DISTINCT_FIELDS_PREFIXES`
    tuple

    NOTE: django-filters provides ways how to override the behavior of the
    default filters however only in a way `all or nothing` and doing a
    distinct is only needed for filtering on related models.

    NOTE: Overriding also does not currently work for the choice fields
    according to this issue https://github.com/carltongibson/django-filter/issues/1475
    and thus this custom filter would be needed nevertheless

    """

    DISTINCT_FIELDS_PREFIXES = ()

    def __init__(self, data=None, queryset=None, *, request=None, prefix=None):
        super().__init__(data, queryset, request=request, prefix=prefix)

        # Set distinct filter option to true for every field
        # with any of specified prefixes
        if self.DISTINCT_FIELDS_PREFIXES:
            for filter_ in self.filters.values():
                if filter_.field_name.startswith(self.DISTINCT_FIELDS_PREFIXES):
                    filter_.distinct = True


class FlawFilter(DistinctFilterSet):
    """
    Class that filters queries to FlawList view / API endpoint based on Flaw fields (currently only supports updated_dt)
    """

    DISTINCT_FIELDS_PREFIXES = ("affects__",)

    cve_id = CharInFilter(field_name="cve_id")

    changed_after = DateTimeFilter(
        field_name="updated_dt", method="changed_after_filter"
    )
    changed_before = DateTimeFilter(
        field_name="updated_dt", method="changed_before_filter"
    )
    bz_id = NumberFilter(field_name="meta_attr__bz_id", lookup_expr="exact")
    tracker_ids = CharInFilter(
        field_name="affects__trackers__external_system_id",
        lookup_expr="in",
        distinct=True,
    )
    # Name on left is name of query param user will provide, like "GET /flaws?changed_after=2021-08-31T01:23:45+00:00"

    search = CharFilter(method="search_helper")
    # We override the default filter() method with search_helper() to use search operators and rankings
    # User input in query parameter becomes a SearchQuery, is compared to all text fields when field_name is empty
    # Else when field_name is specified, search only that field

    title = CharFilter(field_name="title", method="search_helper")
    description = CharFilter(field_name="description", method="search_helper")
    summary = CharFilter(field_name="summary", method="search_helper")
    statement = CharFilter(field_name="statement", method="search_helper")
    embargoed = BooleanFilter(field_name="embargoed")
    affects__embargoed = BooleanFilter(field_name="affects__embargoed")
    affects__trackers__embargoed = BooleanFilter(
        field_name="affects__trackers__embargoed"
    )

    def changed_after_filter(self, queryset, name, value):
        """
        Returns a Flaw if it or any of its affects/trackers have been updated after `value`
        """
        return queryset.filter(
            Q(updated_dt__gte=value)
            | Q(affects__updated_dt__gte=value)
            | Q(affects__trackers__updated_dt__gte=value)
        ).distinct()

    def changed_before_filter(self, queryset, name, value):
        """
        Returns a Flaw if it or any of its affects/trackers have been updated before `value`
        """
        return queryset.filter(
            Q(updated_dt__lte=value)
            | Q(affects__updated_dt__lte=value)
            | Q(affects__trackers__updated_dt__lte=value)
        ).distinct()

    class Meta:
        """
        Class that defines some Filter properties. Can be used to auto-generate filters, but param names are less useful
        """

        model = Flaw
        fields = {
            # Flaw fields
            "uuid": ["exact"],
            "cve_id": ["exact"],
            "type": ["exact"],
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "impact": ["exact"],
            "cwe_id": ["exact"],
            "unembargo_dt": ["exact"],
            "source": ["exact"],
            "reported_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "cvss2": ["exact"],
            "cvss2_score": ["exact"] + LT_GT_LOOKUP_EXPRS + LTE_GTE_LOOKUP_EXPRS,
            "cvss3": ["exact"],
            "cvss3_score": ["exact", "lt"] + LT_GT_LOOKUP_EXPRS + LTE_GTE_LOOKUP_EXPRS,
            "nvd_cvss2": ["exact"],
            "nvd_cvss3": ["exact"],
            "component": ["exact"],
            "is_major_incident": ["exact"],
            # Affect fields
            "affects__uuid": ["exact"],
            "affects__type": ["exact"],
            "affects__affectedness": ["exact"],
            "affects__resolution": ["exact"],
            "affects__ps_module": ["exact"],
            "affects__ps_component": ["exact"],
            "affects__impact": ["exact"],
            "affects__cvss2": ["exact"],
            "affects__cvss2_score": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS,
            "affects__cvss3": ["exact"],
            "affects__cvss3_score": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS,
            "affects__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            # Tracker fields
            "affects__trackers__uuid": ["exact"],
            "affects__trackers__type": ["exact"],
            "affects__trackers__external_system_id": ["exact"],
            "affects__trackers__status": ["exact"],
            "affects__trackers__resolution": ["exact"],
            "affects__trackers__ps_update_stream": ["exact"],
            "affects__trackers__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__trackers__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
        }

    order = OrderingFilter(fields=Meta.fields.keys())

    search_helper = staticmethod(search_helper)
    # Set the class method to be the same as the imported method (and make it static, to avoid breaking on a self param)
    # This ugly hack is needed to reuse code. django-filter requires the method to be defined as part of this class
    # models.py needs to use the method for FlawManager and FlawHistoryManager, but can't define here + import there
    # This would cause a circular import, so instead we define there + import here and set the property


class AffectFilter(DistinctFilterSet):

    DISTINCT_FIELDS_PREFIXES = ("flaw__", "affects__")

    embargoed = BooleanFilter(field_name="embargoed")
    trackers__embargoed = BooleanFilter(field_name="trackers__embargoed")
    flaw__embargoed = BooleanFilter(field_name="flaw__embargoed")

    class Meta:
        model = Affect
        fields = {
            "uuid": ["exact"],
            "type": ["exact"],
            "affectedness": ["exact"],
            "resolution": ["exact"],
            "ps_module": ["exact"],
            "ps_component": ["exact"],
            "impact": ["exact"],
            "cvss2": ["exact"],
            "cvss2_score": ["exact"] + LT_GT_LOOKUP_EXPRS + LTE_GTE_LOOKUP_EXPRS,
            "cvss3": ["exact"],
            "cvss3_score": ["exact"] + LT_GT_LOOKUP_EXPRS + LTE_GTE_LOOKUP_EXPRS,
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            # Flaw fields
            "flaw__uuid": ["exact"],
            "flaw__cve_id": ["exact"],
            "flaw__type": ["exact"],
            "flaw__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "flaw__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "flaw__impact": ["exact"],
            "flaw__cwe_id": ["exact"],
            "flaw__unembargo_dt": ["exact"],
            "flaw__source": ["exact"],
            "flaw__reported_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "flaw__cvss2": ["exact"],
            "flaw__cvss2_score": ["exact"] + LT_GT_LOOKUP_EXPRS + LTE_GTE_LOOKUP_EXPRS,
            "flaw__cvss3": ["exact"],
            "flaw__cvss3_score": ["exact", "lt"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS,
            "flaw__nvd_cvss2": ["exact"],
            "flaw__nvd_cvss3": ["exact"],
            "flaw__component": ["exact"],
            "flaw__is_major_incident": ["exact"],
            # Tracker fields
            "trackers__uuid": ["exact"],
            "trackers__type": ["exact"],
            "trackers__external_system_id": ["exact"],
            "trackers__status": ["exact"],
            "trackers__resolution": ["exact"],
            "trackers__ps_update_stream": ["exact"],
            "trackers__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "trackers__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
        }

    order = OrderingFilter(fields=Meta.fields.keys())


class TrackerFilter(DistinctFilterSet):

    DISTINCT_FIELDS_PREFIXES = ("affects__",)

    embargoed = BooleanFilter(field_name="embargoed")
    affects__embargoed = BooleanFilter(field_name="affects__embargoed")
    affects__flaw__embargoed = BooleanFilter(field_name="flaw__embargoed")

    class Meta:
        model = Tracker
        fields = {
            "uuid": ["exact"],
            "type": ["exact"],
            "external_system_id": ["exact"],
            "status": ["exact"],
            "resolution": ["exact"],
            "ps_update_stream": ["exact"],
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            # Affect fields
            "affects__uuid": ["exact"],
            "affects__type": ["exact"],
            "affects__affectedness": ["exact"],
            "affects__resolution": ["exact"],
            "affects__ps_module": ["exact"],
            "affects__ps_component": ["exact"],
            "affects__impact": ["exact"],
            "affects__cvss2": ["exact"],
            "affects__cvss2_score": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS,
            "affects__cvss3": ["exact"],
            "affects__cvss3_score": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS,
            "affects__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            # Flaw fields
            "affects__flaw__uuid": ["exact"],
            "affects__flaw__cve_id": ["exact"],
            "affects__flaw__type": ["exact"],
            "affects__flaw__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__flaw__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__flaw__impact": ["exact"],
            "affects__flaw__cwe_id": ["exact"],
            "affects__flaw__unembargo_dt": ["exact"],
            "affects__flaw__source": ["exact"],
            "affects__flaw__reported_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__flaw__cvss2": ["exact"],
            "affects__flaw__cvss2_score": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS,
            "affects__flaw__cvss3": ["exact"],
            "affects__flaw__cvss3_score": ["exact", "lt"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS,
            "affects__flaw__nvd_cvss2": ["exact"],
            "affects__flaw__nvd_cvss3": ["exact"],
            "affects__flaw__component": ["exact"],
            "affects__flaw__is_major_incident": ["exact"],
        }

    order = OrderingFilter(fields=Meta.fields.keys())


class FlawCommentFilter(FilterSet):
    class Meta:
        model = FlawComment
        fields = {
            "uuid": ["exact"],
            "order": ["exact"],
            "external_system_id": ["exact"],
        }
