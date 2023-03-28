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
)

from .models import Affect, Flaw, Tracker, search_helper


class CharInFilter(BaseInFilter, CharFilter):
    """
    Filter for char csv
    """

    pass


class FlawFilter(FilterSet):
    """
    Class that filters queries to FlawList view / API endpoint based on Flaw fields (currently only supports updated_dt)
    """

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
        fields = [
            "uuid",
            "cve_id",
            "type",
            "created_dt",
            "updated_dt",
            "impact",
            "cwe_id",
            "embargoed",
            "unembargo_dt",
            "source",
            "reported_dt",
            "cvss2",
            "cvss2_score",
            "cvss3",
            "cvss3_score",
        ]

    search_helper = staticmethod(search_helper)
    # Set the class method to be the same as the imported method (and make it static, to avoid breaking on a self param)
    # This ugly hack is needed to reuse code. django-filter requires the method to be defined as part of this class
    # models.py needs to use the method for FlawManager and FlawHistoryManager, but can't define here + import there
    # This would cause a circular import, so instead we define there + import here and set the property


class AffectFilter(FilterSet):
    class Meta:
        model = Affect
        fields = [
            "uuid",
            "flaw",
            "type",
            "affectedness",
            "resolution",
            "ps_module",
            "ps_component",
            "impact",
        ]


class TrackerFilter(FilterSet):
    class Meta:
        model = Tracker
        fields = [
            "uuid",
            "type",
            "external_system_id",
            "status",
            "resolution",
            "ps_update_stream",
        ]
