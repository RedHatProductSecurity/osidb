"""
Implement filters for OSIDB REST API results
"""
from typing import Union

from django.contrib.postgres.search import (
    SearchQuery,
    SearchRank,
    SearchVector,
    TrigramSimilarity,
)
from django.core.exceptions import FieldDoesNotExist
from django.core.validators import EMPTY_VALUES
from django.db import models
from django.db.models import Q
from django_filters.rest_framework import (
    BaseInFilter,
    BooleanFilter,
    CharFilter,
    ChoiceFilter,
    DateTimeFilter,
    FilterSet,
    NumberFilter,
    OrderingFilter,
)
from djangoql.queryset import apply_search

from apps.workflows.workflow import WorkflowModel
from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawReference,
    Package,
    Tracker,
)

from .djangoql import FlawQLSchema
from .mixins import Alert

LT_GT_LOOKUP_EXPRS = ["lt", "gt"]
LTE_GTE_LOOKUP_EXPRS = ["lte", "gte"]
DATE_LOOKUP_EXPRS = ["date__exact", "date__lte", "date__gte"]


class ChoiceInFilter(BaseInFilter, ChoiceFilter):
    """
    Filter for choice csv
    """

    pass


class CharInFilter(BaseInFilter, CharFilter):
    """
    Filter for char csv
    """

    pass


class EmptyOrNullStringFilter(BooleanFilter):
    """Filter for both empty and null string fields."""

    def filter(self, queryset, value):
        """
        Given a value of True or False, it will return the records that have an
        empty string or null value (True) or the ones that don't (False).
        """
        if value in EMPTY_VALUES:
            return queryset

        exclude = self.exclude ^ (value is False)
        method = queryset.exclude if exclude else queryset.filter
        query = Q(**{self.field_name: ""}) | Q(**{f"{self.field_name}__isnull": True})

        return method(query)


class EmptyCvssFilter(BooleanFilter):
    """Filter by whether the flaw has any CVSS with the given issuer and version."""

    def __init__(self, issuer, version, *args, **kwargs):
        self.issuer = issuer
        self.version = version
        super().__init__(*args, **kwargs)

    def filter(self, queryset, value):
        if value in EMPTY_VALUES:
            return queryset

        method = queryset.exclude if value else queryset.filter
        query = Q(cvss_scores__issuer=self.issuer) & Q(
            cvss_scores__version=self.version
        )
        return method(query).distinct()


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


class SparseFieldsFilterSet(FilterSet):
    def _preprocess_fields(self, value):
        """
        Converts a comma-separated list of fields into an ORM-friendly format.

        A list of fields passed-in to a filter will look something like:
            cve_id,affects.uuid,affects.trackers.resolution

        This method converts such a string into a Python list like so:
            ["cve_id", "affects__uuid", "affects__trackers__resolution"]
        """
        return value.replace(".", "__").split(",")

    def _filter_fields(self, fields):
        """
        Given a set of field names, returns a set of relations and valid fields.

        The argument `fields` can contain any number of user-provided fields,
        these fields may not exist, or they may be properties or any other
        kind of virtual, computed or relation field. Since the goal of these
        field names would be to use them in SQL, we need to make sure to only
        return database-persisted fields, and optionally relations.

        The result of this method can be safely passed down to
        prefetch_related() / only() / defer().
        """
        prefetch_set = set()
        field_set = set()
        for fname in list(fields):
            relation = fname
            if "__" in fname:
                # in the case of something like affects__trackers, we must
                # ensure that:
                # 1. the base field, in this case affects, is a valid model field
                # 2. the whole field relation is not passed to only() (field_set)
                # 3. the whole field relation is passed to prefetch_related
                #    (prefetch_set)
                # this guarantees that invalid fields such as __foo or
                # affectos__trackers (typo in base field) are handled properly.
                # note that something like affects__trackeros (typo in the N+1
                # relationship) is already ignored by Django.
                # the following code will check the existence of the base
                # relationship field and further down we'll prefetch the full
                # relationship (relation variable)
                fname = fname.split("__")[0]
                # we cannot prefetch e.g. affects__trackers__ps_component
                # this means that this won't be performant if we only pass
                # affects__trackers to include_fields, we'll consider this
                # a limitation of these filters.
                relation = relation.rsplit("__", 1)[0]
            try:
                # check that the field actually exists
                field = self._meta.model._meta.get_field(fname)
            except FieldDoesNotExist:
                continue
            if not field.concrete:
                # a field is concrete if it has a column in the database, we don't
                # want non-concrete fields as we cannot filter them via SQL
                if field.is_relation:
                    # related fields are somewhat exceptional in that while we
                    # cannot use them in only(), we can prefetch them, here we'll
                    # either add the relation if the field passed in contains
                    # multiple relationship traversal e.g. affects__trackers
                    # or just the fname e.g. affects
                    prefetch_set.add(relation)
                continue
            field_set.add(fname)
        return prefetch_set, field_set


class IncludeFieldsFilterSet(SparseFieldsFilterSet):
    include_fields = CharFilter(method="include_fields_filter")

    def include_fields_filter(self, queryset, name, value):
        """
        Optimizes a view's QuerySet based on user input.

        This filter will attempt to optimize a given view's queryset based on an
        allowlist of fields (value parameter) provided by the user in order to
        improve performance.

        It does so by leveraging the prefetch_related() and only() QuerySet
        methods, this solution is not perfect and should probably not be
        improved further as it can get very complicated very quickly.

        This filter does not use `select_related` for FK relations as the usage
        of FKs in OSIDB endpoints is seldom used.
        """
        # we want to convert e.g. foo.id to foo__id, so that it's easier to use
        # with Django's QuerySet.prefetch_related() method directly
        fields = self._preprocess_fields(value)
        # must verify that the requested fields are database-persisted fields,
        # properties, descriptors and related fields will yield errors
        to_prefetch, valid_fields = self._filter_fields(fields)
        return (
            queryset.prefetch_related(None)
            .prefetch_related(*list(to_prefetch))
            .only(*list(valid_fields))
        )


class ExcludeFieldsFilterSet(SparseFieldsFilterSet):
    exclude_fields = CharFilter(method="exclude_fields_filter")

    def exclude_fields_filter(self, queryset, name, value):
        """
        Optimizes a view's QuerySet based on user input.

        This filter will attempt to optimize a given view's queryset based on an
        denylist of fields provided by the user in order to improve performance.

        It does so by leveraging the prefetch_related() and defer() QuerySet
        methods, this solution is not perfect and should probably not be
        improved further as it can get very complicated very quickly.

        This filter does not use `select_related` for FK relations as the usage
        of FKs in OSIDB endpoints is seldom used.
        """
        fields = self._preprocess_fields(value)
        # note: we could attempt to optimize the prefetched fields but it is
        # a lot more complicated than the case for include_fields (which is
        # not perfect as it is), so the prefetch_set has been left as-is.
        _, valid_fields = self._filter_fields(fields)
        return queryset.defer(*list(valid_fields))


def search_helper(
    queryset: models.QuerySet,
    field_names: Union[str, tuple],
    field_value: str,  # Three positional args are expected by django-filters, keyword args can be added if needed
):
    """
    Customize search filter and other logic for Postgres full-text search

    By default, Django uses the plainto_tsquery() Postgres function, which doesn't support search operators
    We override this with websearch_to_tsquery() which supports "quoted phrases" and -exclusions
    We also extend logic here to support weighting and ranking search results, based on which column is matched
    """
    query = SearchQuery(field_value, search_type="websearch")

    if field_names and field_names != "search":
        # Search only field(s) user provided, weighted equally
        if isinstance(field_names, str):
            # django-filters gives exactly one field name as str, other users give tuple of fields to search
            field_names = (field_names,)

        vector = SearchVector(*field_names)

    else:  # Empty tuple or 'search' (default from django-filters when field name not specified)
        # Search all Flaw text columns, weighted so title is most relevant
        # TODO: Add logic to make this more generic (for any model) instead of assuming we are searching Flaws
        # We could just search all fields, or get only text fields from a model dynamically
        # Logic to set weights makes this more complicated
        vector = (
            SearchVector("title", weight="A")
            + SearchVector("cve_id", weight="A")
            + SearchVector("comment_zero", weight="B")
            + SearchVector("cve_description", weight="C")
            + SearchVector("statement", weight="D")
        )

    # Allow searching CVEs by similarity instead of tokens like full-text search does.
    # Using tokens, the word 'securit' will not match with 'security', and 'CVE-2001-04'
    # will not match with 'CVE-2001-0414'. This behavior may be intended for text based fields, but
    # when searching for CVEs it's probably because the user forgot part of, or the order of, the numbers.
    similarity = TrigramSimilarity("cve_id", field_value)

    rank = SearchRank(vector, query, cover_density=True)
    # Consider proximity of matching terms when ranking

    return (
        queryset.annotate(rank=rank, similarity=similarity)
        # The similarity threshold of 0.7 has been found by trial and error to work best with CVEs
        .filter(Q(rank__gt=0) | Q(similarity__gt=0.7)).order_by("-rank")
    )
    # Add "rank" column to queryset based on search result relevance
    # Exclude results that don't match (rank 0)
    # Order remaining results from highest rank to lowest


class FlawFilter(DistinctFilterSet, IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    """
    Class that filters queries to FlawList view / API endpoint based on Flaw fields (currently only supports updated_dt)
    """

    DISTINCT_FIELDS_PREFIXES = ("affects__",)

    cve_id = CharInFilter(field_name="cve_id")
    components = CharInFilter(field_name="components", lookup_expr="contains")

    changed_after = DateTimeFilter(
        field_name="updated_dt", method="changed_after_filter"
    )
    changed_before = DateTimeFilter(
        field_name="updated_dt", method="changed_before_filter"
    )

    query = CharFilter(method="query_filter")

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
    comment_zero = CharFilter(field_name="comment_zero", method="search_helper")
    cve_description = CharFilter(field_name="cve_description", method="search_helper")
    statement = CharFilter(field_name="statement", method="search_helper")
    embargoed = BooleanFilter(field_name="embargoed")
    workflow_state = ChoiceInFilter(
        field_name="workflow_state", choices=WorkflowModel.WorkflowState.choices
    )
    affects__embargoed = BooleanFilter(field_name="affects__embargoed")
    affects__trackers__embargoed = BooleanFilter(
        field_name="affects__trackers__embargoed"
    )
    cvss_scores__cvss_version = CharFilter(field_name="cvss_scores__version")

    # Emptiness filters
    cve_id__isempty = EmptyOrNullStringFilter(field_name="cve_id")
    cve_description__isempty = EmptyOrNullStringFilter(field_name="cve_description")
    statement__isempty = EmptyOrNullStringFilter(field_name="statement")
    mitigation__isempty = EmptyOrNullStringFilter(field_name="mitigation")
    owner__isempty = EmptyOrNullStringFilter(field_name="owner")
    cwe_id__isempty = EmptyOrNullStringFilter(field_name="cwe_id")
    cvss2_rh__isempty = EmptyCvssFilter(
        issuer=FlawCVSS.CVSSIssuer.REDHAT, version=FlawCVSS.CVSSVersion.VERSION2
    )
    cvss3_rh__isempty = EmptyCvssFilter(
        issuer=FlawCVSS.CVSSIssuer.REDHAT, version=FlawCVSS.CVSSVersion.VERSION3
    )
    cvss4_rh__isempty = EmptyCvssFilter(
        issuer=FlawCVSS.CVSSIssuer.REDHAT, version=FlawCVSS.CVSSVersion.VERSION4
    )
    cvss2_nist__isempty = EmptyCvssFilter(
        issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION2
    )
    cvss3_nist__isempty = EmptyCvssFilter(
        issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION3
    )
    cvss4_nist__isempty = EmptyCvssFilter(
        issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION4
    )

    def query_filter(self, queryset, name, value):
        return apply_search(queryset, value, schema=FlawQLSchema).distinct()

    def changed_after_filter(self, queryset, name, value):
        """
        Returns a Flaw if it or any of its affects/trackers have been updated after `value`
        """
        return queryset.filter(local_updated_dt__gte=value)

    def changed_before_filter(self, queryset, name, value):
        """
        Returns a Flaw if it or any of its affects/trackers have been updated before `value`
        """
        return queryset.filter(local_updated_dt__lte=value)

    class Meta:
        """
        Class that defines some Filter properties. Can be used to auto-generate filters, but param names are less useful
        """

        model = Flaw
        fields = {
            # Flaw fields
            "uuid": ["exact"],
            "cve_id": ["exact"],
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
            "components": ["exact"],
            "major_incident_state": ["exact"],
            "major_incident_start_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "requires_cve_description": ["exact"],
            "nist_cvss_validation": ["exact"],
            # Workflow fields
            "workflow_state": ["exact"],
            "owner": ["exact"],
            "team_id": ["exact"],
            # Affect fields
            "affects__uuid": ["exact"],
            "affects__affectedness": ["exact"],
            "affects__resolution": ["exact"],
            "affects__ps_module": ["exact"],
            "affects__ps_component": ["exact"],
            "affects__impact": ["exact"],
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
            "affects__trackers__errata__advisory_name": ["exact"],
            "affects__trackers__errata__et_id": ["exact"],
            "affects__trackers__errata__shipped_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            # Acknowledgment fields
            "acknowledgments__uuid": ["exact"],
            "acknowledgments__name": ["exact"],
            "acknowledgments__affiliation": ["exact"],
            "acknowledgments__from_upstream": ["exact"],
            "acknowledgments__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "acknowledgments__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            # FlawCVSS fields
            "cvss_scores__comment": ["exact"],
            "cvss_scores__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "cvss_scores__issuer": ["exact"],
            "cvss_scores__score": ["exact"],
            "cvss_scores__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "cvss_scores__uuid": ["exact"],
            "cvss_scores__vector": ["exact"],
            # Reference fields
            "references__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "references__description": ["exact"],
            "references__type": ["exact"],
            "references__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "references__url": ["exact"],
            "references__uuid": ["exact"],
        }

    order_fields = [
        "bz_id",
        "cve_id",
        "embargoed",
        "comment_zero",
        "statement",
        "cve_description",
        "title",
    ] + list(Meta.fields.keys())
    order = OrderingFilter(fields=order_fields)

    search_helper = staticmethod(search_helper)
    # Set the class method to be the same as the imported method (and make it static, to avoid breaking on a self param)
    # This ugly hack is needed to reuse code. django-filter requires the method to be defined as part of this class
    # models.py needs to use the method for FlawManager, but can't define here + import there
    # This would cause a circular import, so instead we define there + import here and set the property


class AffectFilter(DistinctFilterSet, IncludeFieldsFilterSet, ExcludeFieldsFilterSet):

    DISTINCT_FIELDS_PREFIXES = ("flaw__", "affects__")

    embargoed = BooleanFilter(field_name="embargoed")
    trackers__embargoed = BooleanFilter(field_name="trackers__embargoed")
    flaw__embargoed = BooleanFilter(field_name="flaw__embargoed")
    cvss_scores__cvss_version = CharFilter(field_name="cvss_scores__version")
    flaw__components = CharInFilter(
        field_name="flaw__components", lookup_expr="contains"
    )

    class Meta:
        model = Affect
        fields = {
            "uuid": ["exact"],
            "affectedness": ["exact"],
            "resolution": ["exact"],
            "ps_module": ["exact"],
            "ps_component": ["exact"],
            "impact": ["exact"],
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
            "flaw__components": ["exact"],
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
            # AffectCVSS fields
            "cvss_scores__comment": ["exact"],
            "cvss_scores__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "cvss_scores__issuer": ["exact"],
            "cvss_scores__score": ["exact"],
            "cvss_scores__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "cvss_scores__uuid": ["exact"],
            "cvss_scores__vector": ["exact"],
        }

    order_fields = [
        "cvss_scores__cvss_version",
        "embargoed",
        "flaw__embargoed",
        "trackers__embargoed",
    ] + list(Meta.fields.keys())
    order = OrderingFilter(fields=order_fields)


class TrackerFilter(DistinctFilterSet, IncludeFieldsFilterSet, ExcludeFieldsFilterSet):

    DISTINCT_FIELDS_PREFIXES = ("affects__",)

    embargoed = BooleanFilter(field_name="embargoed")
    affects__embargoed = BooleanFilter(field_name="affects__embargoed")
    affects__flaw__embargoed = BooleanFilter(field_name="flaw__embargoed")
    affects__flaw__components = CharInFilter(
        field_name="affects__flaw__components", lookup_expr="contains"
    )

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
            "affects__affectedness": ["exact"],
            "affects__resolution": ["exact"],
            "affects__ps_module": ["exact"],
            "affects__ps_component": ["exact"],
            "affects__impact": ["exact"],
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
            "affects__flaw__components": ["exact"],
        }

    order_fields = [
        "embargoed",
        "affects__embargoed",
        "affects__flaw__embargoed",
    ] + list(Meta.fields.keys())
    order = OrderingFilter(fields=order_fields)


class FlawAcknowledgmentFilter(IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    class Meta:
        model = FlawAcknowledgment
        fields = {
            "uuid": ["exact"],
            "name": ["exact"],
            "affiliation": ["exact"],
            "from_upstream": ["exact"],
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
        }


class FlawCommentFilter(IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    class Meta:
        model = FlawComment
        fields = {
            "uuid": ["exact"],
            "order": ["exact"],
            "external_system_id": ["exact"],
            "creator": ["exact"],
        }


class FlawCVSSFilter(IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    cvss_version = CharFilter(field_name="version")

    class Meta:
        model = FlawCVSS
        fields = {
            "comment": ["exact"],
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "issuer": ["exact"],
            "score": ["exact"],
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "uuid": ["exact"],
            "vector": ["exact"],
        }


class FlawReferenceFilter(IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    class Meta:
        model = FlawReference
        fields = {
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "description": ["exact"],
            "type": ["exact"],
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "url": ["exact"],
            "uuid": ["exact"],
        }


class AffectCVSSFilter(IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    cvss_version = CharFilter(field_name="version")

    class Meta:
        model = AffectCVSS
        fields = {
            "comment": ["exact"],
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "issuer": ["exact"],
            "score": ["exact"],
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "uuid": ["exact"],
            "vector": ["exact"],
        }


class FlawPackageVersionFilter(IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    class Meta:
        model = Package
        fields = {
            "uuid": ["exact"],
            "package": ["exact"],
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            # versions fields
            "versions__version": ["exact"],
        }


class AlertFilter(IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    parent_uuid = CharFilter(field_name="object_id")
    parent_model = CharFilter(field_name="content_type__model")

    class Meta:
        model = Alert
        fields = {
            "uuid": ["exact"],
            "name": ["exact"],
            "alert_type": ["exact"],
        }
