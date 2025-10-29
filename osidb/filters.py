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
    DateFilter,
    DateTimeFilter,
    FilterSet,
    NumberFilter,
    OrderingFilter,
    UUIDFilter,
)
from djangoql.queryset import apply_search

from apps.workflows.workflow import WorkflowModel
from osidb.models import (
    Affect,
    AffectCVSS,
    AffectV1,
    Erratum,
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


class IsEmptyArrayFilter(BooleanFilter):
    """Filter for empty or null array fields."""

    def filter(self, queryset, value):
        """
        Given a value of True or False, it will return the records that have an
        empty or null array (True) or the ones that don't (False).
        """
        if value in EMPTY_VALUES:
            return queryset

        if value:  # looking for empty
            return queryset.filter(
                Q(**{f"{self.field_name}__isnull": True})
                | Q(**{f"{self.field_name}__len": 0})
            )
        else:  # looking for not empty
            return queryset.filter(**{f"{self.field_name}__isnull": False}).exclude(
                **{f"{self.field_name}__len": 0}
            )


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


class NullForeignKeyFilter(BooleanFilter):
    """Filter for null foreign key fields"""

    def filter(self, queryset, value):
        if value in EMPTY_VALUES:
            return queryset

        exclude = self.exclude ^ (value is False)
        method = queryset.exclude if exclude else queryset.filter
        query = Q(**{f"{self.field_name}__isnull": True})

        return method(query)


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
        .filter(Q(rank__gt=0) | Q(similarity__gt=0.7))
        .order_by("-rank")
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
        field_name="affects__tracker__external_system_id",
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
    affects__tracker__embargoed = BooleanFilter(
        field_name="affects__tracker__embargoed"
    )
    cvss_scores__cvss_version = CharFilter(field_name="cvss_scores__version")
    flaw_has_no_non_community_affects_trackers = BooleanFilter(
        method="flaw_has_no_non_community_affects_trackers_filter"
    )
    flaw_labels = CharInFilter(method="labels_filter")

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

    def flaw_has_no_non_community_affects_trackers_filter(self, queryset, name, value):
        """Check if a flaw has non-community affects AND all of them are missing trackers."""

        from django.db.models import Exists, OuterRef

        from osidb.models import Affect
        from osidb.models.ps_module import PsModule

        community_modules = PsModule.objects.filter(
            ps_product__business_unit="Community"
        ).values_list("name", flat=True)

        has_non_community_affects_with_trackers = Exists(
            Affect.objects.filter(flaw=OuterRef("pk"), tracker__isnull=False).exclude(
                ps_module__in=community_modules
            )
        )

        # This filter is in place since the flaw filter doesn't
        # seem to work if there are no non-community affects.
        has_non_community_affects = Exists(
            Affect.objects.filter(flaw=OuterRef("pk")).exclude(
                ps_module__in=community_modules
            )
        )

        if value:
            return queryset.filter(
                has_non_community_affects & ~has_non_community_affects_with_trackers
            )
        else:
            return queryset.filter(
                ~has_non_community_affects | has_non_community_affects_with_trackers
            )

    def labels_filter(self, queryset, name, value):
        """
        Returns flaws that have all of the specified labels.
        """

        for label in value:
            queryset = queryset.filter(labels__label=label)

        return queryset

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
            "affects__tracker__uuid": ["exact"],
            "affects__tracker__type": ["exact"],
            "affects__tracker__external_system_id": ["exact"],
            "affects__tracker__status": ["exact"],
            "affects__tracker__resolution": ["exact"],
            "affects__tracker__ps_update_stream": ["exact"],
            "affects__tracker__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__tracker__updated_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "affects__tracker__errata__advisory_name": ["exact"],
            "affects__tracker__errata__et_id": ["exact"],
            "affects__tracker__errata__shipped_dt": ["exact"]
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


class FlawV1Filter(FlawFilter):
    """
    Filter for flaws adapted to affects v1
    """

    # Override filters that depended on the v1 affect
    tracker_ids = CharInFilter(method="tracker_ids_filter", distinct=True)
    affects__embargoed = BooleanFilter(method="affects_embargoed_filter")
    affects__trackers__embargoed = BooleanFilter(
        method="affects_trackers_embargoed_filter"
    )

    # Custom filters to match the current ones
    affects__uuid = CharFilter(method="affect_direct_filter")
    affects__affectedness = CharFilter(method="affect_direct_filter")
    affects__resolution = CharFilter(method="affect_direct_filter")
    affects__ps_module = CharFilter(method="affect_direct_filter")
    affects__ps_component = CharFilter(method="affect_direct_filter")
    affects__impact = CharFilter(method="affect_direct_filter")
    affects__created_dt = DateTimeFilter(method="affect_datetime_filter")
    affects__updated_dt = DateTimeFilter(method="affect_datetime_filter")

    affects__trackers__uuid = CharFilter(method="affect_trackers_filter")
    affects__trackers__type = CharFilter(method="affect_trackers_filter")
    affects__trackers__external_system_id = CharFilter(method="affect_trackers_filter")
    affects__trackers__status = CharFilter(method="affect_trackers_filter")
    affects__trackers__resolution = CharFilter(method="affect_trackers_filter")
    affects__trackers__ps_update_stream = CharFilter(method="affect_trackers_filter")
    affects__trackers__created_dt = DateTimeFilter(
        method="affect_trackers_datetime_filter"
    )
    affects__trackers__updated_dt = DateTimeFilter(
        method="affect_trackers_datetime_filter"
    )

    affects__trackers__errata__advisory_name = CharFilter(
        method="affect_trackers_errata_filter"
    )
    affects__trackers__errata__et_id = CharFilter(
        method="affect_trackers_errata_filter"
    )
    affects__trackers__errata__shipped_dt = DateTimeFilter(
        method="affect_trackers_errata_datetime_filter"
    )

    def _get_flaw_ids_by_affect(self, affect_filter):
        return (
            AffectV1.objects.filter(**affect_filter)
            .values_list("flaw_id", flat=True)
            .distinct()
        )

    def _get_flaw_ids_by_tracker(self, tracker_filter):
        tracker_uuids = Tracker.objects.filter(**tracker_filter).values_list(
            "uuid", flat=True
        )
        return (
            AffectV1.objects.filter(all_tracker_ids__overlap=list(tracker_uuids))
            .values_list("flaw_id", flat=True)
            .distinct()
        )

    def _get_flaw_ids_by_errata(self, errata_filter):
        tracker_uuids = (
            Erratum.objects.filter(**errata_filter)
            .values_list("trackers__uuid", flat=True)
            .distinct()
        )
        return (
            AffectV1.objects.filter(all_tracker_ids__overlap=list(tracker_uuids))
            .values_list("flaw_id", flat=True)
            .distinct()
        )

    def affect_direct_filter(self, queryset, name, value):
        key = name.replace("affects__", "") + "__exact"
        flaw_ids = self._get_flaw_ids_by_affect({key: value})
        return queryset.filter(uuid__in=flaw_ids)

    def affect_datetime_filter(self, queryset, name, value):
        key = name.replace("affects__", "")
        flaw_ids = self._get_flaw_ids_by_affect({key: value})
        return queryset.filter(uuid__in=flaw_ids)

    def affect_trackers_filter(self, queryset, name, value):
        key = name.replace("affects__trackers__", "") + "__exact"
        flaw_ids = self._get_flaw_ids_by_tracker({key: value})
        return queryset.filter(uuid__in=flaw_ids)

    def affect_trackers_datetime_filter(self, queryset, name, value):
        key = name.replace("affects__trackers__", "")
        flaw_ids = self._get_flaw_ids_by_tracker({key: value})
        return queryset.filter(uuid__in=flaw_ids)

    def affect_trackers_errata_filter(self, queryset, name, value):
        key = name.replace("affects__trackers__errata__", "") + "__exact"
        flaw_ids = self._get_flaw_ids_by_errata({key: value})
        return queryset.filter(uuid__in=flaw_ids)

    def affect_trackers_errata_datetime_filter(self, queryset, name, value):
        key = name.replace("affects__trackers__errata__", "")
        flaw_ids = self._get_flaw_ids_by_errata({key: value})
        return queryset.filter(uuid__in=flaw_ids)

    def tracker_ids_filter(self, queryset, name, value):
        tracker_uuids = Tracker.objects.filter(
            external_system_id__in=value
        ).values_list("uuid", flat=True)

        flaw_ids = (
            AffectV1.objects.filter(all_tracker_ids__overlap=list(tracker_uuids))
            .values_list("flaw_id", flat=True)
            .distinct()
        )

        return queryset.filter(uuid__in=flaw_ids)

    def affects_embargoed_filter(self, queryset, name, value):
        flaw_ids = (
            AffectV1.objects.filter(embargoed=value)
            .values_list("flaw_id", flat=True)
            .distinct()
        )
        return queryset.filter(uuid__in=flaw_ids)

    def affects_trackers_embargoed_filter(self, queryset, name, value):
        tracker_uuids = Tracker.objects.filter(embargoed=value).values_list(
            "uuid", flat=True
        )

        flaw_ids = (
            AffectV1.objects.filter(all_tracker_ids__overlap=list(tracker_uuids))
            .values_list("flaw_id", flat=True)
            .distinct()
        )

        return queryset.filter(uuid__in=flaw_ids)


class AffectV1Filter(DistinctFilterSet, IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    """
    Filter for flaws adapted to affects v1
    """

    DISTINCT_FIELDS_PREFIXES = ("flaw__", "affects__")

    cve_id = CharFilter(field_name="flaw__cve_id")
    embargoed = BooleanFilter(field_name="embargoed")
    flaw__embargoed = BooleanFilter(field_name="flaw__embargoed")
    flaw__components = CharInFilter(
        field_name="flaw__components", lookup_expr="contains"
    )
    flaw__workflow_state = ChoiceInFilter(
        field_name="flaw__workflow_state", choices=WorkflowModel.WorkflowState.choices
    )

    # Custom method filters for trackers
    trackers__uuid = UUIDFilter(method="tracker_uuid_filter")
    trackers__type = ChoiceFilter(
        method="tracker_type_filter", choices=Tracker.TrackerType.choices
    )
    trackers__external_system_id = CharFilter(method="tracker_external_id_filter")
    trackers__status = CharFilter(method="tracker_status_filter")
    trackers__resolution = CharFilter(method="tracker_resolution_filter")
    trackers__ps_update_stream = CharFilter(method="tracker_ps_update_stream_filter")

    trackers__created_dt = DateTimeFilter(method="tracker_datetime_filter")
    trackers__created_dt__gt = DateTimeFilter(
        field_name="created_dt", lookup_expr="gt", method="tracker_datetime_filter"
    )
    trackers__created_dt__gte = DateTimeFilter(
        field_name="created_dt", lookup_expr="gte", method="tracker_datetime_filter"
    )
    trackers__created_dt__lt = DateTimeFilter(
        field_name="created_dt", lookup_expr="lt", method="tracker_datetime_filter"
    )
    trackers__created_dt__lte = DateTimeFilter(
        field_name="created_dt", lookup_expr="lte", method="tracker_datetime_filter"
    )
    trackers__created_dt__date = DateFilter(
        field_name="created_dt", lookup_expr="date", method="tracker_datetime_filter"
    )
    trackers__created_dt__date__gte = DateFilter(
        field_name="created_dt",
        lookup_expr="date__gte",
        method="tracker_datetime_filter",
    )
    trackers__created_dt__date__lte = DateFilter(
        field_name="created_dt",
        lookup_expr="date__lte",
        method="tracker_datetime_filter",
    )

    trackers__updated_dt = DateTimeFilter(method="tracker_datetime_filter")
    trackers__updated_dt__gt = DateTimeFilter(
        field_name="updated_dt", lookup_expr="gt", method="tracker_datetime_filter"
    )
    trackers__updated_dt__gte = DateTimeFilter(
        field_name="updated_dt", lookup_expr="gte", method="tracker_datetime_filter"
    )
    trackers__updated_dt__lt = DateTimeFilter(
        field_name="updated_dt", lookup_expr="lt", method="tracker_datetime_filter"
    )
    trackers__updated_dt__lte = DateTimeFilter(
        field_name="updated_dt", lookup_expr="lte", method="tracker_datetime_filter"
    )
    trackers__updated_dt__date = DateFilter(
        field_name="updated_dt", lookup_expr="date", method="tracker_datetime_filter"
    )
    trackers__updated_dt__date__gte = DateFilter(
        field_name="updated_dt",
        lookup_expr="date__gte",
        method="tracker_datetime_filter",
    )
    trackers__updated_dt__date__lte = DateFilter(
        field_name="updated_dt",
        lookup_expr="date__lte",
        method="tracker_datetime_filter",
    )

    trackers__embargoed = BooleanFilter(method="tracker_embargoed_filter")
    trackers__isempty = IsEmptyArrayFilter(field_name="all_tracker_ids")

    # Custom method filters for CVSS scores
    cvss_scores__comment = CharFilter(method="cvss_comment_filter")

    cvss_scores__created_dt = DateTimeFilter(method="cvss_datetime_filter")
    cvss_scores__created_dt__gt = DateTimeFilter(
        field_name="created_dt", lookup_expr="gt", method="cvss_datetime_filter"
    )
    cvss_scores__created_dt__gte = DateTimeFilter(
        field_name="created_dt", lookup_expr="gte", method="cvss_datetime_filter"
    )
    cvss_scores__created_dt__lt = DateTimeFilter(
        field_name="created_dt", lookup_expr="lt", method="cvss_datetime_filter"
    )
    cvss_scores__created_dt__lte = DateTimeFilter(
        field_name="created_dt", lookup_expr="lte", method="cvss_datetime_filter"
    )
    cvss_scores__created_dt__date = DateFilter(
        field_name="created_dt", lookup_expr="date", method="cvss_datetime_filter"
    )
    cvss_scores__created_dt__date__gte = DateFilter(
        field_name="created_dt", lookup_expr="date__gte", method="cvss_datetime_filter"
    )
    cvss_scores__created_dt__date__lte = DateFilter(
        field_name="created_dt", lookup_expr="date__lte", method="cvss_datetime_filter"
    )

    cvss_scores__issuer = ChoiceFilter(
        method="cvss_issuer_filter", choices=AffectCVSS.CVSSIssuer.choices
    )
    cvss_scores__score = NumberFilter(method="cvss_score_filter")

    cvss_scores__updated_dt = DateTimeFilter(method="cvss_datetime_filter")
    cvss_scores__updated_dt__gt = DateTimeFilter(
        field_name="updated_dt", lookup_expr="gt", method="cvss_datetime_filter"
    )
    cvss_scores__updated_dt__gte = DateTimeFilter(
        field_name="updated_dt", lookup_expr="gte", method="cvss_datetime_filter"
    )
    cvss_scores__updated_dt__lt = DateTimeFilter(
        field_name="updated_dt", lookup_expr="lt", method="cvss_datetime_filter"
    )
    cvss_scores__updated_dt__lte = DateTimeFilter(
        field_name="updated_dt", lookup_expr="lte", method="cvss_datetime_filter"
    )
    cvss_scores__updated_dt__date = DateFilter(
        field_name="updated_dt", lookup_expr="date", method="cvss_datetime_filter"
    )
    cvss_scores__updated_dt__date__gte = DateFilter(
        field_name="updated_dt", lookup_expr="date__gte", method="cvss_datetime_filter"
    )
    cvss_scores__updated_dt__date__lte = DateFilter(
        field_name="updated_dt", lookup_expr="date__lte", method="cvss_datetime_filter"
    )

    cvss_scores__uuid = UUIDFilter(method="cvss_uuid_filter")
    cvss_scores__vector = CharFilter(method="cvss_vector_filter")
    cvss_scores__cvss_version = CharFilter(method="cvss_version_filter")

    def _filter_by_tracker_attribute(self, queryset, filter_key, value):
        """Helper method to find affects v1 from its trackers' fields"""
        tracker_uuids = Tracker.objects.filter(**{filter_key: value}).values_list(
            "uuid", flat=True
        )

        if not tracker_uuids.exists():
            return queryset.none()

        return queryset.filter(all_tracker_ids__overlap=list(tracker_uuids))

    def _filter_by_cvss_attribute(self, queryset, filter_key, value):
        """Helper method to find affects v1 from CVSS score fields"""
        affect_ids = (
            AffectCVSS.objects.filter(**{filter_key: value})
            .values_list("affect_id", flat=True)
            .distinct()
        )
        if not affect_ids:
            return queryset.none()
        return queryset.filter(uuid__in=affect_ids)

    def tracker_uuid_filter(self, queryset, name, value):
        return queryset.filter(all_tracker_ids__contains=[value])

    def tracker_type_filter(self, queryset, name, value):
        return self._filter_by_tracker_attribute(queryset, "type__exact", value)

    def tracker_external_id_filter(self, queryset, name, value):
        return self._filter_by_tracker_attribute(
            queryset, "external_system_id__exact", value
        )

    def tracker_status_filter(self, queryset, name, value):
        return self._filter_by_tracker_attribute(queryset, "status__exact", value)

    def tracker_resolution_filter(self, queryset, name, value):
        return self._filter_by_tracker_attribute(queryset, "resolution__exact", value)

    def tracker_ps_update_stream_filter(self, queryset, name, value):
        return self._filter_by_tracker_attribute(
            queryset, "ps_update_stream__exact", value
        )

    def tracker_datetime_filter(self, queryset, name, value):
        # Hack that parses the lookup query from the field name, e.g.,
        # trackers__created_dt__gt -> created_dt__gt
        filter_key = name.replace("trackers__", "", 1)
        return self._filter_by_tracker_attribute(queryset, filter_key, value)

    def tracker_embargoed_filter(self, queryset, name, value):
        return self._filter_by_tracker_attribute(queryset, "embargoed", value)

    def cvss_comment_filter(self, queryset, name, value):
        return self._filter_by_cvss_attribute(queryset, "comment__exact", value)

    def cvss_issuer_filter(self, queryset, name, value):
        return self._filter_by_cvss_attribute(queryset, "issuer__exact", value)

    def cvss_score_filter(self, queryset, name, value):
        return self._filter_by_cvss_attribute(queryset, "score__exact", value)

    def cvss_uuid_filter(self, queryset, name, value):
        return self._filter_by_cvss_attribute(queryset, "uuid__exact", value)

    def cvss_vector_filter(self, queryset, name, value):
        return self._filter_by_cvss_attribute(queryset, "vector__exact", value)

    def cvss_version_filter(self, queryset, name, value):
        return self._filter_by_cvss_attribute(queryset, "version__exact", value)

    def cvss_datetime_filter(self, queryset, name, value):
        # Hack that parses the lookup query from the field name, e.g.,
        # cvss_scores__created_dt__gt -> created_dt__gt
        filter_key = name.replace("cvss_scores__", "", 1)
        return self._filter_by_cvss_attribute(queryset, filter_key, value)

    class Meta:
        model = AffectV1
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
        }

    order_fields = [
        # Direct AffectV1 fields
        "uuid",
        "affectedness",
        "resolution",
        "ps_module",
        "impact",
        "created_dt",
        "updated_dt",
        "embargoed",
        # Related Flaw fields
        "cve_id",
        "flaw__impact",
        "flaw__embargoed",
        # Custom Tracker fields
        "trackers__uuid",
        "trackers__type",
        "trackers__external_system_id",
        "trackers__ps_update_stream",
        "trackers__status",
        "trackers__resolution",
        "trackers__created_dt",
        "trackers__updated_dt",
        "trackers__embargoed",
        # Custom CVSS Score fields
        "cvss_scores__cvss_version",
        "cvss_scores__uuid",
        "cvss_scores__vector",
        "cvss_scores__score",
        "cvss_scores__issuer",
        "cvss_scores__created_dt",
        "cvss_scores__updated_dt",
    ] + list(Meta.fields.keys())

    order = OrderingFilter(fields=order_fields)


class AffectFilter(DistinctFilterSet, IncludeFieldsFilterSet, ExcludeFieldsFilterSet):
    DISTINCT_FIELDS_PREFIXES = ("flaw__", "affects__")

    cvss_scores__cvss_version = CharFilter(field_name="cvss_scores__version")
    embargoed = BooleanFilter(field_name="embargoed")
    tracker__embargoed = BooleanFilter(field_name="tracker__embargoed")
    flaw__embargoed = BooleanFilter(field_name="flaw__embargoed")
    flaw__workflow_state = ChoiceInFilter(
        field_name="flaw__workflow_state", choices=WorkflowModel.WorkflowState.choices
    )
    flaw__components = CharInFilter(
        field_name="flaw__components", lookup_expr="contains"
    )
    tracker__embargoed = BooleanFilter(field_name="tracker__embargoed")
    tracker__isnull = NullForeignKeyFilter(field_name="tracker")

    class Meta:
        model = Affect
        fields = {
            "uuid": ["exact"],
            "affectedness": ["exact"],
            "resolution": ["exact"],
            "ps_update_stream": ["exact"],
            "ps_module": ["exact"],
            "ps_component": ["exact"],
            "impact": ["exact"],
            "created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "cve_id": ["exact"],
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
            "tracker__uuid": ["exact"],
            "tracker__type": ["exact"],
            "tracker__external_system_id": ["exact"],
            "tracker__status": ["exact"],
            "tracker__resolution": ["exact"],
            "tracker__ps_update_stream": ["exact"],
            "tracker__created_dt": ["exact"]
            + LT_GT_LOOKUP_EXPRS
            + LTE_GTE_LOOKUP_EXPRS
            + DATE_LOOKUP_EXPRS,
            "tracker__updated_dt": ["exact"]
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
        "tracker__embargoed",
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
            "cve_id": ["exact"],
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


class TrackerV1Filter(TrackerFilter):
    """
    Filter for trackers adapted to affects v1
    """

    # Override filters that depended on the v1 affect
    affects__embargoed = BooleanFilter(method="tracker_affects_embargoed_filter")
    affects__flaw__embargoed = BooleanFilter(method="tracker_flaw_embargoed_filter")
    affects__flaw__components = CharInFilter(method="tracker_flaw_components_filter")

    # Custom filters to match the current ones
    affects__uuid = CharFilter(method="affect_direct_filter")
    affects__affectedness = CharFilter(method="affect_direct_filter")
    affects__resolution = CharFilter(method="affect_direct_filter")
    affects__ps_module = CharFilter(method="affect_direct_filter")
    affects__ps_component = CharFilter(method="affect_direct_filter")
    affects__impact = CharFilter(method="affect_direct_filter")
    affects__created_dt = DateTimeFilter(method="affect_datetime_filter")
    affects__updated_dt = DateTimeFilter(method="affect_datetime_filter")

    affects__flaw__uuid = CharFilter(method="affect_flaw_filter")
    affects__flaw__cve_id = CharFilter(method="affect_flaw_filter")
    affects__flaw__impact = CharFilter(method="affect_flaw_filter")
    affects__flaw__cwe_id = CharFilter(method="affect_flaw_filter")
    affects__flaw__source = CharFilter(method="affect_flaw_filter")
    affects__flaw__created_dt = DateTimeFilter(method="affect_flaw_datetime_filter")
    affects__flaw__updated_dt = DateTimeFilter(method="affect_flaw_datetime_filter")
    affects__flaw__reported_dt = DateTimeFilter(method="affect_flaw_datetime_filter")
    affects__flaw__unembargo_dt = DateTimeFilter(method="affect_flaw_datetime_filter")

    def _get_tracker_uuids_from_affect_v1_filter(self, affect_v1_filter):
        """
        Helper to get all tracker ids from affect v1 objects that match a given filter.
        """
        tracker_uuids = AffectV1.objects.filter(**affect_v1_filter).values_list(
            "all_tracker_ids", flat=True
        )
        return {uuid for sublist in tracker_uuids if sublist for uuid in sublist}

    def affect_direct_filter(self, queryset, name, value):
        key = name.replace("affects__", "") + "__exact"
        tracker_uuids = self._get_tracker_uuids_from_affect_v1_filter({key: value})
        return queryset.filter(uuid__in=tracker_uuids)

    def affect_datetime_filter(self, queryset, name, value):
        key = name.replace("affects__", "")
        tracker_uuids = self._get_tracker_uuids_from_affect_v1_filter({key: value})
        return queryset.filter(uuid__in=tracker_uuids)

    def affect_flaw_filter(self, queryset, name, value):
        key = name.replace("affects__", "") + "__exact"
        tracker_uuids = self._get_tracker_uuids_from_affect_v1_filter({key: value})
        return queryset.filter(uuid__in=tracker_uuids)

    def affect_flaw_datetime_filter(self, queryset, name, value):
        key = name.replace("affects__", "")
        tracker_uuids = self._get_tracker_uuids_from_affect_v1_filter({key: value})
        return queryset.filter(uuid__in=tracker_uuids)

    def tracker_affects_embargoed_filter(self, queryset, name, value):
        tracker_uuids = self._get_tracker_uuids_from_affect_v1_filter(
            {"embargoed": value}
        )
        return queryset.filter(uuid__in=tracker_uuids)

    def tracker_flaw_embargoed_filter(self, queryset, name, value):
        tracker_uuids = self._get_tracker_uuids_from_affect_v1_filter(
            {"flaw__embargoed": value}
        )
        return queryset.filter(uuid__in=tracker_uuids)

    def tracker_flaw_components_filter(self, queryset, name, value):
        tracker_uuids = self._get_tracker_uuids_from_affect_v1_filter(
            {"flaw__components__contains": value}
        )
        return queryset.filter(uuid__in=tracker_uuids)


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
