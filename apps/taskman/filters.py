from django_filters.rest_framework import CharFilter, FilterSet


class FlawTaskFilterSet(FilterSet):
    owner = CharFilter(field_name="owner", method="filter_owner")

    def filter_owner(self, queryset, name, value):
        return queryset.filter(owner__profile__user__username=value)
