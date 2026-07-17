from django_filters import CharFilter, ChoiceFilter, FilterSet, UUIDFilter

from .models.upstream import UpstreamNotification, UpstreamProject


class UpstreamNotificationFilter(FilterSet):
    """
    Filters queries to UpstreamNotificationView based on UpstreamNotification fields.
    """

    status = ChoiceFilter(
        field_name="status",
        choices=UpstreamNotification.NotificationStatus.choices,
    )
    method = ChoiceFilter(
        field_name="method",
        choices=UpstreamNotification.NotificationMethod.choices,
    )
    upstream_project = UUIDFilter(field_name="upstream_project__uuid")
    flaw = UUIDFilter(field_name="flaw__uuid")


class UpstreamProjectFilter(FilterSet):
    """
    Filters queries to UpstreamProjectView based on UpstreamProject fields.
    """

    component = CharFilter(field_name="component_name", lookup_expr="icontains")
    purl = CharFilter(field_name="component_name", lookup_expr="icontains")
    repository_url = CharFilter(field_name="repository_url", lookup_expr="icontains")

    class Meta:
        model = UpstreamProject
        fields = ["component", "repository_url", "purl"]
