from django_filters import ChoiceFilter, FilterSet, UUIDFilter

from .models.upstream import UpstreamNotification


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
