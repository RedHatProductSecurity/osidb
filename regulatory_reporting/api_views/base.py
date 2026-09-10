from django.conf import settings
from rest_framework.exceptions import APIException


class RegulatoryReportingDisabled(APIException):
    status_code = 423
    default_detail = "Regulatory reporting disabled."
    default_code = "regulatory_reporting_disabled"


class RegulatoryReportingFeatureFlagMixin:
    regulatory_reporting_feature_flag = ""
    regulatory_reporting_disabled_detail = "Regulatory reporting disabled."

    def initial(self, request, *args, **kwargs):
        if not getattr(settings, self.regulatory_reporting_feature_flag):
            raise RegulatoryReportingDisabled(
                self.regulatory_reporting_disabled_detail
            )
        return super().initial(request, *args, **kwargs)


class RegulatoryReportingEnabledMixin(RegulatoryReportingFeatureFlagMixin):
    regulatory_reporting_feature_flag = "REGULATORY_REPORTING_ENABLED"
    regulatory_reporting_disabled_detail = "Regulatory reporting is disabled."


class RegulatoryReportingNotificationsEnabledMixin(
    RegulatoryReportingFeatureFlagMixin
):
    regulatory_reporting_feature_flag = "REGULATORY_REPORTING_NOTIFICATIONS_ENABLED"
    regulatory_reporting_disabled_detail = (
        "Regulatory reporting notifications are disabled."
    )
