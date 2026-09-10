from rest_framework.exceptions import APIException

from apps.regulatory_reporting.settings import regulatory_reporting_settings


class RegulatoryReportingDisabled(APIException):
    status_code = 423
    default_detail = "Regulatory reporting disabled."
    default_code = "regulatory_reporting_disabled"


class RegulatoryReportingFeatureFlagMixin:
    regulatory_reporting_feature_flag = ""
    regulatory_reporting_disabled_detail = "Regulatory reporting disabled."

    def initial(self, request, *args, **kwargs):
        if not getattr(
            regulatory_reporting_settings, self.regulatory_reporting_feature_flag
        ):
            raise RegulatoryReportingDisabled(self.regulatory_reporting_disabled_detail)
        return super().initial(request, *args, **kwargs)


class RegulatoryReportingEnabledMixin(RegulatoryReportingFeatureFlagMixin):
    regulatory_reporting_feature_flag = "enabled"
    regulatory_reporting_disabled_detail = "Regulatory reporting is disabled."


class RegulatoryReportingNotificationsEnabledMixin(RegulatoryReportingFeatureFlagMixin):
    regulatory_reporting_feature_flag = "notifications_enabled"
    regulatory_reporting_disabled_detail = (
        "Regulatory reporting notifications are disabled."
    )
