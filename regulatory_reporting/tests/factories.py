import factory
from django.utils import timezone

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import (
    FlawUpstreamMapping,
    SRPReport,
    SRPReportMilestone,
    UpstreamNotification,
    UpstreamProject,
)


class NonReportableFlawFactory(FlawFactory):
    """
    Flaw that does not trigger SRP auto-creation and is readable by public ACLs.

    Use in API/factory tests that create reports or notifications manually.
    """

    embargoed = False
    major_incident_state = Flaw.FlawMajorIncident.NOVALUE


class SRPReportFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = SRPReport

    flaw = factory.SubFactory(NonReportableFlawFactory)
    title = factory.Faker("sentence", nb_words=4)
    responsibility_scope = SRPReport.ResponsibilityScope.MANUFACTURER
    reportable_event_type = (
        SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
    )

    timer_started_at = factory.LazyFunction(timezone.now)
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)


class SRPReportMilestoneFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = SRPReportMilestone

    srp_report = factory.SubFactory(SRPReportFactory)
    milestone_type = SRPReportMilestone.MilestoneType.LEVEL_24H
    acl_read = factory.LazyAttribute(lambda o: o.srp_report.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.srp_report.acl_write)


class UpstreamProjectFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = UpstreamProject

    component_name = factory.Faker("word")
    repository_url = factory.Faker("url")


class UpstreamNotificationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = UpstreamNotification

    # Non-embargoed so ACL-filtered API tests can see created rows reliably.
    flaw = factory.SubFactory(NonReportableFlawFactory)
    upstream_project = factory.SubFactory(UpstreamProjectFactory)
    status = UpstreamNotification.NotificationStatus.REQUIRED
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)


class FlawUpstreamMappingFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = FlawUpstreamMapping

    flaw = factory.SubFactory(NonReportableFlawFactory)
    upstream_project = factory.SubFactory(UpstreamProjectFactory)
