import factory
from django.utils import timezone

from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport, SRPReportMilestone


class SRPReportFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = SRPReport

    flaw = factory.SubFactory(FlawFactory)
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
