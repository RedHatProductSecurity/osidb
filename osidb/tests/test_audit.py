import uuid

import pghistory
import pytest
from django.utils import timezone

from osidb.models import Affect, Flaw, FlawMeta, FlawSource, Impact
from osidb.tests.factories import AffectFactory, FlawMetaFactory

pytestmark = pytest.mark.unit


@pytest.mark.django_db(transaction=True)
class TestAuditFlaw:
    @property
    def acl_read(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

    @property
    def acl_write(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]

    def test_flawevent(self):
        """ """
        # create a flaw with an affect
        Flaw.objects.all().delete()
        flaw1 = Flaw.objects.create_flaw(
            bz_id="12345",
            cwe_id="CWE-1",
            title="first",
            unembargo_dt=timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
            description="description",
            impact=Impact.LOW,
            component="curl",
            source=FlawSource.INTERNET,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            reported_dt=timezone.now(),
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        )
        flaw1.save()
        affect1 = AffectFactory(flaw=flaw1)
        affect1.save()

        flawmeta1 = FlawMetaFactory(
            flaw=flaw1,
            type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
            meta_attr={"status": "+"},
        )
        flawmeta1.save()

        # we have a flaw
        assert Flaw.objects.all()
        # we have an affect
        assert Affect.objects.all()
        # we have an flawmeta
        assert FlawMeta.objects.all()

        # count all historical events across all models
        assert pghistory.models.Events.objects.count() == 4

        # count just flaw1 instance raw events
        assert flaw1.events.count() == 1

        # count just affect1 instance raw events
        assert affect1.events.count() == 2

        # update flaw1 instance
        flaw1.description = "A new description"
        flaw1.save()

        # count flaw1 instance events
        assert flaw1.events.count() == 2

        # retrieve all events associated with flaw1 instance (includes all flaw/affect/flawmeta events)
        assert pghistory.models.Events.objects.references(flaw1).count() == 5

        # search/ all events associated with flaw1 instance and filter on insert events.
        assert (
            pghistory.models.Events.objects.references(flaw1)
            .filter(pgh_label="insert")
            .count()
            == 3
        )

        # search/retrieve specific events(ex. matching description) and assert operation
        event1 = pghistory.models.Events.objects.filter(
            pgh_data__description="description"
        ).order_by("pgh_created_at")
        assert event1.count() == 1
        assert event1[0].pgh_label == "insert"

        # search/retrieve specific events(ex. matching description) and assert operation
        event2 = pghistory.models.Events.objects.filter(
            pgh_data__description="A new description"
        ).order_by("pgh_created_at")
        assert event2.count() == 1
        assert event2[0].pgh_label == "update"

        # count all insert events across all models
        assert pghistory.models.Events.objects.filter(pgh_label="insert").count() == 3

        # count all update events across all models
        assert pghistory.models.Events.objects.filter(pgh_label="update").count() == 2

        # add context metadata (ex. source="testcase") to event
        with pghistory.context(source="testcase"):
            affect2 = AffectFactory(flaw=flaw1)
            affect2.save()
            assert pghistory.models.Events.objects.count() == 7
            assert pghistory.models.Events.objects.references(flaw1).count() == 7

            # filter on flaw1 event context metadata (ex. source="testcase")
            assert (
                pghistory.models.Events.objects.references(flaw1)
                .filter(pgh_context__source="testcase")
                .count()
                == 2
            )
