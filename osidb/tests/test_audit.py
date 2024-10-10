import uuid

import pghistory
import pytest
from django.db import transaction
from django.utils import timezone

from osidb.core import set_user_acls
from osidb.dmodels import FlawSource, Impact
from osidb.dmodels.affect import Affect
from osidb.models import Flaw
from osidb.tests.factories import AffectFactory, FlawFactory

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
            comment_zero="description",
            impact=Impact.LOW,
            components=["curl"],
            source=FlawSource.INTERNET,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            reported_dt=timezone.now(),
        )
        flaw1.save()
        affect1 = AffectFactory(flaw=flaw1)
        affect1.save()

        # we have a flaw
        assert Flaw.objects.all()
        # we have an affect
        assert Affect.objects.all()

        # count all historical events across all models
        assert pghistory.models.Events.objects.count() == 3

        # count just flaw1 instance raw events
        assert flaw1.events.count() == 1

        # count just affect1 instance raw events
        assert affect1.events.count() == 2

        # update flaw1 instance
        flaw1.comment_zero = "A new description"
        flaw1.save()

        # count flaw1 instance events
        assert flaw1.events.count() == 2

        # retrieve all events associated with flaw1 instance (includes all flaw/affect events)
        assert pghistory.models.Events.objects.references(flaw1).count() == 4

        # search/ all events associated with flaw1 instance and filter on insert events.
        assert (
            pghistory.models.Events.objects.references(flaw1)
            .filter(pgh_label="insert")
            .count()
            == 2
        )

        # search/retrieve specific events(ex. matching comment_zero) and assert operation
        event1 = pghistory.models.Events.objects.filter(
            pgh_data__comment_zero="description"
        ).order_by("pgh_created_at")
        assert event1.count() == 1
        assert event1[0].pgh_label == "insert"

        # search/retrieve specific events(ex. matching comment_zero) and assert operation
        event2 = pghistory.models.Events.objects.filter(
            pgh_data__comment_zero="A new description"
        ).order_by("pgh_created_at")
        assert event2.count() == 1
        assert event2[0].pgh_label == "update"

        # count all insert events across all models
        assert pghistory.models.Events.objects.filter(pgh_label="insert").count() == 2

        # count all update events across all models
        assert pghistory.models.Events.objects.filter(pgh_label="update").count() == 2

        # add context metadata (ex. source="testcase") to event
        with pghistory.context(source="testcase"):
            affect2 = AffectFactory(flaw=flaw1)
            affect2.save()
            assert pghistory.models.Events.objects.count() == 6
            assert pghistory.models.Events.objects.references(flaw1).count() == 6

            # filter on flaw1 event context metadata (ex. source="testcase")
            assert (
                pghistory.models.Events.objects.references(flaw1)
                .filter(pgh_context__source="testcase")
                .count()
                == 2
            )

        # track returns just events on the specific entity
        assert pghistory.models.Events.objects.tracks(flaw1).count() == 2

    def test_access_flawevent(
        self,
        public_read_groups,
        public_write_groups,
        embargoed_read_groups,
        embargoed_write_groups,
    ):
        """ """

        flaw1 = FlawFactory(embargoed=True)
        assert flaw1.acl_read == embargoed_read_groups
        assert flaw1.acl_write == embargoed_write_groups

        affect1 = AffectFactory(flaw=flaw1)
        assert affect1.acl_read == embargoed_read_groups
        assert affect1.acl_write == embargoed_write_groups

        assert pghistory.models.Events.objects.tracks(flaw1).count() == 1
        assert pghistory.models.Events.objects.tracks(affect1).count() == 1

        set_user_acls(public_read_groups + public_write_groups)
        with transaction.atomic():
            # public user cannot 'see' flaw1 events
            assert pghistory.models.Events.objects.tracks(flaw1).count() == 0

        with transaction.atomic():
            # public user cannot 'see' affect1 events
            assert pghistory.models.Events.objects.tracks(affect1).count() == 0
