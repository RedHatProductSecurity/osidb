import uuid
from random import choice

import factory
from django.conf import settings
from pytz import UTC

from osidb.models import (
    Affect,
    CVEv5PackageVersions,
    CVEv5Version,
    Flaw,
    FlawComment,
    FlawImpact,
    FlawMeta,
    FlawResolution,
    FlawType,
    PsContact,
    PsModule,
    PsProduct,
    PsUpdateStream,
    Tracker,
    VersionStatus,
)

DATA_PRODSEC_ACL = uuid.uuid5(
    uuid.NAMESPACE_URL,
    "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
)


class FlawFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Flaw

    cve_id = factory.sequence(lambda n: f"CVE-2020-000{n}")
    type = factory.Faker("random_element", elements=list(FlawType))
    created_dt = factory.Faker("date_time", tzinfo=UTC)
    reported_dt = factory.Faker("date_time", tzinfo=UTC)
    state = factory.Faker("random_element", elements=list(Flaw.FlawState))
    resolution = factory.Faker("random_element", elements=list(FlawResolution))
    impact = factory.Faker("random_element", elements=list(FlawImpact))
    description = factory.LazyAttribute(lambda c: f"Description for {c.cve_id}")
    title = factory.Maybe(
        "embargoed",
        yes_declaration=factory.LazyAttribute(
            lambda c: f"EMBARGOED {c.cve_id} kernel: some description"
        ),
        no_declaration=factory.LazyAttribute(
            lambda c: f"{c.cve_id} kernel: some description"
        ),
    )
    statement = factory.LazyAttribute(lambda c: f"Statement for {c.cve_id}")
    embargoed = factory.Faker("random_element", elements=[False, True])
    summary = factory.Maybe(
        "is_major_incident",
        yes_declaration="I'm a spooky CVE",
        no_declaration=factory.Faker("random_element", elements=["", "foo"]),
    )
    unembargo_dt = factory.Maybe(
        "embargoed",
        yes_declaration=factory.Faker("future_datetime", tzinfo=UTC),
        no_declaration=factory.Faker("past_datetime", tzinfo=UTC),
    )
    cvss3 = "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
    # cannot be set to ("random_element", elements=list(FlawSource)) because it could
    # inadvertently trigger validation errors in unrelated tests.
    source = ""
    acl_read = factory.LazyAttribute(
        lambda o: [
            uuid.uuid5(
                uuid.NAMESPACE_URL, f"https://osidb.prod.redhat.com/ns/acls#{group}"
            )
            for group in settings.PUBLIC_READ_GROUPS
        ]
        if o.embargoed is False
        else [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"https://osidb.prod.redhat.com/ns/acls#{settings.EMBARGO_READ_GROUP}",
            )
        ]
    )
    acl_write = factory.LazyAttribute(
        lambda o: [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"https://osidb.prod.redhat.com/ns/acls#{settings.PUBLIC_WRITE_GROUP}",
            )
        ]
        if o.embargoed is False
        else [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"https://osidb.prod.redhat.com/ns/acls#{settings.EMBARGO_WRITE_GROUP}",
            )
        ]
    )
    meta_attr = factory.Dict({"test": "1"})

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """
        instance creation
        with saving to DB
        """
        # embargoed is not a real model attribute but annotation so it is read-only
        # but we want preserve it as writable factory attribute as it is easier to work with
        # than with ACLs so we need to remove it for the flaw creation and emulate annotation
        embargoed = kwargs.pop("embargoed")
        flaw = super()._create(model_class, *args, **kwargs)
        flaw.embargoed = embargoed
        return flaw

    @classmethod
    def _build(cls, model_class, *args, **kwargs):
        """
        instance build
        without saving to DB
        """
        # embargoed is not a real model attribute but annotation so it is read-only
        # but we want preserve it as writable factory attribute as it is easier to work with
        # than with ACLs so we need to remove it for the flaw creation and emulate annotation
        embargoed = kwargs.pop("embargoed")
        flaw = super()._build(model_class, *args, **kwargs)
        flaw.embargoed = embargoed
        return flaw

    # @factory.post_generation
    # def affects(self, create, extracted, **kwargs):
    #     # https://factoryboy.readthedocs.io/en/latest/recipes.html#simple-many-to-many-relationship
    #     if not create:
    #         # Simple build, do nothing.
    #         return
    #
    #     if extracted:
    #         if isinstance(extracted, int):
    #             # A number of affects to create was passed in
    #             cve_id = kwargs.pop("cve_id", self.cve_id)
    #             for affect in AffectFactory.create_batch(
    #                 size=extracted, cve_id=cve_id, **kwargs
    #             ):
    #                 self.affects.add(affect)
    #         else:
    #             # A list of affects were passed in, use them
    #             for affect in extracted:
    #                 self.affects.add(affect)
    #     else:
    #         # Nothing was passed, create random number of affects
    #         for affect in AffectFactory.create_batch(
    #             size=randint(0, 5), cve_id=self.cve_id
    #         ):
    #             self.affects.add(affect)


class AffectFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Affect
        django_get_or_create = ("flaw", "ps_module", "ps_component")

    type = factory.Faker("random_element", elements=list(Affect.AffectType))
    affectedness = factory.Faker(
        "random_element", elements=list(Affect.AffectAffectedness)
    )
    resolution = factory.Faker("random_element", elements=list(Affect.AffectResolution))
    ps_module = factory.sequence(lambda n: f"ps-module-{n}")
    ps_component = factory.sequence(lambda n: f"ps-component-{n}")
    impact = factory.Faker("random_element", elements=list(Affect.AffectImpact))

    flaw = factory.SubFactory(FlawFactory)

    acl_read = [DATA_PRODSEC_ACL]
    acl_write = acl_read
    meta_attr = factory.Dict({"test": "1"})

    # @factory.post_generation
    # def trackers(self, create, extracted, **kwargs):
    #     # https://factoryboy.readthedocs.io/en/latest/recipes.html#simple-many-to-many-relationship
    #     if not create:
    #         # Simple build, do nothing.
    #         return
    #
    #     if extracted:
    #         # A list of trackers were passed in, use them
    #         for tracker in extracted:
    #             self.trackers.add(tracker)
    #     else:
    #         # Nothing was passed, create random trackers
    #         for tracker in TrackerFactory.create_batch(
    #             size=randint(0, 1), cve_id=self.cve_id
    #         ):
    #             self.trackers.add(tracker)


class TrackerFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Tracker
        django_get_or_create = ("type", "external_system_id")

    type = factory.Faker("random_element", elements=list(Tracker.TrackerType))
    external_system_id = factory.LazyAttributeSequence(
        lambda o, n: f"{o.type}-{n}" if o.type else f"{n}"
    )
    status = factory.Faker("word")
    resolution = factory.Faker("word")

    acl_read = factory.List([DATA_PRODSEC_ACL])
    acl_write = acl_read
    meta_attr = {"test": "1"}

    @factory.post_generation
    def affects(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for affect in extracted:
                self.affects.add(affect)


class FlawCommentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = FlawComment

    type = "BUGZILLA"
    created_dt = factory.Faker("date_time", tzinfo=UTC)
    external_system_id = factory.sequence(lambda n: f"fake-external-id{n}")
    acl_read = factory.List([DATA_PRODSEC_ACL])

    flaw = factory.SubFactory(FlawFactory)

    acl_write = acl_read
    meta_attr = {
        "id": "1285930",
        "tags": "[]",
        "text": "some comment text",
        "time": "2006-03-30T11:56:45Z",
        "count": "0",
        "bug_id": "187353",
        "creator": "nonexistantuser@redhat.com",
        "creator_id": "9999",
        "is_private": "False",
        "creation_time": "2006-03-30T11:56:45Z",
    }


class FlawMetaFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = FlawMeta

    type = "REFERENCE"
    created_dt = factory.Faker("date_time", tzinfo=UTC)
    acl_read = factory.List([DATA_PRODSEC_ACL])
    acl_write = acl_read
    meta_attr = {
        "url": "http://nonexistenturl.example.com/1285930",
        "type": "external",
    }

    flaw = factory.SubFactory(FlawFactory)


class CVEv5VersionFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CVEv5Version

    version = "3.2.1"
    status = VersionStatus.UNAFFECTED


class CVEv5PackageVersionsFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CVEv5PackageVersions

    package = "package"

    flaw = factory.SubFactory(FlawFactory)

    @factory.post_generation
    def versions(self, create, extracted, **kwargs):
        if not create:
            # Simple build, do nothing.
            return

        if extracted:
            # A list of groups were passed in, use them
            for version in extracted:
                self.versions.add(version)


class PsContactFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PsContact

    username = factory.sequence(lambda n: f"username_{n}")
    bz_username = factory.Faker("word")
    jboss_username = factory.Faker("word")


class PsProductFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PsProduct

    short_name = factory.sequence(lambda n: f"ps_product_{n}")
    name = factory.LazyAttribute(lambda c: f"{c.short_name} long name")
    team = factory.Faker("word")
    business_unit = factory.Faker("word")


class PsModuleFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PsModule

    name = factory.sequence(lambda n: f"ps_module_{n}")

    public_description = factory.Faker("text")
    cpe = factory.List(
        [
            "cpe:/o:redhat:enterprise_linux:5",
            "cpe:/o:redhat:rhel_els:5",
            "cpe:/a:redhat:rhel_extras*:5",
            "cpe:/a:redhat:rhel_common:5",
        ]
    )

    private_trackers_allowed = factory.Faker("boolean")
    autofile_trackers = factory.Faker("boolean")
    special_handling_features = factory.List([factory.Faker("word") for _ in range(3)])

    bts_name = factory.Faker("word")
    bts_key = factory.Faker("word")
    bts_groups = factory.Dict(
        {
            "public": factory.List([factory.Faker("word") for _ in range(3)]),
            "embargoed": factory.List([factory.Faker("word") for _ in range(3)]),
        }
    )

    supported_from_dt = factory.Faker("date_time", tzinfo=UTC)
    supported_until_dt = factory.Faker(
        "date_time_between",
        tzinfo=UTC,
        start_date=factory.SelfAttribute("..supported_from_dt"),
    )

    default_cc = factory.List([factory.Faker("word") for _ in range(3)])
    private_tracker_cc = factory.List([factory.Faker("word") for _ in range(3)])

    default_component = factory.Faker("word")
    unacked_ps_update_stream = factory.Faker("word")

    ps_product = factory.SubFactory(PsProductFactory)


class PsUpdateStreamFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PsUpdateStream

    name = factory.sequence(lambda n: f"ps_update_stream_{n}")
    version = factory.Faker("word")
    target_release = factory.Faker("word")
    rhsa_sla_applicable = factory.Faker("boolean")

    collections = factory.List([factory.Faker("word") for _ in range(3)])
    flags = factory.List([factory.Faker("word") for _ in range(3)])

    ps_module = factory.SubFactory(PsModuleFactory)
    active_to_ps_module = factory.SelfAttribute("ps_module")
    default_to_ps_module = factory.LazyAttribute(lambda o: choice([o.ps_module, None]))
    aus_to_ps_module = factory.LazyAttribute(lambda o: choice([o.ps_module, None]))
    eus_to_ps_module = factory.LazyAttribute(lambda o: choice([o.ps_module, None]))
