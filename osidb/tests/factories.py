import uuid
from random import choice

import factory
import factory.fuzzy
from cvss.constants2 import METRICS_VALUE_NAMES as CVSS2_METRICS_VALUE_NAMES
from cvss.constants3 import METRICS_VALUE_NAMES as CVSS3_METRICS_VALUE_NAMES
from cvss.constants4 import METRICS_VALUE_NAMES as CVSS4_METRICS_VALUE_NAMES
from django.conf import settings
from pytz import UTC

from osidb.constants import AFFECTEDNESS_VALID_RESOLUTIONS, DATETIME_FMT
from osidb.core import generate_acls
from osidb.models import (
    CVSS,
    Affect,
    AffectCVSS,
    Erratum,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawMeta,
    FlawReference,
    FlawSource,
    FlawType,
    Impact,
    Package,
    PackageVer,
    PsContact,
    PsModule,
    PsProduct,
    PsUpdateStream,
    Snippet,
    Tracker,
)

DATA_PRODSEC_ACL_READ = uuid.uuid5(
    uuid.NAMESPACE_URL,
    "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
)
DATA_PRODSEC_ACL_WRITE = uuid.uuid5(
    uuid.NAMESPACE_URL,
    "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
)


class BaseFactory(factory.django.DjangoModelFactory):
    """
    base test factory overriding DjangoModelFactory where necessary
    """

    @classmethod
    def _after_postgeneration(cls, instance, create, results=None):
        """
        the original implementation is not really compatible with TrackingMixin
        https://github.com/FactoryBoy/factory_boy/blob/3.2.1/factory/django.py#L173
        """
        if create and results:
            instance.save(auto_timestamps=False)


class FlawFactory(BaseFactory):
    class Meta:
        model = Flaw

    class Params:
        # Note that factory.Faker cannot be used directly in factory.LazyAttribute.

        fallback = factory.Faker("random_element", elements=["", "foo"])

        impact_requiring_summary = factory.LazyAttribute(
            lambda f: f.impact in [Impact.MODERATE, Impact.IMPORTANT, Impact.CRITICAL]
        )

        is_mi = factory.LazyAttribute(
            lambda f: f.major_incident_state
            in [Flaw.FlawMajorIncident.APPROVED, Flaw.FlawMajorIncident.CISA_APPROVED]
        )

        not_mi_with_summary = factory.Faker(
            "random_element", elements=list(Flaw.FlawRequiresSummary)
        )

        not_mi_without_summary = factory.Faker(
            "random_element",
            elements=[
                Flaw.FlawRequiresSummary.NOVALUE,
                Flaw.FlawRequiresSummary.REJECTED,
            ],
        )

    cve_id = factory.sequence(lambda n: f"CVE-2020-1000{n}")
    cwe_id = factory.Faker("random_element", elements=["CWE-1", ""])
    type = factory.Faker("random_element", elements=list(FlawType))
    created_dt = factory.Faker("date_time", tzinfo=UTC)
    reported_dt = factory.LazyAttribute(lambda f: f.created_dt)
    updated_dt = factory.LazyAttribute(lambda f: f.created_dt)
    local_updated_dt = factory.LazyAttribute(lambda f: f.created_dt)
    impact = factory.Faker(
        "random_element", elements=list(set(Impact) - {Impact.NOVALUE})
    )
    components = factory.List([factory.Faker("word") for _ in range(3)])
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
    major_incident_state = factory.Faker(
        "random_element",
        elements=list(set(Flaw.FlawMajorIncident) - {Flaw.FlawMajorIncident.INVALID}),
    )
    nist_cvss_validation = factory.Faker(
        "random_element",
        elements=[
            Flaw.FlawNistCvssValidation.NOVALUE,
            # TODO: values below are currently commented out because FlawFactory is not
            #       able to create two cvss via FlawCVSSFactory. Therefore, these values
            #       are tested in test_validate_cvss_scores_and_nist_cvss_validation.
            # Flaw.FlawNistCvssValidation.REQUESTED,
            # Flaw.FlawNistCvssValidation.APPROVED,
            # Flaw.FlawNistCvssValidation.REJECTED,
        ],
    )
    summary = factory.LazyAttribute(
        lambda f: "I am a spooky CVE"
        if f.is_mi
        else ("random summary" if f.impact_requiring_summary else f.fallback)
    )

    @factory.lazy_attribute
    def requires_summary(self):
        if not self.is_mi and self.summary:
            return self.not_mi_with_summary
        elif not self.is_mi and not self.summary:
            return self.not_mi_without_summary
        elif self.is_mi and self.summary:
            return Flaw.FlawRequiresSummary.APPROVED
        # MI without summary is not a valid combination and should never happen,
        # but leaving it here to cover all possibilities
        else:
            return Flaw.FlawRequiresSummary.NOVALUE

    mitigation = factory.LazyAttribute(
        lambda f: "CVE mitigation" if f.is_mi else f.fallback
    )
    unembargo_dt = factory.Maybe(
        "embargoed",
        yes_declaration=factory.Faker("future_datetime", tzinfo=UTC),
        no_declaration=factory.Faker("past_datetime", tzinfo=UTC),
    )
    cvss3 = "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
    source = factory.Maybe(
        "embargoed",
        yes_declaration=factory.Faker(
            "random_element",
            elements=[
                FlawSource.CUSTOMER,
                FlawSource.GOOGLE,
                FlawSource.REDHAT,
                FlawSource.RESEARCHER,
                FlawSource.UPSTREAM,
            ],
        ),
        no_declaration=factory.Faker(
            "random_element",
            elements=[
                FlawSource.GIT,
                FlawSource.INTERNET,
            ],
        ),
    )
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
    # valid flaw is expected to have certain meta attributes present
    meta_attr = factory.LazyAttribute(
        lambda c: {
            "bz_id": getattr(c, "bz_id", "12345"),
            "last_change_time": c.updated_dt
            if isinstance(c.updated_dt, str)
            else c.updated_dt.strftime(DATETIME_FMT),
            "test": "1",
        }
    )

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """
        instance creation
        with saving to DB
        """
        # bz_id is not a real model attribute
        # it is just a shortcut to set it in the meta_attr
        kwargs.pop("bz_id", None)
        flaw = cls._build(model_class, *args, **kwargs)
        # turn of automatic timestamps
        # so we can explicitly assign them
        flaw.save(auto_timestamps=False)
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


class AffectFactory(BaseFactory):
    class Meta:
        model = Affect
        django_get_or_create = ("flaw", "ps_module", "ps_component")

    affectedness = factory.fuzzy.FuzzyChoice(
        [
            Affect.AffectAffectedness.NEW,
            Affect.AffectAffectedness.AFFECTED,
            Affect.AffectAffectedness.NOTAFFECTED,
        ]
    )
    resolution = factory.LazyAttribute(
        lambda a: AFFECTEDNESS_VALID_RESOLUTIONS[a.affectedness][0]
    )
    ps_module = factory.sequence(lambda n: f"ps-module-{n}")
    ps_component = factory.sequence(lambda n: f"ps-component-{n}")
    impact = factory.Faker("random_element", elements=list(Impact))

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.Faker("date_time", tzinfo=UTC)

    flaw = factory.SubFactory(FlawFactory)

    # let us inherit the parent flaw ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)

    meta_attr = factory.Dict({"test": "1"})

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """
        instance creation
        with saving to DB
        """
        affect = cls._build(model_class, *args, **kwargs)
        # turn of automatic timestamps
        # so we can explicitly assign them
        affect.save(auto_timestamps=False)
        return affect


class FlawCommentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = FlawComment

    type = "BUGZILLA"
    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.Faker("date_time", tzinfo=UTC)
    external_system_id = factory.sequence(lambda n: f"fake-external-id{n}")

    # let us inherit the parent flaw ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)
    order = factory.Sequence(lambda n: n)
    text = "some comment text"

    flaw = factory.SubFactory(FlawFactory)

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
    updated_dt = factory.Faker("date_time", tzinfo=UTC)

    # let us inherit the parent flaw ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)

    meta_attr = {
        "url": "http://nonexistenturl.example.com/1285930",
        "type": "external",
    }

    flaw = factory.SubFactory(FlawFactory)


class FlawAcknowledgmentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = FlawAcknowledgment

    name = "John Doe"
    affiliation = "Acme Corp."
    from_upstream = False

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.Faker("date_time", tzinfo=UTC)

    # let us inherit the parent flaw ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)

    flaw = factory.SubFactory(FlawFactory)


class FlawReferenceFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = FlawReference

    type = FlawReference.FlawReferenceType.EXTERNAL
    url = "https://httpd.apache.org/link123"
    description = "link description"

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.Faker("date_time", tzinfo=UTC)

    # let us inherit the parent flaw ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)

    flaw = factory.SubFactory(FlawFactory)


class PackageFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Package

    package = "package"

    flaw = factory.SubFactory(FlawFactory)

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.Faker("date_time", tzinfo=UTC)

    # let us inherit the parent flaw ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)


class PackageVerFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PackageVer

    version = "3.2.1"
    package = factory.SubFactory(PackageFactory)


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

    bts_name = factory.Faker("random_element", elements=["bugzilla", "jboss"])
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

    default_component = factory.Faker("word")

    ps_product = factory.SubFactory(PsProductFactory)


class PsUpdateStreamFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PsUpdateStream

    name = factory.sequence(lambda n: f"ps_update_stream_{n}")
    version = factory.Faker("word")
    target_release = factory.Faker("word")

    collections = factory.List([factory.Faker("word") for _ in range(3)])
    flags = factory.List([factory.Faker("word") for _ in range(3)])

    ps_module = factory.SubFactory(PsModuleFactory)
    active_to_ps_module = factory.SelfAttribute("ps_module")
    default_to_ps_module = factory.LazyAttribute(lambda o: choice([o.ps_module, None]))
    aus_to_ps_module = factory.LazyAttribute(lambda o: choice([o.ps_module, None]))
    eus_to_ps_module = factory.LazyAttribute(lambda o: choice([o.ps_module, None]))
    unacked_to_ps_module = factory.LazyAttribute(lambda o: choice([o.ps_module, None]))


class SnippetFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Snippet

    class Params:
        cve_id = factory.LazyAttribute(lambda f: "CVE-2024-0001")
        ext_id = factory.LazyAttribute(
            lambda f: f.cve_id if f.source == Snippet.Source.NVD else "GHSA-0001"
        )
        url = factory.LazyAttribute(
            lambda f: f"https://nvd.nist.gov/vuln/detail/{f.ext_id}"
            if f.source == Snippet.Source.NVD
            else f"https://osv.dev/vulnerability/{f.ext_id}"
        )

    source = factory.Faker(
        "random_element", elements=[Snippet.Source.NVD, Snippet.Source.OSV]
    )

    external_id = factory.LazyAttribute(
        lambda f: f.ext_id
        if f.source == Snippet.Source.NVD or f.cve_id is None
        else f"{f.ext_id}/{f.cve_id}"
    )

    @factory.lazy_attribute
    def content(self):
        # contains all NVD fields and only the currently used OSV fields
        data = {
            "cve_id": self.cve_id,
            "cvss_scores": [
                {
                    "score": 8.1,
                    "issuer": FlawCVSS.CVSSIssuer.NIST,
                    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "version": FlawCVSS.CVSSVersion.VERSION3,
                }
            ],
            "cwe_id": "CWE-110",
            "description": "some description",
            "references": [
                {"url": self.url, "type": FlawReference.FlawReferenceType.SOURCE}
            ],
            "source": self.source,
            "title": f"From {self.source} collector",
            f"published_in_{self.source.lower()}": "2024-01-21T16:29:00.393Z",
        }

        return data

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.Faker("date_time", tzinfo=UTC)

    acl_read = [uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])]
    acl_write = [
        uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])
    ]


class TrackerFactory(BaseFactory):
    class Meta:
        model = Tracker
        django_get_or_create = ("type", "external_system_id")

    type = factory.Faker("random_element", elements=list(Tracker.TrackerType))
    external_system_id = factory.LazyAttributeSequence(
        lambda o, n: f"{o.type}-{n}" if o.type else f"{n}"
    )
    status = factory.Faker("word")
    resolution = factory.Faker("word")
    ps_update_stream = factory.LazyFunction(lambda: PsUpdateStreamFactory().name)

    embargoed = factory.Faker("random_element", elements=[False, True])
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

    meta_attr = {"test": "1"}

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.LazyAttribute(lambda f: f.created_dt)

    @factory.post_generation
    def affects(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for affect in extracted:
                self.affects.add(affect)

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """
        instance creation
        with saving to DB
        """
        tracker = cls._build(model_class, *args, **kwargs)
        # turn of automatic timestamps
        # so we can explicitly assign them
        tracker.save(auto_timestamps=False)
        return tracker

    @classmethod
    def _build(cls, model_class, *args, **kwargs):
        """
        instance build
        without saving to DB
        """
        # embargoed is not a real model attribute but annotation so it is read-only
        # but we want preserve it as writable factory attribute as it is easier to work with
        # than with ACLs so we need to remove it for the tracker creation and emulate annotation
        embargoed = kwargs.pop("embargoed")
        tracker = super()._build(model_class, *args, **kwargs)
        tracker.embargoed = embargoed
        return tracker


class CVSSFactory(factory.django.DjangoModelFactory):
    class Params:
        # CVSS2 params
        cvss2_access_vector = factory.Faker(
            "random_element", elements=CVSS2_METRICS_VALUE_NAMES["AV"].keys()
        )
        cvss2_access_complexity = factory.Faker(
            "random_element", elements=CVSS2_METRICS_VALUE_NAMES["AC"].keys()
        )
        cvss2_authentication = factory.Faker(
            "random_element", elements=CVSS2_METRICS_VALUE_NAMES["Au"].keys()
        )
        cvss2_confidentiality_impact = factory.Faker(
            "random_element", elements=CVSS2_METRICS_VALUE_NAMES["C"].keys()
        )
        cvss2_integrity_impact = factory.Faker(
            "random_element", elements=CVSS2_METRICS_VALUE_NAMES["I"].keys()
        )
        cvss2_availablity_impact = factory.Faker(
            "random_element", elements=CVSS2_METRICS_VALUE_NAMES["A"].keys()
        )

        # CVSS3 params
        cvss3_attack_vector = factory.Faker(
            "random_element", elements=CVSS3_METRICS_VALUE_NAMES["AV"].keys()
        )
        cvss3_attack_complexity = factory.Faker(
            "random_element",
            elements=CVSS3_METRICS_VALUE_NAMES["AC"].keys(),
        )
        cvss3_privileges_required = factory.Faker(
            "random_element",
            elements=CVSS3_METRICS_VALUE_NAMES["PR"].keys(),
        )
        cvss3_user_interaction = factory.Faker(
            "random_element",
            elements=CVSS3_METRICS_VALUE_NAMES["UI"].keys(),
        )
        cvss3_scope = factory.Faker(
            "random_element",
            elements=CVSS3_METRICS_VALUE_NAMES["S"].keys(),
        )
        cvss3_confidentiality = factory.Faker(
            "random_element",
            elements=CVSS3_METRICS_VALUE_NAMES["C"].keys(),
        )
        cvss3_integrity = factory.Faker(
            "random_element",
            elements=CVSS3_METRICS_VALUE_NAMES["I"].keys(),
        )
        cvss3_availability = factory.Faker(
            "random_element",
            elements=CVSS3_METRICS_VALUE_NAMES["A"].keys(),
        )

        # CVSS4 params
        cvss4_attack_vector = factory.Faker(
            "random_element", elements=CVSS4_METRICS_VALUE_NAMES["AV"].keys()
        )
        cvss4_attack_complexity = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["AC"].keys(),
        )
        cvss4_attack_requirements = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["AT"].keys(),
        )
        cvss4_privileges_required = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["PR"].keys(),
        )
        cvss4_user_interaction = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["UI"].keys(),
        )
        cvss4_vulnerable_system_impact_confidentiality = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["VC"].keys(),
        )
        cvss4_vulnerable_system_impact_integrity = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["VI"].keys(),
        )
        cvss4_vulnerable_system_impact_availability = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["VA"].keys(),
        )
        cvss4_subsequent_system_impact_confidentiality = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["SC"].keys(),
        )
        cvss4_subsequent_system_impact_integrity = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["SI"].keys(),
        )
        cvss4_subsequent_system_impact_availability = factory.Faker(
            "random_element",
            elements=CVSS4_METRICS_VALUE_NAMES["SA"].keys(),
        )

    version = factory.Faker("random_element", elements=list(CVSS.CVSSVersion))
    issuer = factory.Faker("random_element", elements=list(CVSS.CVSSIssuer))

    @factory.lazy_attribute
    def vector(self):
        vectors = {
            CVSS.CVSSVersion.VERSION2: (
                f"AV:{self.cvss2_access_vector}"
                f"/AC:{self.cvss2_access_complexity}"
                f"/Au:{self.cvss2_authentication}"
                f"/C:{self.cvss2_confidentiality_impact}"
                f"/I:{self.cvss2_integrity_impact}"
                f"/A:{self.cvss2_availablity_impact}"
            ),
            CVSS.CVSSVersion.VERSION3: (
                f"CVSS:3.1/AV:{self.cvss3_attack_vector}"
                f"/AC:{self.cvss3_attack_complexity}"
                f"/PR:{self.cvss3_privileges_required}"
                f"/UI:{self.cvss3_user_interaction}"
                f"/S:{self.cvss3_scope}"
                f"/C:{self.cvss3_confidentiality}"
                f"/I:{self.cvss3_integrity}"
                f"/A:{self.cvss3_availability}"
            ),
            CVSS.CVSSVersion.VERSION4: (
                f"CVSS:4.0/AV:{self.cvss4_attack_vector}"
                f"/AC:{self.cvss4_attack_complexity}"
                f"/AT:{self.cvss4_attack_requirements}"
                f"/PR:{self.cvss4_privileges_required}"
                f"/UI:{self.cvss4_user_interaction}"
                f"/VC:{self.cvss4_vulnerable_system_impact_confidentiality}"
                f"/VI:{self.cvss4_vulnerable_system_impact_integrity}"
                f"/VA:{self.cvss4_vulnerable_system_impact_availability}"
                f"/SC:{self.cvss4_subsequent_system_impact_confidentiality}"
                f"/SI:{self.cvss4_subsequent_system_impact_integrity}"
                f"/SA:{self.cvss4_subsequent_system_impact_availability}"
            ),
        }

        return vectors[self.version]

    comment = factory.LazyAttribute(
        lambda o: "CVSS RH comment" if o.issuer == CVSS.CVSSIssuer.REDHAT else ""
    )

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.Faker("date_time", tzinfo=UTC)


class FlawCVSSFactory(CVSSFactory):
    class Meta:
        model = FlawCVSS
        django_get_or_create = ("flaw", "issuer", "version")

    flaw = factory.SubFactory(FlawFactory)

    # let us inherit the parent flaw ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.flaw.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.flaw.acl_write)


class AffectCVSSFactory(CVSSFactory):
    class Meta:
        model = AffectCVSS
        django_get_or_create = ("affect", "issuer", "version")

    affect = factory.SubFactory(AffectFactory)

    # let us inherit the parent affect ACLs if not specified
    acl_read = factory.LazyAttribute(lambda o: o.affect.acl_read)
    acl_write = factory.LazyAttribute(lambda o: o.affect.acl_write)


class ErratumFactory(BaseFactory):
    class Meta:
        model = Erratum

    et_id = factory.sequence(lambda n: f"{n}")
    advisory_name = factory.sequence(lambda n: f"RHSA-2020:{n}")

    created_dt = factory.Faker("date_time", tzinfo=UTC)
    updated_dt = factory.LazyAttribute(lambda f: f.created_dt)
    shipped_dt = factory.LazyAttribute(lambda f: f.created_dt)
