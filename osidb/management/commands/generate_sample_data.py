import random
import uuid
from datetime import datetime, timezone

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from osidb.acls import ACL
from osidb.core import generate_acls, set_user_acls
from osidb.helpers import bypass_rls
from osidb.mixins import Alert
from osidb.models import (
    CVSS,
    Affect,
    AffectCVSS,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawLabelV2,
    FlawReference,
    FlawSource,
    Impact,
    Package,
    PackageVer,
    PsModule,
    PsProduct,
    PsUpdateStream,
    Tracker,
)
from osidb.models.affect import NotAffectedJustification

# ---------------------------------------------------------------------------
# Constants used for sample-data identification (cleanup queries)
# ---------------------------------------------------------------------------
SAMPLE_MODULE_NAMES = [
    "rhel-9",
    "rhel-8",
    "openshift-4",
    "satellite-6",
    "ansible-automation-platform-2",
]
SAMPLE_CVE_PREFIX = "CVE-2024-5"
SAMPLE_NO_CVE_TITLE = "[sample] flaw without CVE"
SAMPLE_PRODUCT_NAMES = [
    "sample_rhel_9",
    "sample_rhel_8",
    "sample_openshift",
    "sample_satellite",
    "sample_aap",
]
SAMPLE_TRACKER_PREFIX = "SAMPLE-"
SAMPLE_BZ_TRACKER_START = 2200000

# ---------------------------------------------------------------------------
# Pools of values cycled / randomly picked when scaling up
# ---------------------------------------------------------------------------
IMPACT_POOL = [
    Impact.CRITICAL,
    Impact.IMPORTANT,
    Impact.MODERATE,
    Impact.LOW,
    Impact.NOVALUE,
]
SOURCE_POOL = [
    FlawSource.INTERNET,
    FlawSource.CUSTOMER,
    FlawSource.REDHAT,
    FlawSource.GIT,
    FlawSource.RESEARCHER,
    FlawSource.UPSTREAM,
    FlawSource.GOOGLE,
]
MI_POOL = [
    Flaw.FlawMajorIncident.NOVALUE,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_REJECTED,
    Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
    Flaw.FlawMajorIncident.EXPLOITS_KEV_REQUESTED,
    Flaw.FlawMajorIncident.EXPLOITS_KEV_REJECTED,
    Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED,
    Flaw.FlawMajorIncident.MINOR_INCIDENT_REQUESTED,
    Flaw.FlawMajorIncident.MINOR_INCIDENT_REJECTED,
]
WF_STATE_POOL = [
    "NEW",
    "TRIAGE",
    "PRE_SECONDARY_ASSESSMENT",
    "SECONDARY_ASSESSMENT",
    "ANALYSIS",
    "DONE",
]
COMPONENT_POOL = [
    "kernel",
    "openssl",
    "httpd",
    "podman",
    "firefox",
    "curl",
    "systemd",
    "glibc",
    "bash",
    "sudo",
    "nginx",
    "python",
]
# (affectedness, resolution) pairs that are mutually valid
AFFECTEDNESS_RESOLUTION_POOL = [
    (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.DELEGATED),
    (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.WONTFIX),
    (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.OOSS),
    (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.DEFER),
    (Affect.AffectAffectedness.NEW, Affect.AffectResolution.NOVALUE),
    (Affect.AffectAffectedness.NOTAFFECTED, Affect.AffectResolution.NOVALUE),
]
TRACKER_STATUS_POOL = [
    ("In Progress", ""),
    ("New", ""),
    ("Review", ""),
    ("Closed", "Done"),
    ("Closed", "Won't Do"),
]

# Fixed CVSS vectors used for sample data
CVSS3_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS2_VECTOR = "AV:N/AC:L/Au:N/C:C/I:C/A:C"

# Default counts (preserve original hardcoded behaviour when no args given)
DEFAULT_FLAWS = 15
DEFAULT_AFFECTS_PER_FLAW = (1, 3)
DEFAULT_TRACKERS = 10


def _parse_range(value):
    """Parse a 'min,max' or single int string into a (min, max) tuple."""
    parts = value.split(",")
    if len(parts) == 1:
        n = int(parts[0])
        return (n, n)
    elif len(parts) == 2:
        lo, hi = int(parts[0]), int(parts[1])
        if lo > hi:
            raise ValueError
        return (lo, hi)
    else:
        raise ValueError


def _acls(embargoed):
    """Return (acl_read, acl_write) UUID lists matching the factory logic."""
    read_groups = (
        settings.EMBARGO_READ_GROUPS if embargoed else settings.PUBLIC_READ_GROUPS
    )
    write_groups = (
        settings.EMBARGO_WRITE_GROUPS if embargoed else settings.PUBLIC_WRITE_GROUPS
    )
    return (
        [uuid.UUID(a) for a in generate_acls(read_groups)],
        [uuid.UUID(a) for a in generate_acls(write_groups)],
    )


def _now():
    return datetime.now(tz=timezone.utc)


class Command(BaseCommand):
    help = "Populate the dev database with sample flaws, affects, trackers, and related objects"

    def add_arguments(self, parser):
        parser.add_argument(
            "--flaws",
            type=int,
            default=DEFAULT_FLAWS,
            help=f"Number of flaws to generate (default: {DEFAULT_FLAWS})",
        )
        parser.add_argument(
            "--affects-per-flaw",
            type=str,
            default=f"{DEFAULT_AFFECTS_PER_FLAW[0]},{DEFAULT_AFFECTS_PER_FLAW[1]}",
            help=(
                "Range of affects per flaw as 'min,max' or a single number "
                f"(default: {DEFAULT_AFFECTS_PER_FLAW[0]},{DEFAULT_AFFECTS_PER_FLAW[1]})"
            ),
        )
        parser.add_argument(
            "--trackers",
            type=int,
            default=DEFAULT_TRACKERS,
            help=(
                f"Total number of trackers to generate (default: {DEFAULT_TRACKERS}). "
                "Each tracker is linked to one or more affects."
            ),
        )

    def handle(self, *args, **options):
        num_flaws = options["flaws"]
        try:
            affects_range = _parse_range(options["affects_per_flaw"])
        except (ValueError, TypeError):
            raise CommandError(
                "Invalid --affects-per-flaw value. Use a single int or 'min,max'."
            )
        num_trackers = options["trackers"]

        if num_flaws < 1:
            raise CommandError("--flaws must be at least 1.")
        if affects_range[0] < 0:
            raise CommandError("--affects-per-flaw minimum must be >= 0.")
        if num_trackers < 0:
            raise CommandError("--trackers must be >= 0.")

        set_user_acls(settings.ALL_GROUPS)

        sample_qs = self._sample_querysets()
        counts = {label: qs.count() for label, qs in sample_qs}
        if any(counts.values()):
            summary = ", ".join(f"{v} {k}" for k, v in counts.items() if v)
            self.stdout.write(f"Found: {summary}")
            confirm = input("Delete all sample data before regenerating? [y/N] ")
            if confirm.lower() != "y":
                self.stdout.write("Aborted.")
                return
            self._delete_sample_data(sample_qs)

        self.stdout.write(
            f"Generating sample data: {num_flaws} flaws, "
            f"{affects_range[0]}-{affects_range[1]} affects/flaw, "
            f"{num_trackers} trackers..."
        )
        with transaction.atomic():
            ps_modules, streams = self._create_product_structure()
            flaws = self._create_flaws(num_flaws)
            affects = self._create_affects(flaws, ps_modules, streams, affects_range)
            tracker_count = self._create_trackers(affects, num_trackers)
            self._create_cvss(flaws, affects)
            self._create_related_objects(flaws)
            self._create_alerts(flaws, affects)
        self.stdout.write(
            self.style.SUCCESS(
                f"Created: {len(flaws)} flaws, {len(affects)} affects, "
                f"{tracker_count} trackers, {len(SAMPLE_MODULE_NAMES)} modules"
            )
        )

    # ------------------------------------------------------------------
    # Cleanup helpers
    # ------------------------------------------------------------------
    @bypass_rls
    def _delete_sample_data(self, sample_qs):
        """Delete all sample querysets.

        FlawLabelV2 is a PolymorphicModel whose FK to Flaw is not traversed
        by Django's cascade deletion collector, causing a FK violation at
        commit time.  Deleting it explicitly first (under bypass_rls so the
        ACL-filtered manager actually finds the rows) avoids the issue.
        """
        # Use non_polymorphic() to bypass the PolymorphicManager type
        # resolution that silently drops rows the cascade collector misses.
        FlawLabelV2.objects.non_polymorphic().filter(
            flaw__cve_id__startswith=SAMPLE_CVE_PREFIX
        ).delete()
        FlawLabelV2.objects.non_polymorphic().filter(
            flaw__title=SAMPLE_NO_CVE_TITLE
        ).delete()
        for _, qs in sample_qs:
            qs.delete()

    def _sample_querysets(self):
        return [
            (
                "trackers",
                Tracker.objects.filter(
                    external_system_id__startswith=SAMPLE_TRACKER_PREFIX
                )
                | Tracker.objects.filter(
                    external_system_id__gte=str(SAMPLE_BZ_TRACKER_START),
                    external_system_id__lt=str(SAMPLE_BZ_TRACKER_START + 1_000_000),
                ),
            ),
            (
                "flaws",
                Flaw.objects.filter(cve_id__startswith=SAMPLE_CVE_PREFIX),
            ),
            (
                "flaws (no CVE)",
                Flaw.objects.filter(title=SAMPLE_NO_CVE_TITLE),
            ),
            (
                "streams",
                PsUpdateStream.objects.filter(ps_module__name__in=SAMPLE_MODULE_NAMES),
            ),
            (
                "modules",
                PsModule.objects.filter(name__in=SAMPLE_MODULE_NAMES),
            ),
            (
                "products",
                PsProduct.objects.filter(short_name__in=SAMPLE_PRODUCT_NAMES),
            ),
        ]

    # ------------------------------------------------------------------
    # Product structure (modules + streams, shared across all affects)
    # ------------------------------------------------------------------
    def _create_product_structure(self):
        module_defs = [
            ("rhel-9", "jboss", "RHEL", "sample_rhel_9"),
            ("rhel-8", "bugzilla", "Red Hat Enterprise Linux 8", "sample_rhel_8"),
            ("openshift-4", "jboss", "OCPBUGS", "sample_openshift"),
            ("satellite-6", "jboss", "SAT", "sample_satellite"),
            ("ansible-automation-platform-2", "jboss", "AAP", "sample_aap"),
        ]
        ps_modules = []
        for name, bts_name, bts_key, product_short_name in module_defs:
            product, _ = PsProduct.objects.get_or_create(
                short_name=product_short_name,
                defaults={
                    "name": f"{product_short_name} long name",
                    "business_unit": "Engineering",
                },
            )
            module, _ = PsModule.objects.get_or_create(
                name=name,
                defaults={
                    "bts_name": bts_name,
                    "bts_key": bts_key,
                    "bts_groups": {"public": [bts_key]},
                    "public_description": f"Sample module {name}",
                    "ps_product": product,
                    "private_trackers_allowed": False,
                    "autofile_trackers": False,
                },
            )
            ps_modules.append(module)

        stream_defs = [
            ("rhel-9.4.0.z", 0),
            ("rhel-9.3.0.z", 0),
            ("rhel-8.9.0.z", 1),
            ("openshift-4.15.z", 2),
            ("satellite-6.14.z", 3),
            ("ansible-automation-platform-2.4", 4),
        ]
        streams = []
        for stream_name, module_idx in stream_defs:
            stream, _ = PsUpdateStream.objects.get_or_create(
                name=stream_name,
                defaults={
                    "ps_module": ps_modules[module_idx],
                    "active_to_ps_module": ps_modules[module_idx],
                    "version": stream_name,
                    "target_release": "",
                },
            )
            streams.append(stream)

        return ps_modules, streams

    # ------------------------------------------------------------------
    # Flaws
    # ------------------------------------------------------------------
    def _create_flaws(self, num_flaws):
        flaws = []
        now = _now()
        for i in range(num_flaws):
            impact = IMPACT_POOL[i % len(IMPACT_POOL)]
            source = SOURCE_POOL[i % len(SOURCE_POOL)]
            mi_state = MI_POOL[i % len(MI_POOL)]
            wf_state = WF_STATE_POOL[i % len(WF_STATE_POOL)]
            embargoed = source in (FlawSource.CUSTOMER, FlawSource.RESEARCHER)
            # One in every 5 non-embargoed flaws is internal-only, so internal
            # visibility is actually exercised by the sample data.
            internal = not embargoed and i % 5 == 4
            wf_name = "EMBARGOED" if embargoed else "DEFAULT"

            # One in every 15 flaws has no CVE
            if i > 0 and i % 15 == 13:
                cve_id = None
                title = SAMPLE_NO_CVE_TITLE
            else:
                cve_id = f"CVE-2024-5{i:04d}"
                prefix = "EMBARGOED " if embargoed else ""
                title = f"{prefix}{cve_id} kernel: sample vulnerability"

            is_mi = mi_state in (
                Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
                Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
                Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED,
            )
            if internal:
                acl_read, acl_write = ACL.INTERNAL.uuid_read, ACL.INTERNAL.uuid_write
            else:
                acl_read, acl_write = _acls(embargoed)

            flaw = Flaw(
                cve_id=cve_id,
                title=title,
                comment_zero=f"Comment zero for {cve_id or 'sample'}",
                impact=impact,
                source=source,
                major_incident_state=mi_state,
                nist_cvss_validation=Flaw.FlawNistCvssValidation.NOVALUE,
                workflow_name=wf_name,
                workflow_state=wf_state,
                statement="Sample statement" if is_mi else "",
                cve_description="I am a spooky CVE" if is_mi else "",
                mitigation="CVE mitigation" if is_mi else "",
                acl_read=acl_read,
                acl_write=acl_write,
                unembargo_dt=None if embargoed else now,
                meta_attr={
                    "bz_id": str(10000 + i),
                    "last_change_time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "test": "1",
                },
                created_dt=now,
                updated_dt=now,
                local_updated_dt=now,
            )
            flaw.save(auto_timestamps=False)
            flaws.append(flaw)
        return flaws

    # ------------------------------------------------------------------
    # Affects
    # ------------------------------------------------------------------
    def _create_affects(self, flaws, ps_modules, streams, affects_range):
        # Build (module_idx, stream_idx) pairs that belong together
        module_stream_pairs = []
        for mi, mod in enumerate(ps_modules):
            for si, stream in enumerate(streams):
                if stream.ps_module_id == mod.pk:
                    module_stream_pairs.append((mi, si))

        affects = []
        now = _now()
        for flaw in flaws:
            count = random.randint(affects_range[0], affects_range[1])  # noqa: S311
            # (ps_update_stream, ps_component) must be unique per flaw, so pick
            # from all pair/component combos rather than risking random collisions.
            combos = [
                (pair, comp) for pair in module_stream_pairs for comp in COMPONENT_POOL
            ]
            random.shuffle(combos)  # noqa: S311
            count = min(count, len(combos))
            for (pm_idx, stream_idx), component in combos[:count]:
                affectedness, resolution = random.choice(AFFECTEDNESS_RESOLUTION_POOL)  # noqa: S311
                stream = streams[stream_idx]
                module = ps_modules[pm_idx]

                impact = Impact.NOVALUE
                if random.random() < 0.1:  # noqa: S311
                    impact = random.choice(  # noqa: S311
                        [
                            Impact.CRITICAL,
                            Impact.IMPORTANT,
                            Impact.MODERATE,
                            Impact.LOW,
                        ]
                    )

                acl_read, acl_write = _acls(flaw.is_embargoed)
                not_affected_justification = (
                    NotAffectedJustification.COMPONENT_NOT_PRESENT
                    if affectedness == Affect.AffectAffectedness.NOTAFFECTED
                    else ""
                )
                affect = Affect(
                    flaw=flaw,
                    cve_id=flaw.cve_id,
                    affectedness=affectedness,
                    resolution=resolution,
                    not_affected_justification=not_affected_justification,
                    ps_module=module.name,
                    ps_component=component,
                    ps_update_stream=stream.name,
                    impact=impact,
                    purl=f"pkg:rpm/redhat/{component}@1?arch=src",
                    acl_read=acl_read,
                    acl_write=acl_write,
                    meta_attr={"test": "1"},
                    created_dt=now,
                    updated_dt=now,
                )
                affect.save(auto_timestamps=False)
                affects.append(affect)
        return affects

    # ------------------------------------------------------------------
    # Trackers — each tracker links to 1+ affects
    # ------------------------------------------------------------------
    def _create_trackers(self, affects, num_trackers):
        if num_trackers == 0 or not affects:
            return 0

        # Only DELEGATED affects typically get trackers
        eligible = [
            a for a in affects if a.resolution == Affect.AffectResolution.DELEGATED
        ]
        if not eligible:
            eligible = list(affects)

        random.shuffle(eligible)  # noqa: S311
        actual_trackers = min(num_trackers, len(eligible))
        buckets = [[] for _ in range(actual_trackers)]
        for idx, affect in enumerate(eligible):
            buckets[idx % actual_trackers].append(affect)

        now = _now()
        created = 0
        for i, linked_affects in enumerate(buckets):
            if not linked_affects:
                continue

            if i % 5 == 0:
                ttype = Tracker.TrackerType.BUGZILLA
                ext_id = str(SAMPLE_BZ_TRACKER_START + i)
            else:
                ttype = Tracker.TrackerType.JIRA
                ext_id = f"{SAMPLE_TRACKER_PREFIX}{i:05d}"

            status, resolution = random.choice(TRACKER_STATUS_POOL)  # noqa: S311
            embargoed = linked_affects[0].flaw.is_embargoed
            acl_read, acl_write = _acls(embargoed)

            tracker = Tracker(
                type=ttype,
                external_system_id=ext_id,
                status=status,
                resolution=resolution,
                ps_update_stream=linked_affects[0].ps_update_stream,
                cve_id=linked_affects[0].cve_id,
                acl_read=acl_read,
                acl_write=acl_write,
                meta_attr={"test": "1"},
                created_dt=now,
                updated_dt=now,
            )
            tracker.save(auto_timestamps=False)
            tracker.affects.set(linked_affects)
            created += 1
        return created

    # ------------------------------------------------------------------
    # CVSS scores
    # ------------------------------------------------------------------
    def _create_cvss(self, flaws, affects):
        now = _now()
        for i, flaw in enumerate(flaws):
            acl_read, acl_write = _acls(flaw.is_embargoed)
            if flaw.impact != Impact.NOVALUE:
                FlawCVSS.objects.create(
                    flaw=flaw,
                    version=CVSS.CVSSVersion.VERSION3,
                    issuer=CVSS.CVSSIssuer.REDHAT,
                    vector=CVSS3_VECTOR,
                    comment="CVSS RH comment",
                    acl_read=acl_read,
                    acl_write=acl_write,
                    created_dt=now,
                    updated_dt=now,
                )
            # First third + last flaw get NIST v3
            if i < len(flaws) // 3 or i == len(flaws) - 1:
                FlawCVSS.objects.create(
                    flaw=flaw,
                    version=CVSS.CVSSVersion.VERSION3,
                    issuer=CVSS.CVSSIssuer.NIST,
                    vector=CVSS3_VECTOR,
                    comment="",
                    acl_read=acl_read,
                    acl_write=acl_write,
                    created_dt=now,
                    updated_dt=now,
                )
            # First two flaws also get NIST v2
            if i < 2:
                FlawCVSS.objects.create(
                    flaw=flaw,
                    version=CVSS.CVSSVersion.VERSION2,
                    issuer=CVSS.CVSSIssuer.NIST,
                    vector=CVSS2_VECTOR,
                    comment="",
                    acl_read=acl_read,
                    acl_write=acl_write,
                    created_dt=now,
                    updated_dt=now,
                )

        # Affect CVSS for first few affects
        for affect in affects[: min(5, len(affects))]:
            acl_read, acl_write = _acls(affect.flaw.is_embargoed)
            AffectCVSS.objects.create(
                affect=affect,
                version=CVSS.CVSSVersion.VERSION3,
                issuer=CVSS.CVSSIssuer.REDHAT,
                vector=CVSS3_VECTOR,
                comment="CVSS RH comment",
                acl_read=acl_read,
                acl_write=acl_write,
                created_dt=now,
                updated_dt=now,
            )

        # Last flaw gets nist_cvss_validation=REQUESTED, but only if it actually
        # has both an RH and a NIST v3 score (RH v3 requires impact != NOVALUE).
        if flaws[-1].impact != Impact.NOVALUE:
            flaws[-1].nist_cvss_validation = Flaw.FlawNistCvssValidation.REQUESTED
            flaws[-1].save(auto_timestamps=False)

    # ------------------------------------------------------------------
    # Related objects (comments, acknowledgments, references, packages)
    # ------------------------------------------------------------------
    def _create_related_objects(self, flaws):
        now = _now()
        for flaw in flaws[: min(8, len(flaws))]:
            acl_read, acl_write = _acls(flaw.is_embargoed)
            FlawComment.objects.create(
                flaw=flaw,
                text=f"Initial triage comment for {flaw.cve_id or flaw.uuid}",
                external_system_id=f"sample-{flaw.uuid}",
                synced_to_bz=False,
                acl_read=acl_read,
                acl_write=acl_write,
                created_dt=now,
                updated_dt=now,
            )
            if flaw.impact in (Impact.CRITICAL, Impact.IMPORTANT):
                FlawComment.objects.create(
                    flaw=flaw,
                    text="Priority escalation noted.",
                    external_system_id=f"sample-priv-{flaw.uuid}",
                    synced_to_bz=False,
                    is_private=True,
                    acl_read=acl_read,
                    acl_write=acl_write,
                    created_dt=now,
                    updated_dt=now,
                )

        # Acknowledgments on private-source flaws
        private_flaws = [
            f for f in flaws if f.source in (FlawSource.CUSTOMER, FlawSource.RESEARCHER)
        ]
        for pf in private_flaws[:2]:
            acl_read, acl_write = _acls(pf.is_embargoed)
            FlawAcknowledgment.objects.create(
                flaw=pf,
                name="Alice Doe",
                affiliation="CERT/CC",
                from_upstream=False,
                acl_read=acl_read,
                acl_write=acl_write,
                created_dt=now,
                updated_dt=now,
            )
            FlawAcknowledgment.objects.create(
                flaw=pf,
                name="Bob Chen",
                affiliation="",
                from_upstream=True,
                acl_read=acl_read,
                acl_write=acl_write,
                created_dt=now,
                updated_dt=now,
            )

        # References on first flaw
        if flaws:
            RT = FlawReference.FlawReferenceType
            acl_read, acl_write = _acls(flaws[0].is_embargoed)
            for ref_type, url in [
                (RT.ARTICLE, "https://access.redhat.com/articles/12345"),
                (
                    RT.EXTERNAL,
                    f"https://nvd.nist.gov/vuln/detail/{flaws[0].cve_id or 'sample'}",
                ),
                (RT.SOURCE, "https://git.kernel.org/stable/c/abc123"),
            ]:
                FlawReference.objects.create(
                    flaw=flaws[0],
                    type=ref_type,
                    url=url,
                    description="",
                    acl_read=acl_read,
                    acl_write=acl_write,
                    created_dt=now,
                    updated_dt=now,
                )

            pkg1 = Package.objects.create(
                flaw=flaws[0],
                package="kernel",
                acl_read=acl_read,
                acl_write=acl_write,
                created_dt=now,
                updated_dt=now,
            )
            PackageVer.objects.create(package=pkg1, version="5.14.0-362.el9")
            PackageVer.objects.create(package=pkg1, version="5.14.0-284.el9")

        if len(flaws) > 2:
            RT = FlawReference.FlawReferenceType
            acl_read, acl_write = _acls(flaws[2].is_embargoed)
            FlawReference.objects.create(
                flaw=flaws[2],
                type=RT.UPSTREAM,
                url=f"https://httpd.apache.org/security/{flaws[2].cve_id or 'sample'}",
                description="",
                acl_read=acl_read,
                acl_write=acl_write,
                created_dt=now,
                updated_dt=now,
            )
            pkg2 = Package.objects.create(
                flaw=flaws[2],
                package="httpd",
                acl_read=acl_read,
                acl_write=acl_write,
                created_dt=now,
                updated_dt=now,
            )
            PackageVer.objects.create(package=pkg2, version="2.4.57-8.el9")

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def _create_alerts(self, flaws, affects):
        W, E = Alert.AlertType.WARNING, Alert.AlertType.ERROR

        flaw_alerts = [
            (
                0,
                "rh_nist_cvss_score_diff",
                "RH and NIST CVSS scores differ significantly",
                W,
            ),
            (
                0,
                "rh_nist_cvss_severity_diff",
                "RH and NIST CVSS severity ratings differ",
                W,
            ),
            (
                1,
                "private_source_no_ack",
                "Flaw has a private source but no acknowledgment from upstream",
                W,
            ),
            (
                3,
                "special_consideration_flaw_missing_statement",
                "Special consideration flaw is missing a statement",
                E,
            ),
            (
                4,
                "special_consideration_flaw_missing_cve_description",
                "Special consideration flaw is missing a CVE description",
                E,
            ),
            (
                5,
                "mi_article_missing",
                "Major incident flaw is missing an article reference",
                E,
            ),
            (
                5,
                "mi_statement_missing",
                "Major incident flaw is missing a statement",
                E,
            ),
            (
                6,
                "mi_cve_description_missing",
                "Major incident flaw is missing a CVE description",
                W,
            ),
            (
                8,
                "embargoed_source_public",
                "Flaw source is marked as embargoed but flaw is public",
                W,
            ),
            (
                9,
                "request_nist_cvss_validation",
                "NIST CVSS validation has been requested",
                W,
            ),
        ]
        for idx, name, desc, atype in flaw_alerts:
            if idx < len(flaws):
                flaws[idx].alert(name, desc, atype)
        if flaws:
            flaws[-1].alert(
                "unsupported_impact_change",
                "Impact has changed for a flaw in an unsupported product",
                W,
            )

        affect_alerts = [
            (
                5,
                "flaw_affects_unknown_component",
                "The affect component is not recognized in product definitions",
                W,
            ),
            (
                6,
                "flaw_historical_affect_status",
                "Affect uses a historical affectedness/resolution combination",
                W,
            ),
            (
                8,
                "flaw_affects_unknown_component",
                "The affect component is not recognized in product definitions",
                W,
            ),
        ]
        for idx, name, desc, atype in affect_alerts:
            if idx < len(affects):
                affects[idx].alert(name, desc, atype)
        if len(affects) > 14:
            affects[14].alert(
                "old_flaw_affect_ps_module",
                "Affect uses a deprecated PS module name",
                W,
            )
