"""
transform Bugzilla flaw bug into OSIDB flaw model
"""
import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime
from functools import cached_property

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from collectors.bzimport.srtnotes_parser import parse_cf_srtnotes
from collectors.jiraffe.convertors import TrackerConvertor
from osidb.core import generate_acls, set_user_acls
from osidb.helpers import filter_cves
from osidb.mixins import AlertMixin, TrackingMixin
from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawReference,
    Package,
    PackageVer,
    Tracker,
)

from ..utils import (
    tracker_parse_update_stream_component,
    tracker_summary2module_component,
)
from .constants import BZ_DT_FMT, BZ_ENABLE_IMPORT_EMBARGOED
from .exceptions import NonRecoverableBZImportException
from .fixups import AffectFixer, FlawFixer

logger = logging.getLogger(__name__)


class BugzillaGroupsConvertorMixin:
    """
    shared functionality to convert Bugzilla groups to ACLs
    """

    @property
    def bz_id(self):
        """
        required property to be defined in the child classes
        """
        raise NotImplementedError

    @property
    def bug(self):
        """
        generic shortcut to be specified in the child classes
        """
        raise NotImplementedError

    @property
    def groups(self):
        """
        appropriate overall LDAP groups
        """
        return self.groups_read + self.groups_write

    @property
    def groups_read(self):
        """
        appropriate read LDAP groups
        """
        return self.get_group("read")

    @property
    def groups_write(self):
        """
        appropriate write LDAP groups
        """
        return self.get_group("write")

    def get_group(self, operation):
        """
        appropriate LDAP group
        """
        mapping = {
            "read": {
                "public": settings.PUBLIC_READ_GROUPS,
                "internal": [settings.INTERNAL_READ_GROUP],
                "embargo": [settings.EMBARGO_READ_GROUP],
            },
            "write": {
                "public": [settings.PUBLIC_WRITE_GROUP],
                "internal": [settings.INTERNAL_WRITE_GROUP],
                "embargo": [settings.EMBARGO_WRITE_GROUP],
            },
        }

        if not self.bug.get("groups", []):
            return mapping[operation]["public"]

        elif "security" not in self.bug.get("groups", []):
            return mapping[operation]["internal"]

        else:
            if not BZ_ENABLE_IMPORT_EMBARGOED:
                raise self.FlawConvertorException(
                    f"Bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
                )
            return mapping[operation]["embargo"]

    @cached_property
    def acl_read(self):
        """
        get read ACL based on read groups

        it is necessary to generete UUIDs and not just hashes
        so the ACL validations may properly compare the result
        """
        return [uuid.UUID(acl) for acl in generate_acls(self.groups_read)]

    @cached_property
    def acl_write(self):
        """
        get write ACL based on write groups

        it is necessary to generete UUIDs and not just hashes
        so the ACL validations may properly compare the result
        """
        return [uuid.UUID(acl) for acl in generate_acls(self.groups_write)]


class BugzillaTrackerConvertor(BugzillaGroupsConvertorMixin, TrackerConvertor):
    """
    Bugzilla tracker bug to OSIDB tracker convertor.
    """

    @property
    def type(self):
        """
        concrete tracker specification
        """
        return Tracker.TrackerType.BUGZILLA

    @property
    def bz_id(self):
        """
        Bugzilla ID
        """
        return self.bug["id"]

    @property
    def bug(self):
        """
        generic bug used in mixin context
        means the raw tracker data here
        """
        return self._raw

    def _normalize(self) -> dict:
        """
        raw data normalization
        """
        ps_module, ps_component = tracker_summary2module_component(self._raw["summary"])
        ps_update_stream = tracker_parse_update_stream_component(self._raw["summary"])[
            0
        ]

        self.ps_module = ps_module
        self.ps_component = ps_component
        self.ps_update_stream = ps_update_stream
        created_dt = datetime.strptime(self._raw["creation_time"], "%Y-%m-%dT%H:%M:%Sz")
        updated_dt = datetime.strptime(
            self._raw["last_change_time"], "%Y-%m-%dT%H:%M:%Sz"
        )
        resolved_dt = None
        if self._raw["cf_last_closed"]:
            resolved_dt = datetime.strptime(
                self._raw["cf_last_closed"], "%Y-%m-%dT%H:%M:%Sz"
            ).replace(tzinfo=timezone.get_current_timezone())
        return {
            "external_system_id": self._raw["id"],
            "owner": self._raw["assigned_to"],
            "qe_owner": self._raw["qa_contact"],
            "ps_module": ps_module,
            "ps_component": ps_component,
            "ps_update_stream": ps_update_stream,
            "status": self._raw["status"],
            "resolution": self._raw["resolution"],
            "not_affected_justification": None,
            "created_dt": created_dt.replace(tzinfo=timezone.get_current_timezone()),
            "updated_dt": updated_dt.replace(tzinfo=timezone.get_current_timezone()),
            "blocks": json.dumps(self._raw["blocks"]),
            "groups": json.dumps(self._raw["groups"]),
            "whiteboard": self._raw["whiteboard"],
            "resolved_dt": resolved_dt,
        }


class FlawSaver:
    """
    FlawSaver is holder of the individual flaw parts provided by FlawConvertor
    which knows how to correctly save them all as the resulting Django DB models
    it provides save method as an interface to perform the whole save operation
    """

    def __init__(
        self,
        flaw,
        affects,
        comments,
        acknowledgments,
        references,
        cvss_scores,
        package_versions,
    ):
        self.flaw = flaw
        self.affects = affects[0]
        self.affects_cvss_scores = affects[1]
        self.comments = comments
        self.acknowledgments = acknowledgments
        self.references = references
        self.cvss_scores = cvss_scores
        self.package_versions = package_versions

    def __str__(self):
        return f"FlawSaver {self.flaw.meta_attr['bz_id']}:{self.flaw.cve_id}"

    @property
    def all_parts(self):
        """get all parts in save-able order"""
        return (
            [self.flaw]
            + self.affects
            + self.affects_cvss_scores
            + self.comments
            + self.acknowledgments
            + self.references
            + self.cvss_scores
        )

    def save_packageversions(self):
        """
        Saves Package and their associated PackageVer and removes obsoleted.
        """
        for package, versions in self.package_versions.items():
            package_instance = Package.objects.create_package(
                flaw=self.flaw,
                package=package,
                acl_read=self.flaw.acl_read,
                acl_write=self.flaw.acl_write,
            )
            # remove all the existing versions
            package_instance.versions.all().delete()
            # replace them
            for version in versions:
                PackageVer.objects.create(
                    version=version,
                    package=package_instance,
                )
        # remove obsoleted Package instances
        Package.objects.filter(
            flaw=self.flaw,
        ).exclude(package__in=self.package_versions.keys()).delete()
        # remove obsoleted versions
        PackageVer.objects.filter(package__isnull=True).delete()

    def clean_affects(self):
        """clean obsoleted affects"""
        # TODO: potentially optimize?
        for old_affect in self.flaw.affects.all():
            for new_affect in self.affects:
                if (
                    old_affect.ps_module == new_affect.ps_module
                    and old_affect.ps_component == new_affect.ps_component
                ):
                    break
            else:
                # affect does not exist any more
                old_affect.delete()

    def clean_affects_cvss_scores(self):
        """clean obsoleted affect cvss scores"""
        old_cvss = set()
        for affect in self.flaw.affects.all():
            for cvss_scores in affect.cvss_scores.all():
                old_cvss.add(cvss_scores)

        new_cvss = set(self.affects_cvss_scores)

        to_delete = list(old_cvss - new_cvss)
        for cvss in to_delete:
            cvss.delete()

    def clean_acknowledgments(self):
        """clean obsoleted flaw acknowledgments"""
        old_acknowledgments = set(self.flaw.acknowledgments.all())
        new_acknowledgments = set(self.acknowledgments)

        to_delete = list(old_acknowledgments - new_acknowledgments)
        for acknowledgment in to_delete:
            acknowledgment.delete()

    def clean_references(self):
        """clean obsoleted flaw references"""
        old_references = set(self.flaw.references.all())
        new_references = set(self.references)

        to_delete = list(old_references - new_references)
        for reference in to_delete:
            reference.delete()

    def clean_cvss_scores(self):
        """clean obsoleted flaw cvss scores"""
        old_cvss = set(self.flaw.cvss_scores.all())
        new_cvss = set(self.cvss_scores)

        to_delete = list(old_cvss - new_cvss)
        for cvss in to_delete:
            cvss.delete()

    def save(self, **kwargs):
        """save flaw with its context to DB"""
        # wrap this in an atomic transaction so that
        # we don't query this flaw during the process
        with transaction.atomic():
            no_alerts = kwargs.get("no_alerts", False)
            for part in self.all_parts:
                part_kwargs = {}

                # we want to store the original timestamps
                # so we turn off assigning the automatic ones
                if isinstance(part, TrackingMixin):
                    part_kwargs["auto_timestamps"] = False

                # we want to store all the data fetched by the collector
                # so we suppress the exception raising in favor of alerts
                if isinstance(part, AlertMixin):
                    part_kwargs["raise_validation_error"] = False
                    # collection during saves should validate only once
                    part_kwargs["no_alerts"] = no_alerts

                # apply proper part_kwargs
                part.save(**part_kwargs)

            # packageversions need special handling
            self.save_packageversions()

            self.clean_affects()
            self.clean_affects_cvss_scores()
            # comments cannot be deleted in Bugzilla
            # history cannot be deleted in Bugzilla
            self.clean_acknowledgments()
            self.clean_references()
            self.clean_cvss_scores()

            # no automatic timestamps and validation exceptions
            # se explanation above for more details
            self.flaw.save(
                auto_timestamps=False,
                no_alerts=no_alerts,
                raise_validation_error=False,
            )


class FlawConvertor(BugzillaGroupsConvertorMixin):
    """
    Bugzilla flaw bug to OSIDB flaw model convertor
    this class is to performs the transformation only
    it takes the fetched but unprocessed backend models
    and provides all the model pieces to be saved
    """

    class FlawConvertorException(NonRecoverableBZImportException):
        """flaw bug to flaw model specific errors"""

    _flaws = None
    _errors = None

    @property
    def flaws(self):
        """
        get all flaws with eventual parsing
        the resulting flaws are not yet final flaws
        but FlawSaver objects with all pieces to be saved
        """
        if self._flaws is None:
            self._flaws = self.bug2flaws()
        return self._flaws

    @property
    def errors(self):
        """check and get parsing errors"""
        if self._errors is None:
            self._flaws = self.bug2flaws()
        # while parsing multiple CVEs from a single Bugzilla bug
        # we may encounter the exact same error multiple times
        # which would be an unnecessary duplicite information
        return list(set(self._errors))

    def record_errors(self, errors):
        """record new error(s)"""
        if self._errors is None:
            self._errors = []

        if isinstance(errors, list):
            self._errors.extend(errors)

        elif isinstance(errors, str):
            self._errors.append(errors)

        elif isinstance(errors, Exception):
            self._errors.append(str(errors))

    ###############
    # SOURCE DATA #
    ###############

    _flaw_bug = None
    _flaw_comments = None
    _task_bug = None

    def __init__(
        self,
        flaw_bug,
        flaw_comments,
        task_bug,
    ):
        """init source data"""
        self._flaw_bug = flaw_bug
        self._flaw_comments = flaw_comments
        self._task_bug = task_bug
        # set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

    @property
    def bug(self):
        """
        generic bug used in mixin context means flaw bug here
        """
        return self.flaw_bug

    @property
    def flaw_bug(self):
        """check and get flaw bug"""
        if self._flaw_bug is None:
            raise self.FlawConvertorException("source data not set")
        return self._flaw_bug

    @property
    def flaw_comments(self):
        """check and get flaw comments"""
        if self._flaw_comments is None:
            raise self.FlawConvertorException("source data not set")
        return self._flaw_comments

    @property
    def task_bug(self):
        """get task bug"""
        # there are flaws without task
        return self._task_bug

    #########################
    # CVE COMMON PROPERTIES #
    #########################

    # shared accross multiple evenual CVEs

    @property
    def alias(self):
        """Bugzilla alias array"""
        return self.flaw_bug["alias"]

    @property
    def bz_id(self):
        """Bugzilla ID"""
        return self.flaw_bug["id"]

    @cached_property
    def flags(self):
        """list of Bugzilla flags"""
        if "flags" not in self.flaw_bug:
            return []

        return [flag for flag in self.flaw_bug["flags"] if isinstance(flag, dict)]

    @cached_property
    def major_incident_state(self):
        """
        A Major Incident state created from hightouch and hightouch-lite flags.
        """
        # Default values
        hightouch = ""
        hightouch_lite = ""

        # Sets values from Bugzilla
        for flag in self.flags:
            if flag["name"] == "hightouch":
                hightouch = flag["status"]
            if flag["name"] == "hightouch-lite":
                hightouch_lite = flag["status"]

        valid_pairs = {
            ("", ""): Flaw.FlawMajorIncident.NOVALUE,
            ("?", "?"): Flaw.FlawMajorIncident.REQUESTED,
            ("?", ""): Flaw.FlawMajorIncident.REQUESTED,
            ("", "?"): Flaw.FlawMajorIncident.REQUESTED,
            ("-", "-"): Flaw.FlawMajorIncident.REJECTED,
            ("-", ""): Flaw.FlawMajorIncident.REJECTED,
            ("", "-"): Flaw.FlawMajorIncident.REJECTED,
            ("+", ""): Flaw.FlawMajorIncident.APPROVED,
            ("+", "-"): Flaw.FlawMajorIncident.APPROVED,
            ("", "+"): Flaw.FlawMajorIncident.CISA_APPROVED,
            ("-", "+"): Flaw.FlawMajorIncident.CISA_APPROVED,
        }
        flags_from_bz = (hightouch, hightouch_lite)

        return valid_pairs.get(flags_from_bz, Flaw.FlawMajorIncident.INVALID)

    @cached_property
    def major_incident_start_dt(self):
        """
        If the flaw is an approved major incident, the start date is assumed to be
        the date when the hightouch/hightouch-lite flag was created.
        """
        if self.major_incident_state in {
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
        }:
            # Get the date of the first "+" flag we find
            for flag in self.flags:
                if (
                    flag["name"] in {"hightouch", "hightouch-lite"}
                    and flag["status"] == "+"
                ):
                    return flag["creation_date"]

    @cached_property
    def requires_cve_description(self):
        """
        A requires_cve_description state created from the requires_doc_text flag.
        """
        # Default values
        status = ""
        setter = ""

        # Sets values from Bugzilla
        for flag in self.flags:
            if flag["name"] == "requires_doc_text":
                setter = flag["setter"]
                status = flag["status"]

        # this combination is set automatically by BZ when Doc Text is added
        if setter == "bugzilla@redhat.com" and status == "+":
            return Flaw.FlawRequiresCVEDescription.REQUESTED

        pairs = {
            "": Flaw.FlawRequiresCVEDescription.NOVALUE,
            "-": Flaw.FlawRequiresCVEDescription.REJECTED,
            "?": Flaw.FlawRequiresCVEDescription.REQUESTED,
            "+": Flaw.FlawRequiresCVEDescription.APPROVED,
        }

        return pairs.get(status)

    @cached_property
    def nist_cvss_validation(self):
        """
        Set Flaw field nist_cvss_validation from bugzilla flag nist_cvss_validation.
        """
        flag_value = ""
        for flag in self.flags:
            if flag["name"] == "nist_cvss_validation":
                flag_value = flag["status"]

        mapping = {
            "": Flaw.FlawNistCvssValidation.NOVALUE,
            "?": Flaw.FlawNistCvssValidation.REQUESTED,
            "+": Flaw.FlawNistCvssValidation.APPROVED,
            "-": Flaw.FlawNistCvssValidation.REJECTED,
        }

        return mapping.get(flag_value)

    @cached_property
    def package_versions(self):
        """parse fixed_in to package versions"""
        fixed_in = self.flaw_bug["fixed_in"]
        fixed_in_values = defaultdict(list)
        if not fixed_in:
            return fixed_in_values

        tokenized = fixed_in.split(",")
        for token in tokenized:
            token = token.strip()
            token_items = token.split(" ", 1)
            if len(token_items) == 1:
                # fixed_in version can be split with ' ', or '-'
                token_items = token.rsplit("-", 1)
                if len(token_items) == 1:
                    self.record_errors("no version in fixed_in")
                    continue
                fixed_in_values[token_items[0]].append(token_items[1])
            else:
                fixed_in_values[token_items[0]].append(token_items[1])
        return fixed_in_values

    @cached_property
    def srtnotes(self) -> dict:
        """
        Bugzilla SRT notes field
        return JSON representation or empty dict if empty or invalid
        """
        try:
            return parse_cf_srtnotes(self.flaw_bug["cf_srtnotes"])
        except Exception as e:
            self.record_errors(f"Invalid or empty SRT notes: {str(e)}")
            return {}

    @property
    def task_owner(self):
        """Bugzilla assignee of given task bug"""
        return self.task_bug["assigned_to"] if self.task_bug else None

    ###########################
    # CVE SPECIFIC PROPERTIES #
    ###########################

    @cached_property
    def cve_ids(self):
        """
        list of CVEs
        these are stored as Bugzilla aliases
        uniqueness is guaranteed
        """
        return filter_cves(self.alias)

    def get_meta_attr(self, cve_id):
        """get meta attributes"""
        meta_attr = self.srtnotes
        meta_attr["bz_id"] = self.bz_id
        meta_attr["alias"] = self.alias
        meta_attr["depends_on"] = self.depends_on
        meta_attr["related_cves"] = [c for c in self.cve_ids if c != cve_id]
        meta_attr["bz_summary"] = self.flaw_bug["summary"]
        meta_attr["last_change_time"] = self.flaw_bug["last_change_time"]
        meta_attr["last_imported_dt"] = timezone.now()
        meta_attr["acl_labels"] = self.groups
        meta_attr["task_owner"] = self.task_owner
        meta_attr["cc"] = self.flaw_bug.get("cc", [])
        meta_attr["groups"] = self.flaw_bug.get("groups", [])
        meta_attr["keywords"] = self.flaw_bug.get("keywords", [])
        # store the original SRT notes string as meta attributes tamper the JSON
        meta_attr["original_srtnotes"] = self.flaw_bug["cf_srtnotes"]
        meta_attr["status"] = self.flaw_bug["status"]
        meta_attr["resolution"] = self.flaw_bug["resolution"]
        meta_attr["fixed_in"] = self.flaw_bug["fixed_in"]
        meta_attr["bz_component"] = self.flaw_bug["component"]
        meta_attr["external_ids"] = self.srtnotes.get("external_ids", [])

        def dump(meta_attr):
            """
            json.dump dict values when appropriate
            """
            meta_attr_dump = {}
            for key, value in meta_attr.items():
                if not isinstance(
                    value, timezone.datetime  # datetime is not JSON serializable
                ) and not isinstance(
                    value, str  # the string values result in extra quotes
                ):
                    value = json.dumps(value)

                meta_attr_dump[key] = value
            return meta_attr_dump

        # process all the meta attributes through json.dumps
        # to set them the correct quotes for later json.loads
        return dump(meta_attr)

    ##############################
    # TRACKER RELATED PROPERTIES #
    ##############################

    @property
    def depends_on(self):
        """
        Bugzilla depends_on array
        contains potential Bugzilla trackers
        """
        return self.flaw_bug["depends_on"]

    ########################
    # DJANGO MODEL GETTERS #
    ########################

    def get_affects(self, flaw):
        """get list of Affect and AffectCVSS Django models"""
        affects = []
        affects_cvss_scores = []

        for affect_json in self.srtnotes.get("affects", []):

            # PS module is identifier so the fixup must be applied before the lookup
            ps_module = AffectFixer.fixplace_ps_module(affect_json.get("ps_module"))
            ps_component = affect_json.get("ps_component")
            affect_json["acl_labels"] = self.groups

            affect_obj = Affect.objects.create_affect(
                flaw,
                ps_module,
                ps_component,
                meta_attr=affect_json,
                acl_read=self.acl_read,
                acl_write=self.acl_write,
                # affects are part of Bugzilla flaw metadata
                # and their timestamps are complicated to parse
                # so let us simply duplicate the flaw ones
                created_dt=self.flaw_bug["creation_time"],
                updated_dt=self.flaw_bug["last_change_time"],
            )

            affect_obj, errors = AffectFixer(
                affect_obj, affect_json, ps_module, ps_component
            ).fix()
            self.record_errors(errors)
            affects.append(affect_obj)

            # AffectCVSS is created here because it requires an affect object
            for cvss_pair in [
                ("cvss2", AffectCVSS.CVSSVersion.VERSION2),
                ("cvss3", AffectCVSS.CVSSVersion.VERSION3),
                ("cvss4", AffectCVSS.CVSSVersion.VERSION4),
            ]:
                cvss, version = cvss_pair

                if affect_json.get(cvss) and "/" in affect_json[cvss]:
                    cvss_obj = AffectCVSS.objects.create_cvss(
                        affect_obj,
                        AffectCVSS.CVSSIssuer.REDHAT,
                        version,
                        vector=affect_json[cvss].split("/", 1)[1],
                        acl_read=self.acl_read,
                        acl_write=self.acl_write,
                        created_dt=self.flaw_bug["creation_time"],
                        updated_dt=self.flaw_bug["last_change_time"],
                    )
                    affects_cvss_scores.append(cvss_obj)

        # fixup might result in duplicate affects (rhel-5.0 and rhel-5.1 fixed to rhel-5)
        # so we need to deduplicate them - simply choosing one of the duplicates by random
        #
        # this has consequences when the duplicate affects have different affectednes etc.
        # which is price for fixing the PS module which is prior - these are old data anyway
        affects = list({a.ps_module + a.ps_component: a for a in affects}.values())

        return [affects, affects_cvss_scores]

    def get_comments(self, flaw):
        """
        Get new and in-place updated FlawComment Django models for saving with the Flaw.
        - Comments are iterated from number zero, those with identical text between
          OSIDB & BZ are updated in-place, as long as a diverging comment has not been
          encountered (then the update stops, after that point, pairing the comments
          would be ambiguous and error-prone).
        - If no diverging comment has been encountered, new comments existing only in BZ
          are created as new FlawComment models.
        - If a diverging comment has been encountered, the sync stops there, the rest of
          the BZ comments (with equal and higher "count") are ignored, and for the rest of
          OSIDB comments only ACLs are updated.
        """

        # Historically, OSIDB has always allowed comment numbers to have holes,
        # e.g. 0, 3, 5, 6, 7. This can be caused by the BZ user not having permissions
        # to the given comments. It is beside the point whether we should allow that
        # or not because this has always been the state of the OSIDB data as of 2024-07
        # when get_comments is heavily changed.
        # Moreover, a large number of tests depend on that and there's no resources
        # to fix those tests as of 2024-07.
        dict_database = {c.order: c for c in FlawComment.objects.filter(flaw=flaw)}
        dict_bugzilla = {c["count"]: c for c in self.flaw_comments}

        max_database = max(dict_database.keys() or [-1])
        max_bugzilla = max(dict_bugzilla.keys() or [-1])

        max_common = min([max_database, max_bugzilla])

        comments_to_save = []

        for i in range(max([max_database, max_bugzilla]) + 1):
            if i <= max_common:
                db_comment = dict_database.get(i)
                bz_comment = dict_bugzilla.get(i)

                if db_comment is None and bz_comment is None:
                    # Both contain the same hole, assume no history bifurcation at this point.
                    pass

                elif db_comment is not None and db_comment.text == bz_comment.get(
                    "text"
                ):
                    # It may happen in some situation that we run out of the DB comments...
                    # Otherwise identical comments both in OSIDB and BZ, just update OSIDB from BZ.

                    db_comment.external_system_id = bz_comment["id"]
                    # Since it is IN BZ, and we're getting it FROM BZ, there's no point to
                    # sending it back TO BZ, so we can say it's already synced to BZ.
                    db_comment.synced_to_bz = True
                    db_comment.created_dt = timezone.datetime.strptime(
                        bz_comment["creation_time"], BZ_DT_FMT
                    )
                    # comment modifications are complicated to parse
                    # so let us simply duplicate the creation ones
                    db_comment.updated_dt = timezone.datetime.strptime(
                        bz_comment["creation_time"], BZ_DT_FMT
                    )
                    db_comment.creator = bz_comment["creator"]
                    db_comment.is_private = bz_comment.get("is_private", False)
                    db_comment.acl_read = self.acl_read
                    db_comment.acl_write = self.acl_write
                    comments_to_save.append(db_comment)
                else:
                    # Reached the end of comments created while bzimport was active.
                    # It means that bzimport has been disabled and the histories diverged.
                    # Send the rest of the DB version comments for processing as is.
                    for j in range(i, max_database + 1):
                        db_comment = dict_database.get(j)
                        if db_comment is not None:
                            db_comment.acl_read = self.acl_read
                            db_comment.acl_write = self.acl_write
                            comments_to_save.append(db_comment)
                    # And stop, since the rest of the BZ comments is irrelevant now.
                    # Those are from a time after disabling bzimport and letting the
                    # histories diverge.
                    break
            else:
                # Reaching this means that histories didn't diverge yet (just one side is incomplete).
                if i > max_bugzilla:
                    # New comment(s) added in OSIDB without syncing to bugzilla
                    # (maybe bbsync failed, maybe bbsync was disabled).
                    pass
                else:  # i > max_database
                    # This means bzimport is either still active or that it was disabled and new
                    # comments weren't made in OSIDB yet since disabling.
                    bz_comment = dict_bugzilla.get(i)
                    if bz_comment is not None:
                        new_comment = FlawComment(
                            flaw=flaw,
                            external_system_id=bz_comment["id"],
                            # Since it is IN BZ, and we're getting it FROM BZ, there's no point to
                            # sending it back TO BZ, so we can say it's already synced to BZ.
                            synced_to_bz=True,
                            created_dt=timezone.datetime.strptime(
                                bz_comment["creation_time"], BZ_DT_FMT
                            ),
                            # comment modifications are complicated to parse
                            # so let us simply duplicate the creation ones
                            updated_dt=timezone.datetime.strptime(
                                bz_comment["creation_time"], BZ_DT_FMT
                            ),
                            order=bz_comment["count"],
                            text=bz_comment["text"],
                            creator=bz_comment["creator"],
                            is_private=bz_comment.get("is_private", False),
                            acl_read=self.acl_read,
                            acl_write=self.acl_write,
                        )
                        comments_to_save.append(new_comment)
        return comments_to_save

    def get_flaw(self, cve_id, full_match=False):
        """get Flaw Django model"""
        flaw = Flaw.objects.create_flaw(
            bz_id=self.bz_id,
            full_match=full_match,
            cve_id=cve_id,
            meta_attr=self.get_meta_attr(cve_id),
            major_incident_state=self.major_incident_state,
            major_incident_start_dt=self.major_incident_start_dt,
            requires_cve_description=self.requires_cve_description,
            nist_cvss_validation=self.nist_cvss_validation,
            created_dt=self.flaw_bug["creation_time"],
            updated_dt=self.flaw_bug["last_change_time"],
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )

        flaw, errors = FlawFixer(flaw, self.flaw_bug, self.srtnotes).fix()
        self.record_errors(errors)
        return flaw

    def get_acknowledgments(self, flaw):
        """get a list of FlawAcknowledgment Django models"""
        acknowledgments = []

        for acknowledgment_json in self.srtnotes.get("acknowledgments", []):
            affiliation = acknowledgment_json.get("affiliation") or ""
            from_upstream = acknowledgment_json.get("from_upstream")
            name = acknowledgment_json.get("name")

            acknowledgment_json["acl_labels"] = self.groups

            acknowledgment_obj = FlawAcknowledgment.objects.create_flawacknowledgment(
                flaw,
                name,
                affiliation,
                from_upstream=from_upstream,
                acl_read=self.acl_read,
                acl_write=self.acl_write,
                created_dt=self.flaw_bug["creation_time"],
                updated_dt=self.flaw_bug["last_change_time"],
            )
            acknowledgments.append(acknowledgment_obj)

        return acknowledgments

    def get_references(self, flaw):
        """get a list of FlawReferences Django models"""
        references = []

        for reference_json in self.srtnotes.get("references", []):
            _type = reference_json.get("type")
            if _type == "vuln_response":
                _type = FlawReference.FlawReferenceType.ARTICLE
            elif _type == "external":
                _type = FlawReference.FlawReferenceType.EXTERNAL
            elif _type == "source":
                _type = FlawReference.FlawReferenceType.SOURCE

            url = reference_json.get("url")
            reference_json["acl_labels"] = self.groups

            reference_obj = FlawReference.objects.create_flawreference(
                flaw,
                url,
                type=_type,
                acl_read=self.acl_read,
                acl_write=self.acl_write,
                created_dt=self.flaw_bug["creation_time"],
                updated_dt=self.flaw_bug["last_change_time"],
            )
            references.append(reference_obj)

        return references

    def get_flaw_cvss(self, flaw):
        """get a list of FlawCVSS Django models"""
        all_cvss = []

        for cvss_pair in [
            ("cvss2", FlawCVSS.CVSSVersion.VERSION2),
            ("cvss3", FlawCVSS.CVSSVersion.VERSION3),
            ("cvss4", FlawCVSS.CVSSVersion.VERSION4),
        ]:
            cvss, version = cvss_pair

            if self.srtnotes.get(cvss) and "/" in self.srtnotes[cvss]:
                comment = {}
                if cvss == "cvss3" and self.srtnotes.get("cvss3_comment"):
                    comment["comment"] = self.srtnotes["cvss3_comment"]
                if cvss == "cvss4" and self.srtnotes.get("cvss4_comment"):
                    comment["comment"] = self.srtnotes["cvss4_comment"]

                cvss_obj = FlawCVSS.objects.create_cvss(
                    flaw,
                    FlawCVSS.CVSSIssuer.REDHAT,
                    version,
                    vector=self.srtnotes[cvss].split("/", 1)[1],
                    acl_read=self.acl_read,
                    acl_write=self.acl_write,
                    created_dt=self.flaw_bug["creation_time"],
                    updated_dt=self.flaw_bug["last_change_time"],
                    **comment,
                )
                all_cvss.append(cvss_obj)

        return all_cvss

    ###########################
    # BUG TO FLAWS PROCESSING #
    ###########################

    def bug2flaws(self):
        """
        perform flaw bug to flaw models conversion

        the tricky part here is the possible CVE change as we do not want to change
        the UUID willy-nilly but rather consider it as CVE-only change when possible

        the exception is the case of multi-CVE flaw where there are no
        guarantees whenever the mapping is not completely unambiguous
        """
        logger.debug(f"{self.__class__}: processing flaw bug {self.bz_id}")

        # there might be between zero and infinity existing flaws with this BZ ID
        existing_flaws = Flaw.objects.filter(meta_attr__bz_id=self.bz_id)

        #################
        # CVE-less flaw #
        #################

        if not self.cve_ids:
            logger.debug(f"{self.__class__}: processing CVE-less flaw")

            # remove all flaws with this BZ ID in case there were multiple CVE flaws before
            # and got removed as matching them to a single CVE-less flaw would be ambiguous
            if existing_flaws.count() > 1:
                existing_flaws.delete()

            flaw = self.get_flaw(cve_id=None)
            return [
                FlawSaver(
                    flaw,
                    self.get_affects(flaw),
                    self.get_comments(flaw),
                    self.get_acknowledgments(flaw),
                    self.get_references(flaw),
                    self.get_flaw_cvss(flaw),
                    self.package_versions,
                )
            ]

        ###################
        # single-CVE flaw #
        ###################

        if len(self.cve_ids) == 1:
            logger.debug(f"{self.__class__}: processing {self.cve_ids[0]}")

            # if there was multiple flaws but now it is only one
            # we remove all the previous as the mapping is ambiguous
            # except the CVE itself where the mapping is straightforward
            if existing_flaws.count() > 1:
                existing_flaws.exclude(cve_id=self.cve_ids[0]).delete()

            flaw = self.get_flaw(self.cve_ids[0])
            return [
                FlawSaver(
                    flaw,
                    self.get_affects(flaw),
                    self.get_comments(flaw),
                    self.get_acknowledgments(flaw),
                    self.get_references(flaw),
                    self.get_flaw_cvss(flaw),
                    self.package_versions,
                )
            ]

        ##################
        # multi-CVE flaw #
        ##################

        flaws = []

        # as we have multiple flaws now the mapping is always ambiguous
        # except the exact CVE match where the mapping is straightforward
        existing_flaws.exclude(cve_id__in=self.cve_ids).delete()

        # in the past there was possible to have multiple CVEs for a flaw
        # but it is no more desired and we create a flaw for every CVE
        for cve_id in self.cve_ids:
            logger.debug(f"{self.__class__}: processing {cve_id}")

            # for multi-CVE flaw we have to perform
            # the full match to make it unambiguous
            flaw = self.get_flaw(cve_id, full_match=True)
            flaws.append(
                FlawSaver(
                    flaw,
                    self.get_affects(flaw),
                    self.get_comments(flaw),
                    self.get_acknowledgments(flaw),
                    self.get_references(flaw),
                    self.get_flaw_cvss(flaw),
                    self.package_versions,
                )
            )

        return flaws
