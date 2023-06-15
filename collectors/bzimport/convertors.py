"""
transform Bugzilla flaw bug into OSIDB flaw model
"""
import json
import logging
import re
import uuid
from collections import defaultdict
from functools import cached_property

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.timezone import make_aware

from collectors.bzimport.srtnotes_parser import parse_cf_srtnotes
from collectors.jiraffe.convertors import JiraTrackerConvertor, TrackerConvertor
from osidb.core import generate_acls, set_user_acls
from osidb.mixins import AlertMixin, TrackingMixin
from osidb.models import (
    Affect,
    CVEv5PackageVersions,
    CVEv5Version,
    Flaw,
    FlawComment,
    FlawHistory,
    FlawMeta,
    FlawReference,
    FlawType,
    Tracker,
    VersionStatus,
)
from osidb.validators import CVE_RE_STR, restrict_regex

from ..utils import (
    tracker_parse_update_stream_component,
    tracker_summary2module_component,
)
from .constants import BZ_DT_FMT, BZ_DT_FMT_HISTORY, BZ_ENABLE_IMPORT_EMBARGOED
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
        if "security" not in self.bug.get("groups", []):
            return settings.PUBLIC_READ_GROUPS

        if not BZ_ENABLE_IMPORT_EMBARGOED:
            raise self.FlawConvertorException(
                f"Bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
            )

        return [settings.EMBARGO_READ_GROUP]

    @property
    def groups_write(self):
        """
        appropriate write LDAP groups
        """
        if "security" not in self.bug.get("groups", []):
            return [settings.PUBLIC_WRITE_GROUP]

        if not BZ_ENABLE_IMPORT_EMBARGOED:
            raise self.FlawConvertorException(
                f"Bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
            )

        return [settings.EMBARGO_WRITE_GROUP]

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
        return self.tracker_data["id"]

    @property
    def bug(self):
        """
        generic bug used in mixin context means tracker data here
        """
        return self.tracker_data

    def _normalize(self) -> dict:
        """
        raw data normalization
        """
        ps_module, ps_component = tracker_summary2module_component(self._raw["summary"])

        return {
            "external_system_id": self._raw["id"],
            "owner": self._raw["assigned_to"],
            "qe_owner": self._raw["qa_contact"],
            "ps_module": ps_module,
            "ps_component": ps_component,
            "ps_update_stream": tracker_parse_update_stream_component(
                self._raw["summary"]
            )[0],
            "status": self._raw["status"],
            "resolution": self._raw["resolution"],
            "created_dt": self._raw["creation_time"],
            "updated_dt": self._raw["last_change_time"],
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
        history,
        meta,
        references,
        trackers,
        package_versions,
    ):
        self.flaw = flaw
        self.affects = affects
        self.comments = comments
        self.history = history
        self.meta = meta
        self.references = references
        self.trackers = trackers
        self.package_versions = package_versions

    def __str__(self):
        return f"FlawSaver {self.flaw.meta_attr['bz_id']}:{self.flaw.cve_id}"

    @property
    def all_parts(self):
        """get all parts in save-able order"""
        return (
            [self.flaw]
            + self.affects
            + self.comments
            + self.history
            + self.meta
            + self.references
            + self.trackers
        )

    def save_packageversions(self):
        """save packageversions and versions and remove the obsoleted"""
        for package, versions in self.package_versions.items():
            package_versions, _ = CVEv5PackageVersions.objects.get_or_create(
                flaw=self.flaw,
                package=package,
            )
            # remove all the existing versions
            for old_version in package_versions.versions.all():
                package_versions.versions.remove(old_version)
                old_version.delete()
            # replace them
            for version in versions:
                version = CVEv5Version.objects.create(
                    version=version,
                    status=VersionStatus.UNAFFECTED,
                )
                package_versions.versions.add(version)
        # remove obsoleted packageversions
        CVEv5PackageVersions.objects.filter(
            flaw=self.flaw,
        ).exclude(package__in=self.package_versions.keys()).delete()
        # remove obsoleted versions
        CVEv5Version.objects.filter(packageversions__isnull=True).delete()

    def clean_affects(self):
        """clean obsoleted affects"""
        # TODO: potentially optimize like clean_meta ?
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

    def clean_meta(self):
        """
        Removes FlawMeta objects that no longer exist upstream.

        This is achieved by comparing the key attributes of the FlawMeta objects:
            * flaw -- the flaw for which the meta object applies
            * type -- the type of flaw metadata
            * meta_attr -- the contents of the flawmeta

        If none of the existing FlawMeta objects match these three attributes with
        any of the upstream meta objects, then it means that it was removed upstream
        and should be removed in OSIDB too.

        E.g.

        OSIDB contains:
            FlawMeta(
                flaw=<CVE-2022-1234>
                type=<ACKNOWLEDGMENT>
                meta_attr={
                    "name": "Adrin Tres"
                }
            )

        And upstream generates:
            FlawMeta(
                flaw=<CVE-2022-1234>
                type=<ACKNOWLEDGMENT>
                meta_attr={
                    "name": "Adrian Torres"
                }
            )

        It's clear that at some point a typo was made, the existing Acknowledgment
        meta removed and replaced with the version without a typo, in that case OSIDB
        should keep in sync with upstream.

        The comparison is leveraged using the FlawMetaManager.create_flawmeta method:

            When the convertor creates FlawMeta objects from the upstream data, it will
            use the create_flawmeta method which will either retrieve an existing FlawMeta
            or create a new one, but never create a duplicate one. This guarantees that
            the equality operator (==) is safe to use in this case.
        """
        # NOTE: maybe we should simply always recreate all from upstream
        old = set(self.flaw.meta.all())
        new = set(self.meta)
        to_delete = list(old - new)
        for meta in to_delete:
            meta.delete()

    def clean_references(self):
        """clean obsoleted flaw references"""
        old_references = set(self.flaw.references.all())
        new_references = set(self.references)

        to_delete = list(old_references - new_references)
        for reference in to_delete:
            reference.delete()

    def clean_trackers(self):
        """clean obsoleted affect-tracker links"""
        tracker_ids = [t.external_system_id for t in self.trackers]
        for affect in self.affects:
            obsoleted_trackers = affect.trackers.exclude(
                external_system_id__in=tracker_ids
            )
            for tracker in obsoleted_trackers:
                affect.trackers.remove(tracker)

    def link_trackers(self):
        """link trackers to affects"""
        for tracker in self.trackers:
            affect = self.flaw.get_affect(
                tracker.meta_attr["ps_module"],
                tracker.meta_attr["ps_component"],
            )
            # related tracker without corresponding affect is suspicious
            # it means some data corruption or invalid manipulation
            # let us leave those unlinked for now
            if not affect:
                logger.warning(
                    f"Failed to match tracker {tracker.external_system_id} "
                    f"with flaw {self.flaw.meta_attr['bz_id']}:{self.flaw.cve_id} - there is no affect "
                    f"{tracker.meta_attr['ps_module']}:{tracker.meta_attr['ps_component']}"
                )
                # TODO store error
                continue

            tracker.affects.add(affect)

    def save(self):
        """save flaw with its context to DB"""
        # wrap this in an atomic transaction so that
        # we don't query this flaw during the process
        with transaction.atomic():
            for part in self.all_parts:
                kwargs = {}

                # we want to store the original timestamps
                # so we turn off assigning the automatic ones
                if isinstance(part, TrackingMixin):
                    kwargs["auto_timestamps"] = False

                # we want to store all the data fetched by the collector
                # so we suppress the exception raising in favor of alerts
                if isinstance(part, AlertMixin):
                    kwargs["raise_validation_error"] = False

                # apply proper kwargs
                part.save(**kwargs)

            # packageversions need special handling
            self.save_packageversions()

            self.clean_affects()
            # comments cannot be deleted in Bugzilla
            # history cannot be deleted in Bugzilla
            self.clean_meta()
            self.clean_references()
            self.clean_trackers()

            self.link_trackers()

            # when all related entities are available we also need
            # to classify the created flaw however disable saving
            # flaw in the classification adjustment and call the
            # save afterwards since it will be only saved when
            # the classification changes and thus some flaw
            # changes done before may be lost
            self.flaw.adjust_classification(save=False)
            # no automatic timestamps and validation exceptions
            # se explanation above for more details
            self.flaw.save(
                auto_timestamps=False,
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
    _flaw_history = None
    _task_bug = None
    _tracker_bugs = None
    _tracker_jiras = None

    def __init__(
        self,
        flaw_bug,
        flaw_comments,
        flaw_history,
        task_bug,
        tracker_bugs,
        tracker_jiras,
    ):
        """init source data"""
        self._flaw_bug = flaw_bug
        self._flaw_comments = flaw_comments
        self._flaw_history = flaw_history
        self._task_bug = task_bug
        self._tracker_bugs = tracker_bugs
        self._tracker_jiras = tracker_jiras
        # set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(
            settings.PUBLIC_READ_GROUPS
            + [
                settings.PUBLIC_WRITE_GROUP,
                settings.EMBARGO_READ_GROUP,
                settings.EMBARGO_WRITE_GROUP,
            ]
        )

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
    def flaw_history(self):
        """check and get flaw history"""
        if self._flaw_history is None:
            raise self.FlawConvertorException("source data not set")
        return self._flaw_history

    @property
    def task_bug(self):
        """get task bug"""
        # there are flaws without task
        return self._task_bug

    @property
    def tracker_bugs(self):
        """get list of tracker bugs"""
        if self._tracker_bugs is None:
            raise self.FlawConvertorException("source data not set")
        return self._tracker_bugs

    @property
    def tracker_jiras(self):
        """get list of tracker Jira issues"""
        if self._tracker_jiras is None:
            raise self.FlawConvertorException("source data not set")
        return self._tracker_jiras

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

    @staticmethod
    def filter_cves(strings):
        """CVE strings filter helper"""
        return [s for s in strings if re.match(restrict_regex(CVE_RE_STR), s)]

    @cached_property
    def cve_ids(self):
        """
        list of CVEs
        these are stored as Bugzilla aliases
        uniqueness is guaranteed
        """
        return self.filter_cves(self.alias)

    def get_meta_attr(self, cve_id):
        """get meta attributes"""
        meta_attr = self.srtnotes
        meta_attr["bz_id"] = self.bz_id
        meta_attr["alias"] = self.alias
        meta_attr["depends_on"] = self.depends_on
        meta_attr["related_cves"] = [c for c in self.cve_ids if c != cve_id]
        meta_attr["last_change_time"] = self.flaw_bug["last_change_time"]
        meta_attr["last_imported_dt"] = timezone.now()
        meta_attr["acl_labels"] = self.groups
        meta_attr["task_owner"] = self.task_owner
        meta_attr["cc"] = json.dumps(self.flaw_bug.get("cc", []))
        meta_attr["groups"] = json.dumps(self.flaw_bug.get("groups", []))
        meta_attr["keywords"] = json.dumps(self.flaw_bug.get("keywords", []))
        # store the original SRT notes string as meta attributes tamper the JSON
        meta_attr["original_srtnotes"] = self.flaw_bug["cf_srtnotes"]
        meta_attr["status"] = self.flaw_bug["status"]
        meta_attr["resolution"] = self.flaw_bug["resolution"]
        return meta_attr

    ##############################
    # TRACKER RELATED PROPERTIES #
    ##############################

    @property
    def bz_trackers(self):
        """
        Bugzilla trackers
        with product definitions context
        """
        return [BugzillaTrackerConvertor(tracker) for tracker in self.tracker_bugs]

    @property
    def depends_on(self):
        """
        Bugzilla depends_on array
        contains potential Bugzilla trackers
        """
        return self.flaw_bug["depends_on"]

    @property
    def jira_trackers(self):
        """
        Jira trackers
        with product definitions context
        """
        return [JiraTrackerConvertor(tracker) for tracker in self.tracker_jiras]

    ########################
    # DJANGO MODEL GETTERS #
    ########################

    def get_affects(self, flaw):
        """get list of Affect Django models"""
        affects = []
        for affect_json in self.srtnotes.get("affects", []):

            # PS module is identifier so the fixup must be applied before the lookup
            ps_module = AffectFixer.fixplace_ps_module(affect_json.get("ps_module"))
            ps_component = affect_json.get("ps_component")
            affect_json["acl_labels"] = self.groups

            affect_obj = Affect.objects.create_affect(
                flaw,
                ps_module,
                ps_component,
                type=Affect.AffectType.DEFAULT,
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

        # fixup might result in duplicate affects (rhel-5.0 and rhel-5.1 fixed to rhel-5)
        # so we need to deduplicate them - simply choosing one of the duplicates by random
        #
        # this has consequences when the duplicate affects have different affectednes etc.
        # which is price for fixing the PS module which is prior - these are old data anyway
        return list({a.ps_module + a.ps_component: a for a in affects}.values())

    def get_comments(self, flaw):
        """get FlawComment Django models"""
        # Delete orphaned / temporary comments
        FlawComment.objects.pending().filter(flaw=flaw).delete()
        return [
            FlawComment.objects.create_flawcomment(
                flaw,
                comment["id"],
                comment,
                created_dt=timezone.datetime.strptime(
                    comment["creation_time"], BZ_DT_FMT
                ),
                # comment modifications are complicated to parse
                # so let us simply duplicate the creation ones
                updated_dt=timezone.datetime.strptime(
                    comment["creation_time"], BZ_DT_FMT
                ),
                order=comment["count"],
                text=comment["text"],
                type=FlawComment.FlawCommentType.BUGZILLA,
                acl_read=self.acl_read,
                acl_write=self.acl_write,
            )
            for comment in self.flaw_comments
        ]

    def get_flaw(self, cve_id, full_match=False):
        """get Flaw Django model"""
        flaw = Flaw.objects.create_flaw(
            bz_id=self.bz_id,
            full_match=full_match,
            cve_id=cve_id,
            type=FlawType.VULNERABILITY,
            meta_attr=self.get_meta_attr(cve_id),
            created_dt=self.flaw_bug["creation_time"],
            updated_dt=self.flaw_bug["last_change_time"],
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )

        flaw, errors = FlawFixer(flaw, self.flaw_bug, self.srtnotes).fix()
        self.record_errors(errors)
        return flaw

    def get_history(self):
        """get list of FlawHistory Django models"""
        history = []

        try:
            removed = {}
            added = {}
            added_srtnotes = {}

            history_flaw_bug = self.flaw_bug.copy()
            history_srtnotes = self.srtnotes.copy()

            for item in reversed(self.flaw_history["bugs"][0]["history"]):

                for change in item["changes"]:
                    removed[change["field_name"]] = change["removed"]
                    added[change["field_name"]] = change["added"]

                if "cf_srtnotes" in removed:
                    history_srtnotes_string = removed["cf_srtnotes"]

                    if history_srtnotes_string:
                        try:
                            added_srtnotes = parse_cf_srtnotes(history_srtnotes_string)
                            history_srtnotes = added_srtnotes

                        except Exception as e:
                            # this is very frequent especially for the old flaws
                            # and there is no way to fix it - we cannot change history
                            # so we will not store this in the logs not to pollute them
                            error_msg = (
                                f"SRT notes history of flaw bug {self.bz_id} "
                                f"parsing exception: {str(e)}"
                            )
                            self.record_errors(error_msg)

                    history_flaw_bug.update(removed)

                meta_attr = history_srtnotes
                meta_attr["bz_id"] = self.bz_id
                meta_attr["alias"] = history_flaw_bug["alias"]
                meta_attr["acl_labels"] = self.groups

                flaw_history_record = FlawHistory(
                    pgh_created_at=make_aware(
                        timezone.datetime.strptime(item["when"], BZ_DT_FMT_HISTORY)
                    ),
                    pgh_label=item["who"],
                    type=FlawType.VULNERABILITY,
                    acl_read=self.acl_read,
                    acl_write=self.acl_write,
                    meta_attr=meta_attr,
                )
                cves = self.filter_cves(history_flaw_bug["alias"])
                if cves:
                    # we pick random CVE for historical records
                    # - mostly there will be either one or none
                    flaw_history_record.cve_id = cves[0]

                # history fixups errors are ignored
                flaw_history_record, _ = FlawFixer(
                    flaw_history_record, history_flaw_bug, history_srtnotes
                ).fix()
                history.append(flaw_history_record)

        except Exception as e:
            error_msg = f"History processing exception: {str(e)}"
            logger.exception(error_msg)
            self.record_errors(error_msg)

        return history

    def get_meta(self, flaw, meta_type, items):
        """get FlawMeta Django models"""
        return [
            # TODO I am not sure this way works also
            # for meta with multiple possible instances
            FlawMeta.objects.create_flawmeta(
                flaw=flaw,
                _type=meta_type,
                created_dt=self.flaw_bug["creation_time"],
                updated_dt=self.flaw_bug["last_change_time"],
                meta=item,
                acl_read=self.acl_read,
                acl_write=self.acl_write,
            )
            for item in items
        ]

    def get_references(self, flaw):
        """get a list of FlawReferences Django models"""
        references = []

        for reference_json in self.srtnotes.get("references", []):
            _type = reference_json.get("type")
            if _type == "vuln_response":
                _type = "ARTICLE"
            elif _type == "external":
                _type = "EXTERNAL"

            url = reference_json.get("url")
            reference_json["acl_labels"] = self.groups

            reference_obj = FlawReference.objects.create_flawreference(
                flaw,
                url,
                type=_type,
                meta_attr=reference_json,
                acl_read=self.acl_read,
                acl_write=self.acl_write,
                created_dt=self.flaw_bug["creation_time"],
                updated_dt=self.flaw_bug["last_change_time"],
            )
            references.append(reference_obj)

        return references

    def get_trackers(self):
        """
        get list of Tracker objects.

        process all related trackers in Bugzilla and Jira
        need to be later linked to the corresponding affects
        """
        all_trackers = self.bz_trackers + self.jira_trackers
        return [tracker.convert() for tracker in all_trackers]

    ###########################
    # BUG TO FLAWS PROCESSING #
    ###########################

    SRTNOTES_META = [
        ("acknowledgments", FlawMeta.FlawMetaType.ACKNOWLEDGMENT),
        ("exploits", FlawMeta.FlawMetaType.EXPLOIT),
        ("references", FlawMeta.FlawMetaType.REFERENCE),
        ("checklists", FlawMeta.FlawMetaType.CHECKLIST),
    ]
    FLAGS_META = {
        "hightouch": FlawMeta.FlawMetaType.MAJOR_INCIDENT,
        "hightouch-lite": FlawMeta.FlawMetaType.MAJOR_INCIDENT_LITE,
        "requires_doc_text": FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
        "nist_cvss_validation": FlawMeta.FlawMetaType.NIST_CVSS_VALIDATION,
        "needinfo": FlawMeta.FlawMetaType.NEED_INFO,
    }

    def get_all_meta(self, flaw):
        """process and create metadata with respect to a given flaw"""
        meta = []

        for meta_key, meta_type in self.SRTNOTES_META:
            if meta_key in self.srtnotes:
                meta.extend(
                    self.get_meta(
                        flaw,
                        meta_type,
                        self.srtnotes[meta_key],
                    )
                )

        flaw.is_major_incident = False

        for flag in self.flags:
            flag_name = flag["name"]
            if flag_name not in self.FLAGS_META:
                continue

            meta.extend(
                self.get_meta(
                    flaw,
                    self.FLAGS_META[flag_name],
                    [flag],
                )
            )

            if flag_name in ["hightouch", "hightouch-lite"] and flag["status"] in [
                "?",
                "+",
            ]:
                flaw.is_major_incident = True

        return meta

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
                    self.get_history(),
                    self.get_all_meta(flaw),
                    self.get_references(flaw),
                    self.get_trackers(),
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
                    self.get_history(),
                    self.get_all_meta(flaw),
                    self.get_references(flaw),
                    self.get_trackers(),
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
                    self.get_history(),
                    self.get_all_meta(flaw),
                    self.get_references(flaw),
                    self.get_trackers(),
                    self.package_versions,
                )
            )

        return flaws
