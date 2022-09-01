"""
transform Bugzilla flaw bug into OSIDB flaw model
"""
import logging
import re
from collections import defaultdict
from functools import cached_property

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.timezone import make_aware

from collectors.bzimport.srtnotes_parser import parse_cf_srtnotes
from collectors.jiraffe.core import get_field_attr
from osidb.core import generate_acls, set_user_acls
from osidb.mixins import TrackingMixin
from osidb.models import (
    Affect,
    CVEv5PackageVersions,
    CVEv5Version,
    Flaw,
    FlawComment,
    FlawHistory,
    FlawMeta,
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


class TrackerBugConvertor:
    """
    Bugzilla tracker bug to OSIDB tracker convertor.

    This class transforms raw data from a unified raw format into proper Tracker
    model records and saves them into the database.
    """

    def __init__(
        self,
        tracker_bug,
        _type: Tracker.TrackerType,
        acl_read: list[str] = None,
        acl_write: list[str] = None,
    ):
        self._raw = tracker_bug
        self.type = _type
        self._acl_read = acl_read
        self._acl_write = acl_write
        # important that this is last as it might require other fields on self
        self.tracker_bug = self._normalize()
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

    def _normalize(self) -> dict:
        if self.type == Tracker.TrackerType.BZ:
            return self._normalize_from_bz()
        return self._normalize_from_jira()

    def _normalize_from_bz(self) -> dict:
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

    def _normalize_from_jira(self) -> dict:
        ps_module, ps_component = tracker_summary2module_component(
            self._raw.fields.summary
        )

        return {
            "external_system_id": self._raw.key,
            "owner": get_field_attr(self._raw, "assignee", "displayName"),
            # QE Assignee corresponds to customfield_12316243
            # in RH Jira which is a field of schema type user
            "qe_owner": get_field_attr(
                self._raw, "customfield_12316243", "displayName"
            ),
            "ps_module": ps_module,
            "ps_component": ps_component,
            "ps_update_stream": tracker_parse_update_stream_component(
                self._raw.fields.summary
            )[0],
            "status": get_field_attr(self._raw, "status", "name"),
            "resolution": get_field_attr(self._raw, "resolution", "name"),
            "created_dt": self._raw.fields.created,
            "updated_dt": self._raw.fields.updated
            if self._raw.fields.updated
            else self._raw.fields.created,
        }

    @property
    def groups_read(self):
        """appropriate read LDAP groups"""
        if "security" not in self.tracker_bug.get("groups", []):
            return settings.PUBLIC_READ_GROUPS

        if not BZ_ENABLE_IMPORT_EMBARGOED:
            raise self.FlawBugConvertorException(
                f"Flaw bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
            )

        return [settings.EMBARGO_READ_GROUP]

    @property
    def groups_write(self):
        """appropriate write LDAP groups"""
        if "security" not in self.tracker_bug.get("groups", []):
            return [settings.PUBLIC_WRITE_GROUP]

        if not BZ_ENABLE_IMPORT_EMBARGOED:
            raise self.FlawBugConvertorException(
                f"Flaw bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
            )

        return [settings.EMBARGO_WRITE_GROUP]

    @cached_property
    def acl_read(self):
        """get read ACL based on read groups"""
        return self._acl_read or generate_acls(self.groups_read)

    @cached_property
    def acl_write(self):
        """get write ACL based on write groups"""
        return self._acl_write or generate_acls(self.groups_write)

    def _gen_tracker_object(self, affect) -> Tracker:
        # there maybe already existing tracker from the previous sync
        # if this is the periodic update however also when the flaw bug
        # has multiple CVEs the resulting flaws will share the trackers
        return Tracker.objects.create_tracker(
            affect=affect,
            _type=self.type,
            external_system_id=self.tracker_bug["external_system_id"],
            status=self.tracker_bug["status"],
            resolution=self.tracker_bug["resolution"],
            ps_update_stream=self.tracker_bug["ps_update_stream"],
            meta_attr=self.tracker_bug,
            created_dt=self.tracker_bug["created_dt"],
            updated_dt=self.tracker_bug["updated_dt"],
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )

    def convert(self, affect=None) -> Tracker:
        return self._gen_tracker_object(affect)


class FlawSaver:
    """
    FlawSaver is holder of the individual flaw parts provided by FlawBugConvertor
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
        trackers,
        package_versions,
    ):
        self.flaw = flaw
        self.affects = affects
        self.comments = comments
        self.history = history
        self.meta = meta
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
                if isinstance(part, TrackingMixin):
                    part.save(auto_timestamps=False)
                else:
                    part.save()

            # packageversions need special handling
            self.save_packageversions()

            self.clean_affects()
            # comments cannot be deleted in Bugzilla
            # history cannot be deleted in Bugzilla
            self.clean_meta()
            self.clean_trackers()

            self.link_trackers()

            # when all related entities are available we also need
            # to classify the created flaw however disable saving
            # flaw in the classification adjustment and call the
            # save afterwards since it will be only saved when
            # the classification changes and thus some flaw
            # changes done before may be lost
            self.flaw.adjust_classification(save=False)
            self.flaw.save(auto_timestamps=False)


class FlawBugConvertor:
    """
    Bugzilla flaw bug to OSIDB flaw model convertor
    this class is to performs the transformation only
    it takes the fetched but unprocessed backend models
    and provides all the model pieces to be saved
    """

    class FlawBugConvertorException(NonRecoverableBZImportException):
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
    _nvd_cvss = None

    def __init__(
        self,
        flaw_bug,
        flaw_comments,
        flaw_history,
        task_bug,
        tracker_bugs,
        tracker_jiras,
        nvd_cvss,
    ):
        """init source data"""
        self._flaw_bug = flaw_bug
        self._flaw_comments = flaw_comments
        self._flaw_history = flaw_history
        self._task_bug = task_bug
        self._tracker_bugs = tracker_bugs
        self._tracker_jiras = tracker_jiras
        self._nvd_cvss = nvd_cvss
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
    def flaw_bug(self):
        """check and get flaw bug"""
        if self._flaw_bug is None:
            raise self.FlawBugConvertorException("source data not set")
        return self._flaw_bug

    @property
    def flaw_comments(self):
        """check and get flaw comments"""
        if self._flaw_comments is None:
            raise self.FlawBugConvertorException("source data not set")
        return self._flaw_comments

    @property
    def flaw_history(self):
        """check and get flaw history"""
        if self._flaw_history is None:
            raise self.FlawBugConvertorException("source data not set")
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
            raise self.FlawBugConvertorException("source data not set")
        return self._tracker_bugs

    @property
    def tracker_jiras(self):
        """get list of tracker Jira issues"""
        if self._tracker_jiras is None:
            raise self.FlawBugConvertorException("source data not set")
        return self._tracker_jiras

    #########################
    # CVE COMMON PROPERTIES #
    #########################

    # shared accross multiple evenual CVEs

    @cached_property
    def acl_read(self):
        """get read ACL based on read groups"""
        return generate_acls(self.groups_read)

    @cached_property
    def acl_write(self):
        """get write ACL based on write groups"""
        return generate_acls(self.groups_write)

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

    @property
    def groups(self):
        """appropriate overall LDAP groups"""
        return self.groups_read + self.groups_write

    @property
    def groups_read(self):
        """appropriate read LDAP groups"""
        if "security" not in self.flaw_bug.get("groups", []):
            return settings.PUBLIC_READ_GROUPS

        if not BZ_ENABLE_IMPORT_EMBARGOED:
            raise self.FlawBugConvertorException(
                f"Flaw bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
            )

        return [settings.EMBARGO_READ_GROUP]

    @property
    def groups_write(self):
        """appropriate write LDAP groups"""
        if "security" not in self.flaw_bug.get("groups", []):
            return [settings.PUBLIC_WRITE_GROUP]

        if not BZ_ENABLE_IMPORT_EMBARGOED:
            raise self.FlawBugConvertorException(
                f"Flaw bug {self.bz_id} is embargoed but BZ_ENABLE_IMPORT_EMBARGOED is set to False"
            )

        return [settings.EMBARGO_WRITE_GROUP]

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
        meta_attr["last_imported_dt"] = timezone.now()
        meta_attr["acl_labels"] = self.groups
        meta_attr["task_owner"] = self.task_owner
        return meta_attr

    def get_nvd_cvss2(self, cve_id):
        """get NVD CVSS2"""
        if cve_id in self._nvd_cvss and "cvss2" in self._nvd_cvss[cve_id]:
            return self._nvd_cvss[cve_id]["cvss2"]

    def get_nvd_cvss3(self, cve_id):
        """get NVD CVSS3"""
        if cve_id in self._nvd_cvss and "cvss3" in self._nvd_cvss[cve_id]:
            return self._nvd_cvss[cve_id]["cvss3"]

    ##############################
    # TRACKER RELATED PROPERTIES #
    ##############################

    @property
    def bz_trackers(self):
        """
        Bugzilla trackers
        with product definitions context
        """
        return [
            TrackerBugConvertor(
                tracker, Tracker.TrackerType.BZ, self.acl_read, self.acl_write
            )
            for tracker in self.tracker_bugs
        ]

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
        return [
            TrackerBugConvertor(
                tracker, Tracker.TrackerType.JIRA, self.acl_read, self.acl_write
            )
            for tracker in self.tracker_jiras
        ]

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

    def get_flaw(self, cve_id):
        """get Flaw Django model"""
        flaw = Flaw.objects.create_flaw(
            bz_id=self.bz_id,
            cve_id=cve_id,
            type=FlawType.VULN,
            meta_attr=self.get_meta_attr(cve_id),
            nvd_cvss2=self.get_nvd_cvss2(cve_id),
            nvd_cvss3=self.get_nvd_cvss3(cve_id),
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
                    type=FlawType.VULN,
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
        "requires_doc_text": FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT,
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
        """perform flaw bug to flaw models conversion"""
        logger.debug(f"{self.__class__}: processing flaw bug {self.bz_id}")

        #################
        # CVE-less flaw #
        #################

        if not self.cve_ids:
            # remove all flaws with this BZ ID and any CVE ID in case there were
            # some CVEs before which got removed as they might have been multiple
            # and matching them to a single CVE-less flaw would be nontrivial
            # - see the next comment for more details
            Flaw.objects.filter(meta_attr__bz_id=self.bz_id).exclude(
                cve_id__isnull=True
            ).delete()

            flaw = self.get_flaw(cve_id=None)
            return [
                FlawSaver(
                    flaw,
                    self.get_affects(flaw),
                    self.get_comments(flaw),
                    self.get_history(),
                    self.get_all_meta(flaw),
                    self.get_trackers(),
                    self.package_versions,
                )
            ]

        #############
        # CVE flaws #
        #############

        flaws = []

        # CVE as Bugzilla alias is not persistent unlike BZ ID which is the identifier
        # so if it changes or gets removed (both looks the same from OSIDB point of view)
        # during the sync there will be that CVE missing in the fetched data
        # and to reflect it correctly we should remove corresponding flaw
        Flaw.objects.filter(meta_attr__bz_id=self.bz_id).exclude(
            cve_id__in=self.cve_ids
        ).delete()

        # in the past there was possible to have multiple CVEs for a flaw
        # but it is no more desired and we create a flaw for every CVE
        for cve_id in self.cve_ids:
            logger.debug(f"{self.__class__}: processing {cve_id}")

            flaw = self.get_flaw(cve_id)
            flaws.append(
                FlawSaver(
                    flaw,
                    self.get_affects(flaw),
                    self.get_comments(flaw),
                    self.get_history(),
                    self.get_all_meta(flaw),
                    self.get_trackers(),
                    self.package_versions,
                )
            )

        return flaws
