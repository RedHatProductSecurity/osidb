from typing import Union

import nvdlib
from celery.utils.log import get_task_logger
from django.conf import settings
from django.utils import timezone
from nvdlib.classes import CVE

from collectors.framework.models import Collector
from osidb.core import set_user_acls
from osidb.models import Flaw, FlawCVSS

logger = get_task_logger(__name__)


class NVDQuerier:
    """
    NVD query handler

    implementing query logic needed to NVD CVSS fetch
    https://nvd.nist.gov/developers/vulnerabilities
    uses nvdlib implementation to ease the logic
    """

    # maps NVD values to FlawCVSS values
    NVD_CVSS_MAP = {
        "cvssMetricV2": FlawCVSS.CVSSVersion.VERSION2,
        "cvssMetricV30": FlawCVSS.CVSSVersion.VERSION3,
        "cvssMetricV31": FlawCVSS.CVSSVersion.VERSION3,
        "cvssMetricV40": FlawCVSS.CVSSVersion.VERSION4,
    }

    def get(self, **params: dict) -> list:
        """
        run query request with nvdlib with the given parameters
        """
        return nvdlib.searchCVE(**params)

    def get_cve(self, cve: str) -> list:
        """
        given CVE data getter
        """
        return self.response2result(self.get(**{"cveId": cve}))

    def get_changed_cves(
        self, start: timezone.datetime, end: timezone.datetime
    ) -> list:
        """
        data getter for CVEs last modified between the give start and end timestamps
        the caller is responsible for providing the meaningful timestamps in sense
        of start being before the end and also the difference less then 120 days
        """
        return self.response2result(
            self.get(
                **{
                    "lastModStartDate": start,
                    "lastModEndDate": end,
                },
            )
        )

    def response2result(self, vulnerabilities: list) -> list:
        """
        convert the response data to the result we care for
        filtering out everything unnecessary and simplifying
        """

        def get_cvss_metric(data: CVE, version: str) -> Union[dict, None]:
            """
            Return CVSS metric from `data` for the given `version`.
            `version` can be of 3 values: cvssMetricV2, cvssMetricV30, cvssMetricV31.
            """
            # depending on the data, the following attributes might not be present
            if "metrics" not in data or (version not in data.metrics):
                return None

            cvss_data = getattr(data.metrics, version)[0]

            if cvss_data.source != "nvd@nist.gov":
                return None

            return {
                "issuer": FlawCVSS.CVSSIssuer.NIST,
                "vector": cvss_data.cvssData.vectorString,
                "version": self.NVD_CVSS_MAP[version]
                # Actual score is generated automatically when FlawCVSS is saved
            }

        result = []
        for vulnerability in vulnerabilities:
            if getattr(vulnerability, "vulnStatus", False) == "Rejected":
                continue

            # the result structure should match the Flaw fields
            # note that CVSS metrics may not be present in data
            result.append(
                {
                    "cve_id": vulnerability.id,
                    "cvss_scores": list(
                        filter(
                            lambda x: x is not None,
                            [
                                get_cvss_metric(vulnerability, "cvssMetricV2"),
                                # get CVSS 3.1 or CVSS 3.0 if 3.1 is not present
                                get_cvss_metric(vulnerability, "cvssMetricV31")
                                or get_cvss_metric(vulnerability, "cvssMetricV30"),
                                get_cvss_metric(vulnerability, "cvssMetricV40"),
                            ],
                        )
                    ),
                }
            )

        return result


class NVDCollector(Collector, NVDQuerier):
    """
    NVD CVSS collector
    """

    # the NIST NVD CVE project started in 1999
    # https://nvd.nist.gov/general/cve-process
    BEGINNING = timezone.datetime(1999, 1, 1, tzinfo=timezone.get_current_timezone())

    # the API period queries are limited to the window of 120 days
    # https://nvd.nist.gov/developers/vulnerabilities
    BATCH_PERIOD_DAYS = 100

    def __init__(self):
        """initiate collector"""
        super().__init__()

    def get_batch(self) -> (dict, timezone.datetime):
        """
        get next batch of NVD data plus period_end timestamp
        """
        period_start = self.metadata.updated_until_dt or self.BEGINNING
        period_end = period_start + timezone.timedelta(days=self.BATCH_PERIOD_DAYS)

        while True:
            batch = self.get_changed_cves(period_start, period_end)
            # in case of initial sync let us skip empty periods
            if batch or timezone.now() < period_end:
                return batch, period_end

            period_start = period_end
            period_end += timezone.timedelta(days=self.BATCH_PERIOD_DAYS)

    def collect(self, cve: Union[str, None] = None) -> str:
        """
        collector run handler

        on every run the NVD CVSS scores are fetched then compared
        with the existing ones and the changes are stored to DB

        cve param makes the collector to sync the given CVE scores only
        """
        # set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

        logger.info("Fetching NVD data")
        start_dt = timezone.now()
        updated_flaws = []

        # fetch data
        # by default for the next batch but can be overridden by a given CVE
        batch_data, period_end = (
            self.get_batch() if cve is None else (self.get_cve(cve=cve), None)
        )

        # process data
        for item in batch_data:
            cve_id = item["cve_id"]

            # check if a flaw is already in DB, and if so, update CVSS if necessary
            try:
                flaw = Flaw.objects.get(cve_id=cve_id)

                # update NIST CVSS data if necessary
                if self.update_cvss_via_flawcvss(flaw, item):
                    updated_flaws.append(cve_id)
                    # no automatic timestamps as those go from Bugzilla
                    # and no validation exceptions not to fail here
                    flaw.save(auto_timestamps=False, raise_validation_error=False)
            except Flaw.DoesNotExist:
                pass

        changes = (
            f"Updated CVEs due to changes in CVSS scores assigned by NIST: "
            f"{', '.join(updated_flaws) if updated_flaws else 'none'}. "
        )
        logger.info(changes)

        # do not update the collector metadata when ad-hoc collecting a given CVE
        if cve is not None:
            return f"NVD CVSS collection for {cve} completed"

        # when we get to the future with the period end
        # the initial sync is done and the data are complete
        updated_until_dt = min(start_dt, period_end)
        complete = start_dt == updated_until_dt or self.metadata.is_complete
        self.store(complete=complete, updated_until_dt=updated_until_dt)

        msg = f"{self.name} is updated until {updated_until_dt}. {changes}"

        logger.info("NVD sync was successful.")
        return msg

    def collect_updated(self) -> str:
        """
        collect NVD CVSS scores for recently updated flaws
        as they might have newly added or updated CVE IDs
        """
        if not self.is_complete:
            msg = (
                f"Collector {self.name} is not complete - skipping recent flaw updates"
            )
            logger.info(msg)
            return msg

        updated_cves = []
        for flaw in Flaw.objects.filter(
            cve_id__isnull=False, updated_dt__gte=self.metadata.updated_until_dt
        ):
            updated_cves.append(flaw.cve_id)
            self.collect(cve=flaw.cve_id)

        return (
            f"CVEs synced due to flaw updates: {', '.join(updated_cves)}"
            if updated_cves
            else ""
        )

    @staticmethod
    def get_original_nvd_cvss(flaw: Flaw, cvss_version: str) -> Union[str, None]:
        """
        Return NVD CVSS data stored in OSIDB from `flaw` for the given `cvss_version`.
        `cvss_version` is of FlawCVSS.CVSSVersion enum type.
        """
        return (
            flaw.cvss_scores.filter(issuer=FlawCVSS.CVSSIssuer.NIST)
            .filter(version=cvss_version)
            .values_list("vector", flat=True)
            .first()
        )

    @staticmethod
    def get_new_nvd_cvss(item: dict, cvss_version: str) -> Union[str, None]:
        """
        Return NVD CVSS data stored in NVD from `item` for the given `cvss_version`.
        `cvss_version` is of FlawCVSS.CVSSVersion enum type.
        """
        cvss = [i for i in item["cvss_scores"] if i["version"] == cvss_version]

        return cvss[0]["vector"] if cvss else None

    def update_cvss_via_flawcvss(self, flaw: Flaw, item: dict) -> bool:
        """
        Update NVD CVSS data in `flaw` if they are not equal to new NVD data in `item`.
        Return True if CVSS data was updated, False otherwise.
        """
        original_cvss2 = self.get_original_nvd_cvss(flaw, FlawCVSS.CVSSVersion.VERSION2)
        original_cvss3 = self.get_original_nvd_cvss(flaw, FlawCVSS.CVSSVersion.VERSION3)
        original_cvss4 = self.get_original_nvd_cvss(flaw, FlawCVSS.CVSSVersion.VERSION4)

        new_cvss2 = self.get_new_nvd_cvss(item, FlawCVSS.CVSSVersion.VERSION2)
        new_cvss3 = self.get_new_nvd_cvss(item, FlawCVSS.CVSSVersion.VERSION3)
        new_cvss4 = self.get_new_nvd_cvss(item, FlawCVSS.CVSSVersion.VERSION4)

        # update CVSS2, CVSS3 and CVSS4 if necessary
        if were_updated := (
            (original_cvss2 != new_cvss2)
            or (original_cvss3 != new_cvss3)
            or (original_cvss4 != new_cvss4)
        ):
            for original_cvss, new_cvss, version in [
                (original_cvss2, new_cvss2, FlawCVSS.CVSSVersion.VERSION2),
                (original_cvss3, new_cvss3, FlawCVSS.CVSSVersion.VERSION3),
                (original_cvss4, new_cvss4, FlawCVSS.CVSSVersion.VERSION4),
            ]:
                if original_cvss and new_cvss is None:
                    # NVD CVSS was removed, so do the same in OSIDB
                    flaw.cvss_scores.filter(issuer=FlawCVSS.CVSSIssuer.NIST).filter(
                        version=version
                    ).delete()
                    continue

                if original_cvss != new_cvss:
                    # perform either update or create
                    cvss_score = FlawCVSS.objects.create_cvss(
                        flaw,
                        FlawCVSS.CVSSIssuer.NIST,
                        version,
                        vector=new_cvss,
                        acl_write=flaw.acl_write,
                        acl_read=flaw.acl_read,
                    )
                    cvss_score.save()

        return were_updated
