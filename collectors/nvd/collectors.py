from typing import Union

import nvdlib
from celery.utils.log import get_task_logger
from django.conf import settings
from django.utils import timezone

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

        def compose_cvss(metrics: list) -> Union[str, None]:
            """
            compose the result vector helper
            """
            for metric in metrics:
                # we only care for NVD record
                if metric.source == "nvd@nist.gov":
                    return f"{metric.cvssData.baseScore}/{metric.cvssData.vectorString}"

        def get_metric(metrics: dict, version: str) -> Union[str, None]:
            """
            get metric record for the given version if exists
            """
            if version not in metrics:
                return None
            return compose_cvss(getattr(metrics, version))

        result = []
        for vulnerability in vulnerabilities:
            result.append(
                {
                    "cve": vulnerability.id,
                    "cvss2": get_metric(vulnerability.metrics, "cvssMetricV2"),
                    # try to get CVSS 3.1 but if not present 3.0 is better than nothing
                    "cvss3": get_metric(vulnerability.metrics, "cvssMetricV31")
                    or get_metric(vulnerability.metrics, "cvssMetricV30"),
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

        logger.info("Fetching NVD CVSS")
        start_dt = timezone.now()
        desync = []

        # fetch data
        # by default for the next batch but can be overridden by a given CVE
        batch_data, period_end = (
            self.get_batch() if cve is None else (self.get_cve(cve=cve), None)
        )

        # process data
        for item in batch_data:
            flaw = Flaw.objects.filter(cve_id=item["cve"]).first()
            if not flaw:
                continue

            # we are interested in NIST only
            flaw_nist_cvss_scores = flaw.cvss_scores.filter(
                issuer=FlawCVSS.CVSSIssuer.NIST
            )

            # get the original CVSSv2 and CVSSv3 vectors
            original_cvss2 = (
                flaw_nist_cvss_scores.filter(version=FlawCVSS.CVSSVersion.VERSION2)
                .values_list("vector", flat=True)
                .first()
            )
            original_cvss3 = (
                flaw_nist_cvss_scores.filter(version=FlawCVSS.CVSSVersion.VERSION3)
                .values_list("vector", flat=True)
                .first()
            )

            # get the new CVSSv2 and CVSSv3 vectors
            new_cvss2 = item["cvss2"].split("/", 1)[1] if item["cvss2"] else None
            new_cvss3 = item["cvss3"].split("/", 1)[1] if item["cvss3"] else None

            # check if any changes (via FlawCVSS)
            if original_cvss2 == new_cvss2 and original_cvss3 == new_cvss3:
                continue

            # check if any changes (via Flaw, will be deprecated)
            if flaw.nvd_cvss2 == item["cvss2"] and flaw.nvd_cvss3 == item["cvss3"]:
                continue

            desync.append(item["cve"])

            # update CVSSv2 and CVSSv3 if necessary (via FlawCVSS)
            for original_cvss, new_cvss, version in [
                (original_cvss2, new_cvss2, FlawCVSS.CVSSVersion.VERSION2),
                (original_cvss3, new_cvss3, FlawCVSS.CVSSVersion.VERSION3),
            ]:
                if original_cvss != new_cvss:
                    # performs either update or create
                    cvss_score = FlawCVSS.objects.create_cvss(
                        flaw,
                        FlawCVSS.CVSSIssuer.NIST,
                        version,
                        vector=new_cvss,
                        acl_write=flaw.acl_write,
                        acl_read=flaw.acl_read,
                    )
                    cvss_score.save()

            # update CVSSv2 and CVSSv3 if necessary (via Flaw, will be deprecated)
            if flaw.nvd_cvss2 != item["cvss2"]:
                flaw.nvd_cvss2 = item["cvss2"]
            if flaw.nvd_cvss3 != item["cvss3"]:
                flaw.nvd_cvss3 = item["cvss3"]

            # no automatic timestamps as those go from Bugzilla
            # and no validation exceptions not to fail here
            flaw.save(
                auto_timestamps=False,
                raise_validation_error=False,
            )

        logger.info(
            f"NVD CVSS scores were updated for the following CVEs: {', '.join(desync)}"
            if desync
            else "No CVEs with desynced NVD CVSS."
        )

        # do not update the collector metadata
        # when ad-hoc collecting a given CVE
        if cve is not None:
            return f"NVD CVSS collection for {cve} completed"

        # when we get to the future with the period end
        # the initial sync is done and the data are complete
        updated_until_dt = min(start_dt, period_end)
        complete = start_dt == updated_until_dt or self.metadata.is_complete
        self.store(complete=complete, updated_until_dt=updated_until_dt)

        msg = f"{self.name} is updated until {updated_until_dt}."
        msg += f" CVEs synced: {', '.join(desync)}" if desync else ""

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
