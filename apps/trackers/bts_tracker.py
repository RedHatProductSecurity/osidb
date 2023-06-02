"""
BTS Trackers model used to create in-memory trackers
that will be persisted in the corresponding BTS
"""
from typing import Any, Dict

from apps.trackers.exceptions import UnsupportedTrackerError
from osidb.models import Affect, Flaw, PsModule, PsUpdateStream


class BTSTracker:
    """
    In-memory BTS tracker instance that should hold enough data to
    create tracker in all BTS supported (currently Bugzilla and Jira)
    """

    def __init__(self, flaw: Flaw, affect: Affect, stream: PsUpdateStream) -> None:
        """
        performs feasibility checks and initializes context
        """
        assert (
            flaw and affect and stream
        ), "parameters are mandatory and must be non-empty"

        # we do not support tracker filing for the old multi-CVE flaws
        if Flaw.objects.filter(meta_attr__bz_id=flaw.bz_id).count() > 1:
            raise UnsupportedTrackerError(
                "Creating trackers for flaws with multiple CVEs is not supported"
            )

        self._flaw = flaw
        self._affect = affect
        self._ps_module = PsModule.objects.filter(name=affect.ps_module).first()
        self._stream = stream

    def generate_bts_object(self) -> Dict[str, Any]:
        """
        Generates an object that contains all needed fields
        to create or update a new tracker in the corresponding BTS
        """

    def _generate_summary(self) -> str:
        """
        Generates the summary of a tracker
        """
        # CVE ID might be not yet assigned
        cve_id = self._flaw.cve_id + " " if self._flaw.cve_id else ""
        return f"{cve_id}{self._affect.ps_component}: {self._flaw.title} [{self._stream.name}]"
