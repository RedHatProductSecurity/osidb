from osidb.models import Affect, Flaw, Impact, PsUpdateStream

from .default_handler import DefaultHandler


class MajorIncidentHandler(DefaultHandler):
    """
    major incident pre-selection handler

    pre-selection works the same way as for DefaultHandler
    only the applicability conditions are different
    """

    @staticmethod
    def is_applicable(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream
    ) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return affect.flaw.major_incident_state in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
            Flaw.FlawMajorIncident.ZERO_DAY,
        ]
