from osidb.models import Impact, PsModule
from osidb.models.affect import Affect
from osidb.models.flaw.flaw import Flaw

from .default_handler import DefaultHandler


class MajorIncidentHandler(DefaultHandler):
    """
    major incident pre-selection handler

    pre-selection works the same way as for DefaultHandler
    only the applicability conditions are different
    """

    @staticmethod
    def is_applicable(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return affect.flaw.major_incident_state in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
            Flaw.FlawMajorIncident.ZERO_DAY,
        ]
