from osidb.models import Affect, Flaw, Impact, PsModule

from .base import ProductDefinitionHandler
from .fedramp_handler import FedrampHandler
from .ubi_handler import UBIHandler


class UnackedHandler(ProductDefinitionHandler):
    """
    Unacked stream handler

    This handler should run before UBIHandler and before FedrampHandler
    """

    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        if UBIHandler.will_modify_offers(affect, impact, ps_module):
            # If UBI streams are selected, the unacked stream must not be selected.
            return offers
        if FedrampHandler.will_modify_offers(affect, impact, ps_module):
            # If Fedramp streams are selected, the unacked stream must not be selected.
            # Ref. OSIDB-1876 comment #10 written by P.
            return offers

        unacked_preselected = affect.flaw.major_incident_state not in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
        ] and impact in [Impact.MODERATE, Impact.LOW]
        unacked_stream = ps_module.unacked_ps_update_stream.first()
        if unacked_stream:
            offers[unacked_stream.name] = {
                "ps_update_stream": unacked_stream.name,
                "selected": unacked_preselected,
                "aus": False,
                "eus": False,
                "acked": False,
            }
        return offers
