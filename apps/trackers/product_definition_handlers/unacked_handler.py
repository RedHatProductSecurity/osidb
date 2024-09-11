from osidb.models import Affect, Flaw, Impact, PsModule

from .base import ProductDefinitionHandler
from .ubi_handler import UBIHandler


class UnackedHandler(ProductDefinitionHandler):
    """
    Unacked stream handler

    This handler should run before UBIHandler
    """

    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        unacked_stream = ps_module.unacked_ps_update_stream.first()
        if not unacked_stream:
            # Nothing to handle
            return offers
        if not ps_module.active_ps_update_streams.filter(name=unacked_stream.name):
            # Ignore unacked stream that is not active for this module
            return offers
        if UBIHandler.will_modify_offers(affect, impact, ps_module):
            # If UBI streams are selected, the unacked stream must not be selected.
            return offers

        unacked_preselected = affect.flaw.major_incident_state not in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
        ] and impact in [Impact.MODERATE, Impact.LOW]
        offers[unacked_stream.name] = {
            "ps_update_stream": unacked_stream.name,
            "selected": unacked_preselected,
            "aus": False,
            "eus": False,
            "acked": False,
        }
        return offers
