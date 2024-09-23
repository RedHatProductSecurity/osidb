from osidb.models import Affect, Flaw, Impact, PsModule

from .base import ProductDefinitionHandler


class UnackedHandler(ProductDefinitionHandler):
    """
    unacked pre-selection handler
    """

    UNACKED_IMPACT_APPLICABLE = [Impact.MODERATE, Impact.LOW]

    @staticmethod
    def is_applicable(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return bool(impact in UnackedHandler.UNACKED_IMPACT_APPLICABLE)

    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        """
        pre-select the streams
        """
        unacked_stream = ps_module.unacked_ps_update_stream.first()
        if not unacked_stream:
            # Nothing to handle
            return offers
        if not ps_module.active_ps_update_streams.filter(name=unacked_stream.name):
            # Ignore unacked stream that is not active for this module
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
