from osidb.models import Affect, Impact, PsModule

from .base import ProductDefinitionHandler


class UnackedHandler(ProductDefinitionHandler):
    """
    unacked pre-selection handler
    """

    UNACKED_IMPACT_APPLICABLE = [Impact.MODERATE, Impact.LOW]
    UNACKED_IMPACT_PRESELECTED = [Impact.MODERATE]

    @staticmethod
    def is_applicable(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return impact in UnackedHandler.UNACKED_IMPACT_APPLICABLE

    @staticmethod
    def get_offer(affect: Affect, impact: Impact, ps_module: PsModule, offers):
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

        offers[unacked_stream.name] = {
            "ps_update_stream": unacked_stream.name,
            "selected": impact in UnackedHandler.UNACKED_IMPACT_PRESELECTED,
            "aus": False,
            "eus": False,
            "acked": False,
        }
        return offers
