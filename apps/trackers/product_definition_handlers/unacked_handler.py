from osidb.dmodels import PsModule
from osidb.dmodels.affect import Affect
from osidb.models import Impact

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
        if unacked_stream and unacked_stream.name in offers:
            offers[unacked_stream.name]["selected"] = (
                impact in UnackedHandler.UNACKED_IMPACT_PRESELECTED
            )
        return offers
