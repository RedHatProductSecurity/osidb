from osidb.models import Affect, Impact, PsUpdateStream

from .base import ProductDefinitionHandler


class UnackedHandler(ProductDefinitionHandler):
    """
    unacked pre-selection handler
    """

    UNACKED_IMPACT_APPLICABLE = [Impact.MODERATE, Impact.LOW]
    UNACKED_IMPACT_PRESELECTED = [Impact.MODERATE]

    @staticmethod
    def is_applicable(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream
    ) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return impact in UnackedHandler.UNACKED_IMPACT_APPLICABLE

    @staticmethod
    def get_offer(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream, offer
    ):
        """
        pre-select the streams
        """
        if (
            ps_update_stream.is_unacked
            and offer["ps_update_stream"] == ps_update_stream.name
        ):
            offer["selected"] = impact in UnackedHandler.UNACKED_IMPACT_PRESELECTED
        return offer
