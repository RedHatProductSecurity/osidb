from osidb.models import Affect, Impact, PsUpdateStream

from .base import ProductDefinitionHandler


class ModerateHandler(ProductDefinitionHandler):
    """
    moderate impact pre-selection handler
    """

    @staticmethod
    def is_applicable(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream
    ) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return impact == Impact.MODERATE and ps_update_stream.is_moderate

    @staticmethod
    def get_offer(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream, offer
    ):
        """
        pre-select the streams
        """
        if (
            ps_update_stream.is_moderate
            and offer["ps_update_stream"] == ps_update_stream.name
        ):
            offer["selected"] = True
        return offer
