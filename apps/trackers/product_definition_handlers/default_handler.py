from osidb.models import Affect, Impact, PsUpdateStream

from .base import ProductDefinitionHandler


class DefaultHandler(ProductDefinitionHandler):
    """
    default pre-selection handler
    """

    # only the higher impacts have the default handling
    DEFAULT_IMPACT_APPLICABLE = [Impact.CRITICAL, Impact.IMPORTANT]

    @staticmethod
    def is_applicable(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream
    ) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return impact in DefaultHandler.DEFAULT_IMPACT_APPLICABLE

    @staticmethod
    def get_offer(
        affect: Affect, impact: Impact, ps_update_stream: PsUpdateStream, offer
    ):
        """
        pre-select the streams
        """
        if (
            ps_update_stream.is_default
            and offer["ps_update_stream"] == ps_update_stream.name
        ):
            offer["selected"] = True
        return offer
