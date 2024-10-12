from osidb.models import Affect, Impact, PsModule

from .base import ProductDefinitionHandler


class DefaultHandler(ProductDefinitionHandler):
    """
    default pre-selection handler
    """

    # only the higher impacts have the default handling
    DEFAULT_IMPACT_APPLICABLE = [Impact.CRITICAL, Impact.IMPORTANT]

    @staticmethod
    def is_applicable(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return impact in DefaultHandler.DEFAULT_IMPACT_APPLICABLE

    @staticmethod
    def get_offer(affect: Affect, impact: Impact, ps_module: PsModule, offers):
        """
        pre-select the streams
        """
        for stream in ps_module.default_ps_update_streams.all():
            if stream.name in offers:
                offers[stream.name]["selected"] = True
        return offers
