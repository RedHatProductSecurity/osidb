from osidb.models import Impact, PsModule
from osidb.models.affect import Affect

from .base import ProductDefinitionHandler


class ModerateHandler(ProductDefinitionHandler):
    """
    moderate impact pre-selection handler
    """

    @staticmethod
    def is_applicable(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
        """
        return (
            impact == Impact.MODERATE and ps_module.moderate_ps_update_streams.exists()
        )

    @staticmethod
    def get_offer(affect: Affect, impact: Impact, ps_module: PsModule, offers):
        """
        pre-select the streams
        """
        for stream in ps_module.moderate_ps_update_streams.all():
            if stream.name in offers:
                offers[stream.name]["selected"] = True
        return offers
