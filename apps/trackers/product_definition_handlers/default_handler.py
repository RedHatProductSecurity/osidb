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
            if stream.name not in offers:
                continue

            offers[stream.name] = {
                "ps_update_stream": stream.name,
                "selected": True,
                "acked": not bool(
                    ps_module.unacked_ps_update_stream.filter(name=stream.name)
                ),
                "eus": bool(ps_module.eus_ps_update_streams.filter(name=stream.name)),
                "aus": bool(ps_module.aus_ps_update_streams.filter(name=stream.name)),
            }
        return offers
