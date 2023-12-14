from osidb.models import Affect, Impact, PsModule

from .base import ProductDefinitionHandler


class UnackedHandler(ProductDefinitionHandler):
    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):

        unacked_preselected = not affect.flaw.is_major_incident_temp() and impact in [
            Impact.MODERATE,
            Impact.LOW,
        ]
        unacked_stream = ps_module.unacked_ps_update_stream.first()
        if unacked_stream:
            offers[unacked_stream.name] = {
                "ps_update_stream": unacked_stream.name,
                "selected": unacked_preselected,
                "aus": False,
                "eus": False,
                "acked": False,
            }
        return offers
