from osidb.helpers import ps_update_stream_natural_keys
from osidb.models import Affect, CompliancePriority, Impact, PsModule, PsUpdateStream

from .base import ProductDefinitionHandler


class FedrampHandler(ProductDefinitionHandler):
    """
    Fedramp product definition handles

    This handler should run after UnackedHandler and after FedrampHandler.

    The handlers that run before this handler must avoid doing changes in `offers`
    that would conflict with FedrampHandler:
    - If Fedramp streams are selected, the unacked stream must not be selected.
    - If Fedramp streams are selected UBI stream handling must be disabled
      (no additional UBI streams must be selected).
    """

    FEDRAMP_OVERRIDES = [Impact.MODERATE]

    @staticmethod
    def will_modify_offers(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        True if FedrampHandler will modify the offers passed to get_offer. Can be used
        by other handlers to avoid doing offers edits that would have to be reverted
        by FedrampHandler.
        """
        return (
            FedrampHandler.compliance_priority_fedramp_streams(affect, ps_module)
            and impact in FedrampHandler.FEDRAMP_OVERRIDES
        )

    @staticmethod
    def compliance_priority_fedramp_streams(
        affect: Affect, ps_module: PsModule
    ) -> list[PsUpdateStream]:
        if affect.is_compliance_priority:
            stream_names = CompliancePriority.objects.get(
                ps_module=ps_module.name
            ).streams
            streams = PsUpdateStream.objects.filter(name__in=stream_names).all()
            return (
                min(list(streams), key=ps_update_stream_natural_keys)
                if streams
                else None
            )

    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        # compliance priority / fedramp special handling
        #
        # Only apply this special handling when fedramp stream is
        # configured in the compliance_priority list.
        if FedrampHandler.will_modify_offers(affect, impact, ps_module):

            # If multiple fedramp streams are configured, only seed the
            # streams_to_preselect with the oldest one.
            stream_to_preselect = FedrampHandler.compliance_priority_fedramp_streams(
                affect, ps_module
            )

            # Moderate issues in fedramp components need to be fixed in
            # fedramp streams and all following streams.
            for stream in ps_module.default_ps_update_streams.all():
                if ps_update_stream_natural_keys(
                    stream
                ) >= ps_update_stream_natural_keys(stream_to_preselect):
                    offers[stream.name] = {
                        "ps_update_stream": stream.name,
                        "selected": True,
                        "eus": bool(
                            ps_module.eus_ps_update_streams.filter(name=stream.name)
                        ),
                        "aus": bool(
                            ps_module.aus_ps_update_streams.filter(name=stream.name)
                        ),
                        "acked": True,
                    }

        return offers
