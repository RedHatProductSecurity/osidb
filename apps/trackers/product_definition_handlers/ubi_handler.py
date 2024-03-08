from osidb.helpers import ps_update_stream_natural_keys
from osidb.models import Affect, Impact, PsModule, UbiPackage

from .base import ProductDefinitionHandler
from .fedramp_handler import FedrampHandler


class UBIHandler(ProductDefinitionHandler):
    """
    UBI product definition handles

    This handler should run after UnackedHandler and before FedrampHandler

    The handler that runs before this handler must avoid doing changes in `offers`
    that would conflict with UBIHandler:
    - If UBI streams are selected, the unacked stream must not be selected.
    """

    UBI_OVERRIDES = [Impact.MODERATE]

    @staticmethod
    def will_modify_offers(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        True if UbiHandler will modify the offers passed to get_offer. Can be used
        by other handlers to avoid doing offers edits that would have to be reverted
        by UbiHandler.
        """
        is_ubi = UBIHandler.has_ubi_packages(ps_module, affect)
        return is_ubi and impact in UBIHandler.UBI_OVERRIDES

    @staticmethod
    def has_ubi_packages(ps_module: PsModule, affect: Affect) -> bool:
        """check whether a ps_module has ubi packages given a target PsUpdateStream name"""
        if "ubi_packages" not in ps_module.special_handling_features:
            return False
        packages = UbiPackage.objects.filter(name=affect.ps_component)
        return bool(packages)

    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        if FedrampHandler.will_modify_offers(affect, impact, ps_module):
            # FedrampHandler is next and it would have to undo everything done by UbiHandler.
            return offers

        if UBIHandler.will_modify_offers(affect, impact, ps_module):

            z_stream = ps_module.z_stream
            if z_stream:
                # This can pre-select streams that are not marked as default,
                # so streams_to_preselect may not be a subset of
                # ps_module.default_ps_update_streams.  The reason for that is
                # that during the RC phase / after Batch 3, it's better to file
                # Z-stream trackers for the next minor release Z-stream rather
                # than the current minor release Z-stream.

                # ps_module.z_stream is the latest Z-stream stream defined in
                # ps_module's active streams - it may not be included in the
                # default streams list

                offers[z_stream.name] = {
                    "ps_update_stream": z_stream.name,
                    "selected": True,
                    "eus": bool(
                        ps_module.eus_ps_update_streams.filter(name=z_stream.name)
                    ),
                    "aus": bool(
                        ps_module.aus_ps_update_streams.filter(name=z_stream.name)
                    ),
                    "acked": True,
                }

                # ensure Y-streams earlier than the ps_module.z_stream are not
                # pre-selected
                for stream in ps_module.y_streams:
                    if ps_update_stream_natural_keys(
                        stream
                    ) > ps_update_stream_natural_keys(z_stream):
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
