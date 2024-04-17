from osidb.helpers import ps_update_stream_natural_keys
from osidb.models import Affect, Impact, PsModule, UbiPackage

from .base import ProductDefinitionHandler


class UBIHandler(ProductDefinitionHandler):
    """
    UBI product definition handles

    This handler should run anytime after UnackedHandler
    """

    def __init__(self) -> None:
        self.UBI_OVERRIDES = [Impact.MODERATE]

    def has_ubi_packages(ps_module: PsModule, affect: Affect) -> bool:
        """check weheter a ps_module has ubi packages given a target PsUpdateStream name"""
        if "ubi_packages" not in ps_module.special_handling_features:
            return False
        packages = UbiPackage.objects.filter(name=affect.ps_component)
        return bool(packages)

    def get_offer(self, affect: Affect, impact: Impact, ps_module: PsModule, offers):
        is_ubi = UBIHandler.has_ubi_packages(ps_module, affect)

        if is_ubi and impact in self.UBI_OVERRIDES:
            unacked_stream = ps_module.unacked_ps_update_stream.first()
            if unacked_stream:
                offers[unacked_stream.name] = {
                    "ps_update_stream": unacked_stream.name,
                    "selected": False,
                    "aus": False,
                    "eus": False,
                    "acked": False,
                }

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
                    "acked": not ps_module.unacked_ps_update_stream,
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
                            "acked": not ps_module.unacked_ps_update_stream,
                        }

        return offers
