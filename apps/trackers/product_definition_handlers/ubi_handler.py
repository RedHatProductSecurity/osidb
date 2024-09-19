from osidb.dmodels import PsModule, UbiPackage
from osidb.dmodels.affect import Affect
from osidb.helpers import ps_update_stream_natural_keys
from osidb.models import Impact

from .base import ProductDefinitionHandler


class UBIHandler(ProductDefinitionHandler):
    """
    UBI pre-selection handler
    """

    UBI_OVERRIDES = [Impact.MODERATE]

    @staticmethod
    def is_applicable(affect: Affect, impact: Impact, ps_module: PsModule) -> bool:
        """
        check whether the hanler is applicable to the given affect
        the caller is responsible for checking the applicability before getting the offer
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

    @staticmethod
    def get_offer(affect: Affect, impact: Impact, ps_module: PsModule, offers):
        """
        pre-select the streams
        """
        z_stream = ps_module.z_stream
        if not z_stream or z_stream.name not in offers:
            # no applicable Z-stream exists
            return offers

        # This can pre-select streams that are not marked as default,
        # so streams_to_preselect may not be a subset of
        # ps_module.default_ps_update_streams.  The reason for that is
        # that during the RC phase / after Batch 3, it's better to file
        # Z-stream trackers for the next minor release Z-stream rather
        # than the current minor release Z-stream.

        # ps_module.z_stream is the latest Z-stream stream defined in
        # ps_module's active streams - it may not be included in the
        # default streams list

        offers[z_stream.name]["selected"] = True

        for stream in ps_module.y_streams:
            if stream.name not in offers:
                continue

            # skip Y-streams earlier than the Z-stream
            if ps_update_stream_natural_keys(stream) > ps_update_stream_natural_keys(
                z_stream
            ):
                offers[stream.name]["selected"] = True

        return offers
