from datetime import datetime, timezone

import pytest
from freezegun import freeze_time

from osidb.models import PsModule, PsUpdateStream
from osidb.tests.factories import PsModuleFactory, PsUpdateStreamFactory


class TestPsModule:
    @freeze_time(datetime(2020, 10, 20, tzinfo=timezone.utc))
    @pytest.mark.parametrize(
        "supported_from,supported_until,is_prodsec_supported",
        [
            (
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,
            ),
            (
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                False,
            ),
            (
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,  # support start in the future should not restrict ProdSec support
            ),
            (
                None,
                datetime(2020, 10, 30, tzinfo=timezone.utc),
                True,
            ),
            (
                datetime(2020, 10, 10, tzinfo=timezone.utc),
                None,
                True,
            ),
        ],
    )
    def test_is_prodsec_supported(
        self, supported_from, supported_until, is_prodsec_supported
    ):
        assert (
            PsModule(
                supported_from_dt=supported_from,
                supported_until_dt=supported_until,
            ).is_prodsec_supported
            == is_prodsec_supported
        )

    @pytest.mark.django_db
    def test_z_stream_property(self):
        """Test PsModule.z_stream property returns latest Z-stream"""
        ps_module = PsModuleFactory(name="rhel-9")
        PsUpdateStreamFactory(
            name="rhel-9.8.z", ps_module=ps_module, active_to_ps_module=ps_module
        )
        PsUpdateStreamFactory(
            name="rhel-9.9.z", ps_module=ps_module, active_to_ps_module=ps_module
        )

        # Should return latest (natural sort desc)
        assert ps_module.z_stream.name == "rhel-9.9.z"

    @pytest.mark.django_db
    def test_get_z_streams_with_instance(self):
        """Test PsUpdateStreamManager.get_z_streams accepts PsModule instance"""
        ps_module = PsModuleFactory(name="rhel-9")
        PsUpdateStreamFactory(
            name="rhel-9.8.z", ps_module=ps_module, active_to_ps_module=ps_module
        )
        PsUpdateStreamFactory(
            name="rhel-9.9.z", ps_module=ps_module, active_to_ps_module=ps_module
        )

        result = PsUpdateStream.objects.get_z_streams(ps_module)
        names = list(result.values_list("name", flat=True))

        assert len(names) == 2
        # Should be ordered desc (latest first) using natural sort
        assert names == ["rhel-9.9.z", "rhel-9.8.z"]

    @pytest.mark.django_db
    def test_get_y_streams_with_instance(self):
        """Test PsUpdateStreamManager.get_y_streams accepts PsModule instance"""
        ps_module = PsModuleFactory(name="rhel-9")
        PsUpdateStreamFactory(
            name="rhel-9.9", ps_module=ps_module, active_to_ps_module=ps_module
        )
        PsUpdateStreamFactory(
            name="rhel-9.10", ps_module=ps_module, active_to_ps_module=ps_module
        )

        result = PsUpdateStream.objects.get_y_streams(ps_module)
        names = list(result.values_list("name", flat=True))

        assert len(names) == 2
        # Should be ordered asc (next/lowest first) using natural sort
        assert names == ["rhel-9.9", "rhel-9.10"]
