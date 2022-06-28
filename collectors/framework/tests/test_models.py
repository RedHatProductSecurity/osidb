import pytest
from celery.schedules import crontab

from collectors.framework.tests.factories import CollectorMetadataFactory

pytestmark = pytest.mark.unit


class TestCollectorMetadata:
    @pytest.mark.parametrize("crontab_params", [{}, {"minute": "1"}, {"hour": "*/5"}])
    def test_crontab_store(self, crontab_params):
        original_crontab = crontab(**crontab_params)
        metadata = CollectorMetadataFactory(crontab=str(original_crontab))
        restored_crontab = crontab(**metadata.crontab_params)

        assert original_crontab == restored_crontab

    def test_no_crontab(self):
        metadata = CollectorMetadataFactory(crontab="")

        assert metadata.crontab_params is None
