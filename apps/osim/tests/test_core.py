import logging

import pytest

logger = logging.getLogger("apps.osim")
pytestmark = pytest.mark.unit


class TestCore(object):
    def test_test(self):
        """test the tests ..."""
        assert 1 == 1
