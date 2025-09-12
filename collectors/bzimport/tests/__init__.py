import os

import pytest

os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Skip tests for deprecated Bugzilla collector
pytestmark = pytest.mark.skip()
