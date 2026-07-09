import pytest

from osidb.exceptions import OSIDBException
from osidb.helpers import get_env_groups

pytestmark = pytest.mark.unit


class TestGetEnvGroups:
    """Tests for the get_env_groups helper that normalizes env vars to lists."""

    def test_json_list(self, monkeypatch):
        monkeypatch.setenv("TEST_GROUPS", '["group-a", "group-b"]')
        assert get_env_groups("TEST_GROUPS") == ["group-a", "group-b"]

    def test_json_single_element_list(self, monkeypatch):
        monkeypatch.setenv("TEST_GROUPS", '["group-a"]')
        assert get_env_groups("TEST_GROUPS") == ["group-a"]

    def test_plain_string(self, monkeypatch):
        monkeypatch.setenv("TEST_GROUPS", "group-a")
        assert get_env_groups("TEST_GROUPS") == ["group-a"]

    def test_json_string_value(self, monkeypatch):
        monkeypatch.setenv("TEST_GROUPS", '"group-a"')
        assert get_env_groups("TEST_GROUPS") == ["group-a"]

    def test_missing_env_var(self):
        with pytest.raises(OSIDBException, match="Required environment variable"):
            get_env_groups("NONEXISTENT_TEST_VAR")

    def test_empty_list(self, monkeypatch):
        monkeypatch.setenv("TEST_GROUPS", "[]")
        assert get_env_groups("TEST_GROUPS") == []

    def test_preserves_order(self, monkeypatch):
        monkeypatch.setenv("TEST_GROUPS", '["c", "a", "b"]')
        assert get_env_groups("TEST_GROUPS") == ["c", "a", "b"]
