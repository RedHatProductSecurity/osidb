"""Stream scope is imported as exhaustive lists without package-family inference."""

import pytest

from ..core import sync_component_mapping
from ..models import BlocklistEntry, PackageScope

pytestmark = [pytest.mark.unit, pytest.mark.django_db]


def test_sync_normalizes_and_keeps_streams_separate():
    """Each stream gets only its supplied names, with case duplicates removed."""
    data = {
        "package_scope": {
            "rhel-6-els": ["OpenSSL", "openssl", "krb5-libs"],
            "example-1-restricted": ["perl-DBI"],
        }
    }
    for _ in range(2):
        assert sync_component_mapping(data)["package_scope"] == 2
        assert dict(
            PackageScope.objects.values_list("ps_update_stream", "components")
        ) == {
            "rhel-6-els": ["openssl", "krb5-libs"],
            "example-1-restricted": ["perl-dbi"],
        }


def test_sync_replaces_scope():
    """A replacement bundle removes obsolete streams and package membership."""
    sync_component_mapping(
        {"package_scope": {"old-stream": ["openssl"], "current-stream": ["yum"]}}
    )
    sync_component_mapping({"package_scope": {"current-stream": ["krb5"]}})
    assert list(PackageScope.objects.values_list("ps_update_stream", "components")) == [
        ("current-stream", ["krb5"])
    ]


@pytest.mark.parametrize("data", [{}, {"package_scope": {}}])
def test_missing_or_empty_section_clears_scope(data):
    """Missing sections follow the same replacement semantics as other lists."""
    sync_component_mapping({"package_scope": {"rhel-6-els": ["openssl"]}})
    assert sync_component_mapping(data)["package_scope"] == 0
    assert not PackageScope.objects.exists()


def test_empty_stream_scope_is_preserved():
    """An empty inclusion list remains distinguishable from an absent stream."""
    assert (
        sync_component_mapping({"package_scope": {"empty-stream": []}})["package_scope"]
        == 1
    )
    assert PackageScope.objects.get(ps_update_stream="empty-stream").components == []


@pytest.mark.parametrize(
    "scope",
    [
        None,
        [],
        {"": ["openssl"]},
        {" ": ["openssl"]},
        {" rhel-6-els": ["openssl"]},
        {"rhel-6-els ": ["openssl"]},
        {"\trhel-6-els": ["openssl"]},
        {"rhel-6-els\n": ["openssl"]},
        {"\u00a0rhel-6-els": ["openssl"]},
        {"s" * 101: ["openssl"]},
        {"rhel-6-els": "openssl"},
        {"rhel-6-els": [None]},
        {"rhel-6-els": [""]},
        {"rhel-6-els": [" "]},
        {"rhel-6-els": [" openssl"]},
        {"rhel-6-els": ["openssl "]},
        {"rhel-6-els": ["\topenssl"]},
        {"rhel-6-els": ["openssl\n"]},
        {"rhel-6-els": ["\u00a0openssl"]},
        {"rhel-6-els": ["x" * 513]},
    ],
)
def test_malformed_scope_rolls_back_bundle(scope):
    """Invalid container shapes or names cannot partially replace reference data."""
    sync_component_mapping(
        {"package_scope": {"rhel-6-els": ["openssl"]}, "blocklist": {"old": "reason"}}
    )
    with pytest.raises(ValueError):
        sync_component_mapping({"package_scope": scope, "blocklist": {}})
    stored_scope = PackageScope.objects.get()
    assert stored_scope.ps_update_stream == "rhel-6-els"
    assert stored_scope.components == ["openssl"]
    assert BlocklistEntry.objects.filter(name="old").exists()
