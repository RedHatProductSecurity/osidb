"""RHEL 6 scope data must never fail into an empty exclusion list."""

import pytest

from ..core import sync_component_mapping
from ..els import _package_name, rhel6_els_in_scope, rhel6_els_names
from ..models import BlocklistEntry, Rhel6ElsPackage

pytestmark = pytest.mark.unit

ELS = {
    "packages": ["openssl", "krb5-libs", "vim-enhanced", "yum", "unmatched-published"],
    "source_package_aliases": {
        "krb5-libs": "krb5",
        "krb5-workstation": "krb5",
        "vim-enhanced": "vim",
        "vim-common": "vim",
        "unrelated-libs": "unrelated",
    },
}


def test_expand_only_published_rpm_families():
    """Expand published source families without admitting unrelated aliases."""
    assert rhel6_els_names(ELS) == {
        "openssl",
        "krb5-libs",
        "krb5",
        "krb5-workstation",
        "vim-enhanced",
        "vim",
        "vim-common",
        "yum",
        "unmatched-published",
    }


def test_rpm_names_normalized_consistently():
    """Published RPM names use the same lowercase form as lookups."""
    assert rhel6_els_names({"packages": ["MAKEDEV"], "source_package_aliases": {}}) == {
        "makedev"
    }


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {"packages": []},
        {"packages": [], "source_package_aliases": {}},
        {"packages": "openssl", "source_package_aliases": {}},
        {"packages": [None], "source_package_aliases": {}},
        {"packages": [" "], "source_package_aliases": {}},
        {"packages": ["openssl"], "source_package_aliases": []},
        {"packages": ["openssl"], "source_package_aliases": {"bad": 12}},
        {"packages": ["openssl"], "source_package_aliases": {"x": "y", "X": "z"}},
        {"packages": ["x"], "source_package_aliases": {"x": "y", "y": "x"}},
    ],
)
def test_reject_invalid_els_data(data):
    """Reject malformed sections and ambiguous or indirect source aliases."""
    with pytest.raises(ValueError):
        rhel6_els_names(data)


@pytest.mark.django_db
def test_sync_els_and_preserve_on_old_bundle():
    """Repeated syncs are idempotent and older bundles retain known coverage."""
    counts = sync_component_mapping({"rhel6_els_packages": ELS})
    assert counts["rhel6_els_packages"] == 9
    assert rhel6_els_in_scope("krb5") is True
    assert rhel6_els_in_scope("vim-common") is True
    assert rhel6_els_in_scope("perl-DBI") is False
    assert rhel6_els_in_scope("dnf") is False
    sync_component_mapping({})
    assert Rhel6ElsPackage.objects.count() == 9
    sync_component_mapping({"rhel6_els_packages": ELS})
    assert Rhel6ElsPackage.objects.count() == 9


@pytest.mark.django_db
@pytest.mark.parametrize(
    "section",
    [
        {"packages": []},
        {"packages": ["open\nssl"], "source_package_aliases": {}},
        {"packages": ["openssl"], "source_package_aliases": {"bad\tname": "openssl"}},
        {"packages": ["openssl"], "source_package_aliases": {"alias": "bad/source"}},
    ],
)
def test_invalid_payload_preserves_all_previous_tables(section):
    """Invalid packages or aliases cannot replace any last-known-good data."""
    sync_component_mapping({"rhel6_els_packages": ELS, "blocklist": {"old": "reason"}})
    with pytest.raises(ValueError):
        sync_component_mapping({"rhel6_els_packages": section, "blocklist": {}})
    assert Rhel6ElsPackage.objects.count() == 9
    assert BlocklistEntry.objects.filter(name="old").exists()


@pytest.mark.django_db
def test_valid_update_replaces_membership():
    """A valid new section replaces obsolete coverage entries."""
    sync_component_mapping({"rhel6_els_packages": ELS})
    sync_component_mapping(
        {"rhel6_els_packages": {"packages": ["openssl"], "source_package_aliases": {}}}
    )
    assert list(Rhel6ElsPackage.objects.values_list("name", flat=True)) == ["openssl"]


@pytest.mark.django_db
def test_first_install_is_unknown():
    """Missing catalog data or a missing component never means excluded."""
    assert rhel6_els_in_scope("perl-DBI") is None
    Rhel6ElsPackage.objects.create(name="openssl")
    assert rhel6_els_in_scope("") is None


@pytest.mark.parametrize(
    "name",
    [
        "openssl",
        "perl-DBI",
        "libstdc++",
        "python2.7",
        "pkg_name",
        "MAKEDEV",
        "A" * 512,
    ],
)
def test_valid_package_names(name):
    """Accept supported ASCII punctuation, case, and the length boundary."""
    assert _package_name(name) == name.lower()


@pytest.mark.parametrize(
    "name",
    [
        None,
        1,
        "",
        " ",
        " openssl",
        "openssl ",
        "open ssl",
        "open\nssl",
        "openssl\n",
        "open\tssl",
        "open\rssl",
        "open\x00ssl",
        "open/ssl",
        "open:ssl",
        "open@ssl",
        "open%ssl",
        "öpenSSL",
        "İ" * 512,
        "a" * 513,
    ],
)
def test_invalid_package_names(name):
    """Reject whitespace, controls, non-ASCII, unsupported punctuation and overflow."""
    with pytest.raises(ValueError, match="Invalid RHEL 6 ELS package name"):
        _package_name(name)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "names, component, expected",
    [
        ([], "openssl", None),
        (["openssl"], "OpenSSL", True),
        (["openssl"], "perl-DBI", False),
    ],
)
def test_lookup_uses_one_snapshot(
    django_assert_num_queries, names, component, expected
):
    """Return tri-state membership in one query without transferring the catalog."""
    Rhel6ElsPackage.objects.bulk_create([Rhel6ElsPackage(name=name) for name in names])
    with django_assert_num_queries(1) as queries:
        assert rhel6_els_in_scope(component) is expected
    assert "EXISTS(" in queries.captured_queries[0]["sql"]
    assert "LIMIT 1" in queries.captured_queries[0]["sql"]


@pytest.mark.django_db
def test_missing_component_does_not_query(django_assert_num_queries):
    """An empty component is unknown without consulting the catalog."""
    with django_assert_num_queries(0):
        assert rhel6_els_in_scope("") is None
