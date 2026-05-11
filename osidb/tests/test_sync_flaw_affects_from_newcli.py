import json
import subprocess
from unittest.mock import MagicMock

import pytest
from packageurl import PackageURL

from osidb.tasks import sync_flaw_affects_from_newcli
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


def _purls_from_newcli_payload(payload: dict) -> set[str]:
    """Return the first PURL from every entry in both ``builds`` and ``deps``."""
    entries = list(payload.get("builds") or []) + list(payload.get("deps") or [])
    return {entry["purls"][0] for entry in entries if entry.get("purls")}


def test_sync_flaw_affects_from_newcli_creates_one_affect_per_dep(
    newcli_urllib3_hummingbird1_json, monkeypatch
):
    flaw = FlawFactory(components=["urllib3"])
    expected_purls = _purls_from_newcli_payload(newcli_urllib3_hummingbird1_json)

    def fake_run(cmd, **kwargs):
        assert cmd == [
            "newcli",
            "-s",
            "urllib3",
            "--include",
            "hummingbird-1",
            "--json",
        ]
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps(newcli_urllib3_hummingbird1_json),
            stderr="",
        )

    monkeypatch.setattr("osidb.tasks.subprocess.run", fake_run)

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    n_deps = len(newcli_urllib3_hummingbird1_json["deps"])
    assert stats == {"created": n_deps, "skipped": 0, "skipped_existing": 0}
    assert flaw.affects.count() == n_deps

    stored = {
        str(a.purl) for a in list(flaw.affects.filter(ps_update_stream="hummingbird-1"))
    }
    normalized_expected = {
        PackageURL.from_string(p).to_string() for p in expected_purls
    }
    assert stored == normalized_expected


def test_sync_flaw_affects_from_newcli_runs_newcli_per_flaw_component(
    newcli_urllib3_hummingbird1_json,
    newcli_openssl_hummingbird1_json,
    monkeypatch,
):
    """
    Each flaw component gets its own ``newcli -s <component>`` call; payloads are merged into
    one set of affects. The openssl sample repeats the python-cryptography PURL from urllib3,
    so that row is skipped as already existing.
    """
    flaw = FlawFactory(components=["urllib3", "openssl"])
    newcli_s_order = []

    def fake_run(cmd, **kwargs):
        component = cmd[2]
        newcli_s_order.append(component)
        if component == "urllib3":
            payload = newcli_urllib3_hummingbird1_json
        elif component == "openssl":
            payload = newcli_openssl_hummingbird1_json
        else:
            raise AssertionError(f"unexpected newcli -s {component!r}")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr("osidb.tasks.subprocess.run", fake_run)

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert newcli_s_order == ["urllib3", "openssl"]
    n_urllib3 = len(newcli_urllib3_hummingbird1_json["deps"])
    assert stats == {
        "created": n_urllib3,
        "skipped": 0,
        "skipped_existing": 1,
    }
    assert flaw.affects.count() == n_urllib3


def test_sync_flaw_affects_from_newcli_skips_existing(
    newcli_urllib3_hummingbird1_json, monkeypatch
):
    flaw = FlawFactory(components=["urllib3"])
    n_deps = len(newcli_urllib3_hummingbird1_json["deps"])

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps(newcli_urllib3_hummingbird1_json),
            stderr="",
        )

    monkeypatch.setattr("osidb.tasks.subprocess.run", fake_run)

    assert sync_flaw_affects_from_newcli(str(flaw.uuid)) == {
        "created": n_deps,
        "skipped": 0,
        "skipped_existing": 0,
    }
    assert sync_flaw_affects_from_newcli(str(flaw.uuid)) == {
        "created": 0,
        "skipped": 0,
        "skipped_existing": n_deps,
    }


def test_sync_flaw_affects_from_newcli_no_components_raises(monkeypatch):
    flaw = FlawFactory(components=[])

    monkeypatch.setattr(
        "osidb.tasks.subprocess.run",
        MagicMock(side_effect=AssertionError("newcli should not run")),
    )

    with pytest.raises(ValueError, match="no non-empty components"):
        sync_flaw_affects_from_newcli(str(flaw.uuid))


def test_sync_flaw_affects_from_newcli_includes_build_as_affect(
    newcli_ostree_hummingbird1_json, monkeypatch
):
    """
    When newcli returns a non-empty ``builds`` list, an affect is created for each build entry
    in addition to any ``deps`` entries.

    For ``newcli -s ostree --include hummingbird-1``, the payload contains:
    - one ``builds`` entry: ostree (the searched component itself)
    - one ``deps`` entry: bootc (which bundles ostree as a cargo dependency)

    Both should result in separate affects on the flaw.
    """
    flaw = FlawFactory(components=["ostree"])

    def fake_run(cmd, **kwargs):
        assert cmd == [
            "newcli",
            "-s",
            "ostree",
            "--include",
            "hummingbird-1",
            "--json",
        ]
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps(newcli_ostree_hummingbird1_json),
            stderr="",
        )

    monkeypatch.setattr("osidb.tasks.subprocess.run", fake_run)

    n_builds = len(newcli_ostree_hummingbird1_json["builds"])  # 1 (ostree)
    n_deps = len(newcli_ostree_hummingbird1_json["deps"])  # 1 (bootc)
    expected_total = n_builds + n_deps  # 2

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert stats == {"created": expected_total, "skipped": 0, "skipped_existing": 0}
    assert flaw.affects.count() == expected_total

    stored = {
        str(a.purl) for a in flaw.affects.filter(ps_update_stream="hummingbird-1")
    }
    expected_purls = _purls_from_newcli_payload(newcli_ostree_hummingbird1_json)
    normalized_expected = {
        PackageURL.from_string(p).to_string() for p in expected_purls
    }
    assert stored == normalized_expected


def test_sync_flaw_affects_from_newcli_multi_builds_with_duplicate(
    newcli_openssl_multi_builds_json, monkeypatch
):
    """
    Multiple ``builds`` entries across different streams, including a same-stream duplicate,
    are all processed correctly.

    Fixture layout (4 builds + 2 deps):
    - builds[0]: hummingbird-1 / openssl            → created
    - builds[1]: rhel-9.8.z   / openssl (3.5.1-7)  → created  (first encounter)
    - builds[2]: rhel-9.8.z   / openssl (3.5.5-1)  → skipped_existing (same stream+component)
    - builds[3]: rhel-8.8.0.z / openssl (1.1.1k)   → created
    - deps[0]:   hummingbird-1 / bootc              → created
    - deps[1]:   hummingbird-1 / chunkah            → created

    Expected: created=5, skipped=0, skipped_existing=1.
    Running a second time should mark all 5 as skipped_existing.
    """
    flaw = FlawFactory(components=["openssl"])

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps(newcli_openssl_multi_builds_json),
            stderr="",
        )

    monkeypatch.setattr("osidb.tasks.subprocess.run", fake_run)

    stats = sync_flaw_affects_from_newcli(str(flaw.uuid))
    assert stats == {"created": 5, "skipped": 0, "skipped_existing": 1}
    assert flaw.affects.count() == 5

    # Group stored components by stream to allow multiple affects per stream
    from collections import defaultdict

    stored_by_stream = defaultdict(set)
    for a in flaw.affects.all():
        stored_by_stream[a.ps_update_stream].add(
            PackageURL.from_string(str(a.purl)).name
        )

    # hummingbird-1: one build (openssl) + two deps (bootc, chunkah)
    assert stored_by_stream["hummingbird-1"] == {"openssl", "bootc", "chunkah"}
    # rhel-9.8.z: only the first openssl build (duplicate skipped)
    assert stored_by_stream["rhel-9.8.z"] == {"openssl"}
    # rhel-8.8.0.z: one openssl build
    assert stored_by_stream["rhel-8.8.0.z"] == {"openssl"}

    # Second run: all 6 raw entries (4 builds + 2 deps) find existing affects.
    # The duplicate rhel-9.8.z build also matches the affect created by the first encounter,
    # so skipped_existing is 6, not 5.
    stats2 = sync_flaw_affects_from_newcli(str(flaw.uuid))
    assert stats2 == {"created": 0, "skipped": 0, "skipped_existing": 6}
    assert flaw.affects.count() == 5


def test_sync_flaw_affects_from_newcli_include_modules_from_env(
    newcli_urllib3_hummingbird1_json, monkeypatch
):
    monkeypatch.setenv(
        "OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES",
        '["hummingbird-1","rhel-9"]',
    )
    flaw = FlawFactory(components=["urllib3"])

    seen_include = []

    def fake_run(cmd, **kwargs):
        seen_include.append(cmd[4])
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps(newcli_urllib3_hummingbird1_json),
            stderr="",
        )

    monkeypatch.setattr("osidb.tasks.subprocess.run", fake_run)

    sync_flaw_affects_from_newcli(str(flaw.uuid))

    assert seen_include == ["hummingbird-1,rhel-9"]
