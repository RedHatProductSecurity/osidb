import json
import subprocess
from unittest.mock import MagicMock

import pytest
from packageurl import PackageURL

from osidb.tasks import sync_flaw_affects_from_newcli
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


def _purls_from_newcli_payload(payload: dict) -> set[str]:
    return {dep["purls"][0] for dep in payload["deps"]}


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
