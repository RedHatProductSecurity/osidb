"""Real PostgreSQL writes discovered through both versions of the public API."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Event

import pytest
from django.conf import settings as django_settings
from django.db import connection, connections, transaction
from django.db.models import F
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from osidb.acls import ACL
from osidb.core import (
    restore_user_acl_session,
    set_user_acls,
    snapshot_user_acl_session,
)
from osidb.models import (
    Affect,
    AliasLabel,
    CollaboratorLabel,
    CollaboratorLabelDefinition,
    Flaw,
    FlawChangeEvent,
    FlawCVSS,
    FlawSource,
    Impact,
    NotAffectedJustification,
    Tracker,
)
from osidb.tests.event_helpers import latest_event, reset_events
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.enable_signals,
    pytest.mark.django_db(transaction=True),
]


def db_time():
    with connection.cursor() as cursor:
        cursor.execute("SELECT statement_timestamp()")
        return cursor.fetchone()[0]


def timestamps(instance):
    fields = ["created_dt", "updated_dt"]
    if isinstance(instance, Flaw):
        fields.append("local_updated_dt")
    return type(instance).objects.filter(pk=instance.pk).values(*fields).get()


@pytest.fixture
def graph():
    flaw = FlawFactory(
        embargoed=False,
        source=FlawSource.CUSTOMER,
        impact=Impact.LOW,
        major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
    )
    module = PsModuleFactory(bts_name="bugzilla", private_trackers_allowed=True)
    stream = PsUpdateStreamFactory(ps_module=module)
    affect = AffectFactory(
        flaw=flaw,
        ps_module=module.name,
        ps_update_stream=stream.name,
        affectedness=Affect.AffectAffectedness.NEW,
        resolution=Affect.AffectResolution.NOVALUE,
        impact=Impact.LOW,
        not_affected_justification="",
    )
    return flaw, affect


@pytest.fixture(params=["v1", "v2"])
def api(request, auth_client, refresh_v1_view, settings):
    settings.OSIDB_USE_FLAW_WATERMARK = True
    acl = snapshot_user_acl_session()
    try:
        client = auth_client()
    finally:
        restore_user_acl_session(acl)
    base = f"/osidb/api/{request.param}/flaws"

    def get(path="", **params):
        acl = snapshot_user_acl_session()
        try:
            response = client.get(base + path, params)
        finally:
            restore_user_acl_session(acl)
        assert response.status_code == 200, response.content
        return response.json()

    def refresh():
        if request.param == "v1":
            refresh_v1_view()

    return get, refresh


def assert_discovered(get, flaw, old, new):
    for id_type, key in (("uuid", str(flaw.pk)), ("cve_id", flaw.cve_id)):
        pairs = dict(get("/index", id_type=id_type)["results"])
        assert datetime.fromisoformat(pairs[key]) == new
    params = {
        "changed_after": (old + (new - old) / 2).isoformat(),
        "changed_before": new.isoformat(),
    }
    body = get(**params)
    assert body["count"] == 1
    assert [row["uuid"] for row in body["results"]] == [str(flaw.pk)]
    params["changed_before"] = (new - timedelta(microseconds=1)).isoformat()
    assert get(**params)["count"] == 0


@pytest.mark.parametrize("writer", ["update", "bulk_update", "raw_sql"])
@pytest.mark.parametrize("justification_only", [False, True])
def test_bypass_save_write_is_discovered(graph, api, writer, justification_only):
    flaw, affect = graph
    get, refresh = api
    if justification_only:
        Affect.objects.filter(pk=affect.pk).update(
            auto_timestamps=False,
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
            not_affected_justification=NotAffectedJustification.COMPONENT_NOT_PRESENT,
        )
    control = FlawFactory(embargoed=False)
    refresh()
    old = db_time() - timedelta(days=2)
    reset_events([flaw, control], old)
    before = timestamps(flaw), timestamps(affect)
    changes = {
        "not_affected_justification": NotAffectedJustification.VULN_CODE_NOT_PRESENT,
    }
    if not justification_only:
        changes["affectedness"] = Affect.AffectAffectedness.NOTAFFECTED
    lower = db_time()
    if writer == "update":
        assert (
            Affect.objects.filter(pk=affect.pk).update(auto_timestamps=False, **changes)
            == 1
        )
    elif writer == "bulk_update":
        affect.refresh_from_db()
        for name, value in changes.items():
            setattr(affect, name, value)
        assert Affect.objects.bulk_update([affect], [*changes, "updated_dt"]) == 1
    else:
        assignments = ", ".join(f'"{name}" = %s' for name in changes)
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE osidb_affect SET {assignments} WHERE uuid = %s",
                [*changes.values(), affect.pk],
            )
            assert cursor.rowcount == 1
    new = latest_event(flaw).local_updated_dt
    assert old < lower <= new <= db_time()
    assert latest_event(control).local_updated_dt == old
    assert (timestamps(flaw), timestamps(affect)) == before
    refresh()
    assert_discovered(get, flaw, old, new)
    for identity in (str(flaw.pk), flaw.cve_id):
        body = get(f"/{identity}")
        assert datetime.fromisoformat(body["updated_dt"]) == before[0]["updated_dt"]
        assert "local_updated_dt" not in body and "change_events" not in body
        assert len(body["affects"]) == 1
        for name, value in changes.items():
            assert body["affects"][0][name] == value
    with override_settings(OSIDB_USE_FLAW_WATERMARK=False):
        pairs = dict(get("/index")["results"])
        assert (
            datetime.fromisoformat(pairs[str(flaw.pk)]) == before[0]["local_updated_dt"]
        )
        # Both legacy predicates still operate after a real bypass-save write.
        assert (
            get(
                uuid=str(flaw.pk),
                changed_before=before[0]["local_updated_dt"].isoformat(),
            )["count"]
            == 1
        )
    assert latest_event(flaw).local_updated_dt == new


def make_child(kind, flaw, affect):
    if kind == "tracker":
        return TrackerFactory(
            affects=[affect],
            embargoed=False,
            type=Tracker.TrackerType.BUGZILLA,
            ps_update_stream=affect.ps_update_stream,
        ), {"status": "read regression status"}
    if kind in ("cvss", "affect_cvss"):
        factory = FlawCVSSFactory if kind == "cvss" else AffectCVSSFactory
        parent = {"flaw": flaw} if kind == "cvss" else {"affect": affect}
        return factory(
            **parent,
            issuer=FlawCVSS.CVSSIssuer.NIST,
            version=FlawCVSS.CVSSVersion.VERSION3,
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ), {"vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"}
    if kind == "reference":
        return FlawReferenceFactory(flaw=flaw), {"description": "changed reference"}
    if kind == "acknowledgment":
        return FlawAcknowledgmentFactory(flaw=flaw), {"name": "Changed Reporter"}
    if kind == "comment":
        return FlawCommentFactory(flaw=flaw), {"text": "changed comment"}
    if kind == "alias":
        return AliasLabel.objects.create(flaw=flaw, name="old-alias"), {
            "name": "new-alias"
        }
    assert kind == "collaborator"
    CollaboratorLabelDefinition.objects.create(name="read-regression")
    return CollaboratorLabel.objects.create(flaw=flaw, name="read-regression"), {
        "state": CollaboratorLabel.State.REQ,
    }


@pytest.mark.parametrize(
    "kind",
    [
        "tracker",
        "cvss",
        "affect_cvss",
        "reference",
        "acknowledgment",
        "comment",
        "alias",
        "collaborator",
    ],
)
@pytest.mark.parametrize("writer", ["update", "save"])
def test_child_changes_reach_index_and_window(graph, api, kind, writer):
    flaw, affect = graph
    child, changes = make_child(kind, flaw, affect)
    control = FlawFactory(embargoed=False)
    get, refresh = api
    refresh()
    old = db_time() - timedelta(days=2)
    reset_events([flaw, control], old)
    before = timestamps(flaw), timestamps(child)
    lower = db_time()
    if writer == "update":
        assert (
            type(child)
            .objects.filter(pk=child.pk)
            .update(updated_dt=F("updated_dt"), **changes)
            == 1
        )
    else:
        child.refresh_from_db()
        for name, value in changes.items():
            setattr(child, name, value)
        child.save()
    new = latest_event(flaw).local_updated_dt
    assert old < lower <= new <= db_time()
    assert latest_event(control).local_updated_dt == old
    child.refresh_from_db()
    for name, value in changes.items():
        assert getattr(child, name) == value
    if writer == "update":
        assert (timestamps(flaw), timestamps(child)) == before
    elif kind in ("cvss", "affect_cvss"):
        # Real pre_save business callback still recomputes the derived score.
        assert child.score == 3.8
    refresh()
    assert_discovered(get, flaw, old, new)


def test_bookkeeping_noop_and_visibility_tradeoff(graph, api):
    flaw, affect = graph
    get, refresh = api
    old = db_time() - timedelta(days=2)
    reset_events([flaw], old)
    for changes in (
        {"meta_attr": {"read-regression": "bookkeeping"}},
        {"last_validated_dt": db_time()},
        {"affectedness": affect.affectedness},
        {"acl_write": ACL.INTERNAL.uuid_write},
        {"acl_read": sorted(set(ACL.PUBLIC.uuid_read + ACL.INTERNAL.uuid_read))},
    ):
        Affect.objects.filter(pk=affect.pk).update(auto_timestamps=False, **changes)
        assert latest_event(flaw).local_updated_dt == old
    Affect.objects.filter(pk=affect.pk).update(
        auto_timestamps=False,
        acl_read=ACL.INTERNAL.uuid_read,
        acl_write=ACL.INTERNAL.uuid_write,
    )
    new = latest_event(flaw).local_updated_dt
    assert new > old
    refresh()
    assert_discovered(get, flaw, old, new)


@pytest.mark.enable_rls
@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("enabled", [False, True])
def test_index_identity_rendering_rls_order_and_latest_trap(version, enabled, settings):
    settings.OSIDB_USE_FLAW_WATERMARK = enabled
    set_user_acls(django_settings.ALL_GROUPS)
    a = FlawFactory(embargoed=False, cve_id="CVE-2026-7654324")
    b = FlawFactory(embargoed=False, cve_id=None)
    hidden = FlawFactory(embargoed=True)
    at = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    quiet = at - timedelta(days=3650)
    reset_events([a], at + timedelta(hours=10))
    FlawChangeEvent.objects.create(flaw=a, local_updated_dt=at + timedelta(hours=12))
    reset_events([b], quiet)
    expected = [
        str(pk)
        for pk in Flaw.objects.filter(pk__in=[a.pk, b.pk]).values_list("pk", flat=True)
    ]
    legacy = Flaw.objects.get(pk=b.pk).local_updated_dt
    client = APIClient()
    base = f"/osidb/api/{version}/flaws"
    response = client.get(base + "/index")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"results", "dt", "env", "revision", "version"}
    pairs = body["results"]
    assert [row[0] for row in pairs] == expected
    selected = quiet if enabled else legacy
    assert dict(pairs)[str(b.pk)] == selected.isoformat().replace("+00:00", "Z")
    assert str(hidden.pk) not in dict(pairs)
    if enabled:
        response = client.get(
            base,
            {
                "changed_after": (at + timedelta(hours=9)).isoformat(),
                "changed_before": (at + timedelta(hours=11)).isoformat(),
            },
        )
        assert response.status_code == 200 and response.json()["count"] == 0
    pages = [
        client.get(base, {"limit": 1, "offset": n, "include_fields": "uuid"}).json()
        for n in (0, 1)
    ]
    assert [p["count"] for p in pages] == [2, 2]
    assert [p["results"][0]["uuid"] for p in pages] == expected
    set_user_acls(django_settings.ALL_GROUPS)
    Flaw.objects.filter(pk=a.pk).update(cve_id="CVE-2026-7654325")
    assert [
        row[0]
        for row in client.get(base + "/index", {"id_type": "cve_id"}).json()["results"]
    ] == ["CVE-2026-7654325"]
    set_user_acls(django_settings.ALL_GROUPS)
    Flaw.objects.filter(pk=a.pk).update(cve_id=None)
    assert client.get(base + "/index", {"id_type": "cve_id"}).json()["results"] == []
    set_user_acls(django_settings.ALL_GROUPS)


@pytest.mark.parametrize("commit", [False, True])
def test_concurrent_writer_api_visibility_is_atomic(graph, api, commit):
    """Separate real connections: uncommitted content/events never leak to API."""
    flaw, affect = graph
    get, refresh = api
    refresh()
    old = db_time() - timedelta(days=2)
    reset_events([flaw], old)
    before = timestamps(flaw), timestamps(affect)
    written, release = Event(), Event()

    def writer():
        connections.close_all()
        try:
            set_user_acls(django_settings.ALL_GROUPS)
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL statement_timeout = '10s'")
                    cursor.execute("SET LOCAL lock_timeout = '2s'")
                Affect.objects.filter(pk=affect.pk).update(
                    auto_timestamps=False,
                    affectedness=Affect.AffectAffectedness.NOTAFFECTED,
                    not_affected_justification=NotAffectedJustification.COMPONENT_NOT_PRESENT,
                )
                new = latest_event(flaw).local_updated_dt
                assert new > old
                written.set()
                assert release.wait(15), "API reader did not release writer"
                if not commit:
                    transaction.set_rollback(True)
            return new
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        try:
            assert written.wait(15), "writer did not reach uncommitted state"
            for id_type, key in (("uuid", str(flaw.pk)), ("cve_id", flaw.cve_id)):
                assert (
                    datetime.fromisoformat(
                        dict(get("/index", id_type=id_type)["results"])[key]
                    )
                    == old
                )
            assert (
                get(changed_after=(old + timedelta(days=1)).isoformat())["count"] == 0
            )
            assert (
                get(f"/{flaw.pk}")["affects"][0]["affectedness"] == affect.affectedness
            )
        finally:
            release.set()
        new = future.result(timeout=20)
    refresh()
    if commit:
        assert_discovered(get, flaw, old, new)
        assert (
            get(f"/{flaw.pk}")["affects"][0]["affectedness"]
            == Affect.AffectAffectedness.NOTAFFECTED
        )
    else:
        assert latest_event(flaw).local_updated_dt == old
        assert get(changed_after=(old + timedelta(days=1)).isoformat())["count"] == 0
        assert get(f"/{flaw.pk}")["affects"][0]["affectedness"] == affect.affectedness
    assert (timestamps(flaw), timestamps(affect)) == before
