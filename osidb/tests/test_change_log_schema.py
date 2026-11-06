"""Append and ordinary-runtime maintenance also work in osidb_admin."""

import os
from uuid import uuid4

import pytest
from django.conf import settings
from django.db import connection
from psycopg import sql

from osidb.core import set_user_acls
from osidb.models import Flaw, FlawChangeEvent
from osidb.tasks import compact_flaw_change_events
from osidb.tests.factories import FlawFactory

pytestmark = [
    pytest.mark.unit,
    pytest.mark.enable_rls,
    pytest.mark.django_db(transaction=True),
]


def test_nonpublic_append_prune_and_hidden_parent_safety():
    set_user_acls(settings.ALL_GROUPS)
    public = FlawFactory(embargoed=False)
    hidden = FlawFactory(embargoed=True)
    owner = connection.copy()
    owner.settings_dict.update(
        USER=os.environ.get("OSIDB_TEST_MIGRATION_USER", "osidb_manage_user"),
        PASSWORD=os.environ.get(
            "OSIDB_TEST_MIGRATION_PASSWORD", connection.settings_dict["PASSWORD"]
        ),
    )
    assert owner.settings_dict["NAME"].startswith("test_")
    moved = []
    created = False
    try:
        with owner.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='osidb_admin')"
            )
            if not cursor.fetchone()[0]:
                cursor.execute("CREATE SCHEMA osidb_admin AUTHORIZATION CURRENT_USER")
                created = True
            cursor.execute(
                sql.SQL("GRANT USAGE ON SCHEMA osidb_admin TO {}").format(
                    sql.Identifier(connection.settings_dict["USER"])
                )
            )
            for name in ["osidb_flaw", "osidb_flawchangeevent"]:
                cursor.execute(
                    sql.SQL("ALTER TABLE public.{} SET SCHEMA osidb_admin").format(
                        sql.Identifier(name)
                    )
                )
                moved.append(name)
        with connection.cursor() as cursor:
            cursor.execute("SET search_path=osidb_admin,public")
            cursor.execute(
                "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user"
            )
            assert cursor.fetchone() == (False, False)
        Flaw.objects.filter(pk=public.pk).update(title="nonpublic append")
        assert FlawChangeEvent.objects.filter(flaw=public).count() == 2
        FlawChangeEvent.objects.create(
            flaw_id=uuid4(), local_updated_dt=public.local_updated_dt
        )
        set_user_acls(settings.PUBLIC_READ_GROUPS)
        assert not Flaw.objects.filter(pk=hidden.pk).exists()
        assert compact_flaw_change_events()["deleted"] == 2
        assert set(FlawChangeEvent.objects.values_list("flaw_id", flat=True)) == {
            public.pk,
            hidden.pk,
        }
        assert not Flaw.objects.filter(pk=hidden.pk).exists()
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SET search_path=public")
        with owner.cursor() as cursor:
            for name in reversed(moved):
                cursor.execute(
                    sql.SQL("ALTER TABLE osidb_admin.{} SET SCHEMA public").format(
                        sql.Identifier(name)
                    )
                )
            if created:
                cursor.execute("DROP SCHEMA osidb_admin")
        owner.close()
