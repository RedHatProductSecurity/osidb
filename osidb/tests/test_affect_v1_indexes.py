import pytest
from django.db import connection


@pytest.mark.django_db
def test_affect_v1_expected_indexes_exist():
    """
    Regression test:
    `affect_v1` is a materialized view. Dropping/recreating it drops all its indexes.
    Ensure the expected indexes exist after migrations.
    """
    if connection.vendor != "postgresql":
        pytest.skip("Index introspection test requires PostgreSQL")

    expected = {
        "affect_v1_uuid_idx",
        "affect_v1_flaw_id_idx",
        "affect_v1_sorting_idx",
        "affect_v1_all_tracker_ids_gin_idx",
    }

    with connection.cursor() as c:
        c.execute(
            """
            SELECT indexname
            FROM pg_indexes
            WHERE schemaname = current_schema()
              AND tablename = 'affect_v1'
            """
        )
        present = {row[0] for row in c.fetchall()}

    missing = expected - present
    assert not missing, f"Missing indexes on affect_v1: {sorted(missing)}"
