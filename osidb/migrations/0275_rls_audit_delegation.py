"""
Rewrite RLS policies on all audit tables to delegate ACL checks to the
source object via a COALESCE subselect, falling back to the audit row's
own acl_read/acl_write when the source object has been deleted.

This eliminates the need to propagate ACL changes to historical audit rows,
which was the primary source of lock contention during visibility widening
(OSIDB-5732).
"""

from django.db import migrations

# (audit_table, source_table, policy_prefix)
AUDIT_SOURCE_PAIRS = [
    ("osidb_flawaudit", "osidb_flaw", "flawaudit"),
    ("osidb_affectaudit", "osidb_affect", "affectaudit"),
    ("osidb_trackeraudit", "osidb_tracker", "trackeraudit"),
    ("osidb_flawacknowledgmentaudit", "osidb_flawacknowledgment", "flawacknowledgmentaudit"),
    ("osidb_flawreferenceaudit", "osidb_flawreference", "flawreferenceaudit"),
    ("osidb_flawcommentaudit", "osidb_flawcomment", "flawcommentaudit"),
    ("osidb_flawcvssaudit", "osidb_flawcvss", "flawcvssaudit"),
    ("osidb_affectcvssaudit", "osidb_affectcvss", "affectcvssaudit"),
    ("osidb_flawlabelv2audit", "osidb_flawlabelv2", "flawlabelv2audit"),
]

ACL_CHECK = "string_to_array(current_setting('osidb.acl'), ',')::uuid[]"


def _build_forward_sql():
    parts = []

    seen_source_tables = set()
    for _audit_table, source_table, _prefix in AUDIT_SOURCE_PAIRS:
        if source_table in seen_source_tables:
            continue
        seen_source_tables.add(source_table)
        for acl_col in ("acl_read", "acl_write"):
            func_name = f"_rls_get_{acl_col}_{source_table}"
            # Note: REVOKE is omitted because this is a controlled environment with only
            # two database users (osidb_admin and osidb_manage), both of which have
            # legitimate access to read these ACL columns. The SECURITY DEFINER wrapper
            # is used solely to bypass RLS when checking the source object's ACL, not to
            # restrict access. Exposure is minimal since the function only returns ACL
            # arrays that are already visible to any user who can query the audit table.
            parts.append(f"""
CREATE OR REPLACE FUNCTION {func_name}(obj_id uuid)
RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER
AS $func$
    SELECT {acl_col} FROM {source_table} WHERE uuid = obj_id;
$func$;
""")

    for audit_table, source_table, prefix in AUDIT_SOURCE_PAIRS:
        coalesce_read = (
            f"COALESCE("
            f"_rls_get_acl_read_{source_table}(pgh_obj_id), "
            f"acl_read)"
        )
        coalesce_write = (
            f"COALESCE("
            f"_rls_get_acl_write_{source_table}(pgh_obj_id), "
            f"acl_write)"
        )

        parts.append(f"""
-- {audit_table}: delegate ACL checks to source object
DROP POLICY IF EXISTS acl_policy_{prefix}_select ON {audit_table};
CREATE POLICY acl_policy_{prefix}_select ON {audit_table}
FOR SELECT
USING ({coalesce_read}::uuid[] && {ACL_CHECK});

DROP POLICY IF EXISTS acl_policy_{prefix}_update ON {audit_table};
CREATE POLICY acl_policy_{prefix}_update ON {audit_table}
FOR UPDATE
USING ({coalesce_write}::uuid[] && {ACL_CHECK})
WITH CHECK (
    {coalesce_read}::uuid[] && {ACL_CHECK}
    AND {coalesce_write}::uuid[] && {ACL_CHECK}
);

DROP POLICY IF EXISTS acl_policy_{prefix}_delete ON {audit_table};
CREATE POLICY acl_policy_{prefix}_delete ON {audit_table}
FOR DELETE
USING ({coalesce_write}::uuid[] && {ACL_CHECK});
""")
    return "\n".join(parts)


def _build_reverse_sql():
    parts = []
    for audit_table, _source_table, prefix in AUDIT_SOURCE_PAIRS:
        parts.append(f"""
-- {audit_table}: restore direct ACL checks
DROP POLICY IF EXISTS acl_policy_{prefix}_select ON {audit_table};
CREATE POLICY acl_policy_{prefix}_select ON {audit_table}
FOR SELECT
USING (acl_read::uuid[] && {ACL_CHECK});

DROP POLICY IF EXISTS acl_policy_{prefix}_update ON {audit_table};
CREATE POLICY acl_policy_{prefix}_update ON {audit_table}
FOR UPDATE
USING (acl_write::uuid[] && {ACL_CHECK})
WITH CHECK (
    acl_read::uuid[] && {ACL_CHECK}
    AND acl_write::uuid[] && {ACL_CHECK}
);

DROP POLICY IF EXISTS acl_policy_{prefix}_delete ON {audit_table};
CREATE POLICY acl_policy_{prefix}_delete ON {audit_table}
FOR DELETE
USING (acl_write::uuid[] && {ACL_CHECK});
""")

    seen_source_tables = set()
    for _audit_table, source_table, _prefix in AUDIT_SOURCE_PAIRS:
        if source_table in seen_source_tables:
            continue
        seen_source_tables.add(source_table)
        for acl_col in ("acl_read", "acl_write"):
            parts.append(
                f"DROP FUNCTION IF EXISTS _rls_get_{acl_col}_{source_table}(uuid);"
            )

    return "\n".join(parts)


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0274_remove_flaw_insert_insert_remove_flaw_update_update_and_more"),
    ]

    operations = [
        migrations.RunSQL(
            sql=_build_forward_sql(),
            reverse_sql=_build_reverse_sql(),
        ),
    ]
