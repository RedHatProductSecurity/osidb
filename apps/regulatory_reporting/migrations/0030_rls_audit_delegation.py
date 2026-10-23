"""
Delegate regulatory_reporting audit table RLS checks to source objects,
mirroring osidb/migrations/0277_rls_audit_delegation.py.

SRPReport and SRPReportMilestone audit rows previously relied on
ACLMixin.set_acls_history()/_set_related_acls_history() (removed by
osidb/migrations/0277_rls_audit_delegation.py) to propagate ACL changes
onto historical rows. Both audit tables are append-only — no UPDATE
policy has ever existed for them (only INSERT and SELECT) — so under
PostgreSQL's default-deny RLS behavior that propagation attempt was
already a silent no-op for any non-BYPASSRLS role; this is a pre-existing
bug, not one introduced by 0277. Delegating the SELECT policy to the live
source object fixes it without needing to make these tables mutable,
consistent with their append-only design.
"""

from django.db import migrations

# (audit_table, source_table, policy_prefix)
AUDIT_SOURCE_PAIRS = [
    (
        "regulatory_reporting_srpreportaudit",
        "regulatory_reporting_srpreport",
        "srpreportaudit",
    ),
    (
        "regulatory_reporting_srpreportmilestoneaudit",
        "regulatory_reporting_srpreportmilestone",
        "srpreportmilestoneaudit",
    ),
]

ACL_CHECK = "string_to_array(current_setting('osidb.acl'), ',')::uuid[]"


def _build_forward_sql():
    parts = []

    for _audit_table, source_table, _prefix in AUDIT_SOURCE_PAIRS:
        func_name = f"_rls_get_acl_read_{source_table}"
        # See osidb/migrations/0277_rls_audit_delegation.py for the
        # search_path/EXECUTE rationale; the same reasoning applies here.
        parts.append(f"""
CREATE OR REPLACE FUNCTION {func_name}(obj_id uuid)
RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = osidb_admin, public, pg_temp
AS $func$
    SELECT acl_read FROM {source_table} WHERE uuid = obj_id;
$func$;
""")

    for audit_table, source_table, prefix in AUDIT_SOURCE_PAIRS:
        coalesce_read = (
            f"COALESCE(_rls_get_acl_read_{source_table}(pgh_obj_id), acl_read)"
        )
        parts.append(f"""
-- {audit_table}: delegate ACL checks to source object.
-- Only the SELECT policy is rewritten: these tables are append-only
-- (no UPDATE/DELETE policy exists, matching their append-only trigger).
DROP POLICY IF EXISTS acl_policy_{prefix}_select ON {audit_table};
CREATE POLICY acl_policy_{prefix}_select ON {audit_table}
FOR SELECT
USING ({coalesce_read}::uuid[] && {ACL_CHECK});
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
""")

    for _audit_table, source_table, _prefix in AUDIT_SOURCE_PAIRS:
        parts.append(f"DROP FUNCTION IF EXISTS _rls_get_acl_read_{source_table}(uuid);")

    return "\n".join(parts)


class Migration(migrations.Migration):

    dependencies = [
        ("regulatory_reporting", "0029_srpreportmilestone_mitigation_fields"),
    ]

    operations = [
        migrations.RunSQL(
            sql=_build_forward_sql(),
            reverse_sql=_build_reverse_sql(),
        ),
    ]
