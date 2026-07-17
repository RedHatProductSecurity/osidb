"""
Enable RLS on the polymorphic FlawLabel child tables.

These tables (created in 0244_polymorphic_labels) don't carry their own
acl_read/acl_write columns - those live on the parent osidb_flawlabelv2
table, reached through a mandatory JOIN for most queries.

However, Django's queryset.count()/.exists() (and similarly minimal
queries) can compile to a query that only touches the child table, with
no JOIN to the parent at all, since no parent column ends up in the
SELECT list. Without RLS of their own, those child tables are wide open
regardless of the parent's ACLs. Give each child table a policy that
checks the corresponding parent row's ACLs directly.
"""

from django.db import migrations

PARENT_TABLE = "osidb_flawlabelv2"
FK_COLUMN = "flawlabel_ptr_id"

CHILD_TABLES = (
    ("osidb_aliaslabel", "aliaslabel"),
    ("osidb_bulabel", "bulabel"),
    ("osidb_collaboratorlabel", "collaboratorlabel"),
    ("osidb_productfamilylabel", "productfamilylabel"),
    ("osidb_workflowlabel", "workflowlabel"),
)


def _acl_check(alias, groups_col):
    return (
        f"{alias}.{groups_col}::uuid[] && "
        "string_to_array(current_setting('osidb.acl'), ',')::uuid[]"
    )


def _parent_acl_exists(table, *group_cols):
    checks = " AND ".join(_acl_check("p", col) for col in group_cols)
    return (
        f"EXISTS (SELECT 1 FROM {PARENT_TABLE} p "
        f"WHERE p.uuid = {table}.{FK_COLUMN} AND {checks})"
    )


def _child_rls_policy_sql(table: str, policy_prefix: str) -> str:
    return f"""
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS acl_policy_{policy_prefix}_create ON {table};
CREATE POLICY acl_policy_{policy_prefix}_create
ON {table}
FOR INSERT
WITH CHECK ({_parent_acl_exists(table, "acl_read", "acl_write")});
DROP POLICY IF EXISTS acl_policy_{policy_prefix}_select ON {table};
CREATE POLICY acl_policy_{policy_prefix}_select
ON {table}
FOR SELECT
USING ({_parent_acl_exists(table, "acl_read")});
DROP POLICY IF EXISTS acl_policy_{policy_prefix}_update ON {table};
CREATE POLICY acl_policy_{policy_prefix}_update
ON {table}
FOR UPDATE
USING ({_parent_acl_exists(table, "acl_write")})
WITH CHECK ({_parent_acl_exists(table, "acl_read", "acl_write")});
DROP POLICY IF EXISTS acl_policy_{policy_prefix}_delete ON {table};
CREATE POLICY acl_policy_{policy_prefix}_delete
ON {table}
FOR DELETE
USING ({_parent_acl_exists(table, "acl_write")});
"""


ENABLE_CHILD_TABLE_RLS_SQL = "".join(
    _child_rls_policy_sql(table, policy_prefix) for table, policy_prefix in CHILD_TABLES
)


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0263_affect_v1_add_embargoed"),
    ]

    operations = [
        migrations.RunSQL(
            sql=ENABLE_CHILD_TABLE_RLS_SQL,
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
