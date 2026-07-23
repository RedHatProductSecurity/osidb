from django.db import migrations


def _rls_policy_sql(table: str, policy_prefix: str) -> str:
    return f"""
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on {table} entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_{policy_prefix}_create on {table};
create policy acl_policy_{policy_prefix}_create
on {table}
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_{policy_prefix}_select on {table};
create policy acl_policy_{policy_prefix}_select
on {table}
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_{policy_prefix}_update on {table};
create policy acl_policy_{policy_prefix}_update
on {table}
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_{policy_prefix}_delete on {table};
create policy acl_policy_{policy_prefix}_delete
on {table}
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
"""


CHILD_ACL_TABLES = (
    ("osidb_flawcvss", "flawcvss"),
    ("osidb_affectcvss", "affectcvss"),
    ("osidb_flawcomment", "flawcomment"),
    ("osidb_flawreference", "flawreference"),
    ("osidb_flawacknowledgment", "flawacknowledgment"),
    ("osidb_package", "package"),
    ("osidb_snippet", "snippet"),
    ("osidb_upstreamdata", "upstreamdata"),
)

ENABLE_CHILD_ACL_TABLE_RLS_SQL = "".join(
    _rls_policy_sql(table, policy_prefix) for table, policy_prefix in CHILD_ACL_TABLES
)


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0245_migrate_labels_to_v2"),
    ]

    operations = [
        migrations.RunSQL(
            reverse_sql=migrations.RunSQL.noop,
            sql=ENABLE_CHILD_ACL_TABLE_RLS_SQL,
        ),
    ]
