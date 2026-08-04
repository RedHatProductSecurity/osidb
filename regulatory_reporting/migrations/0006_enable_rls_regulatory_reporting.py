from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("regulatory_reporting", "0005_upstreamproject_purl"),
    ]

    operations = [
        migrations.RunSQL(
            reverse_sql=migrations.RunSQL.noop,
            sql="""
    --enable row based security for srpreport entity table
    ALTER TABLE regulatory_reporting_srpreport ENABLE ROW LEVEL SECURITY;
    ALTER TABLE regulatory_reporting_srpreport FORCE ROW LEVEL SECURITY;
    --following policies define fine grained read/write control on srpreport entity
    --policy for entity insert (eg. create)
    DROP policy if exists acl_policy_srpreport_create on regulatory_reporting_srpreport;
    create policy acl_policy_srpreport_create
    on regulatory_reporting_srpreport
    for INSERT
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity select
    DROP policy if exists acl_policy_srpreport_select on regulatory_reporting_srpreport;
    create policy acl_policy_srpreport_select
    on regulatory_reporting_srpreport
    for select
    USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
    --policy for entity update
    DROP policy if exists acl_policy_srpreport_update on regulatory_reporting_srpreport;
    create policy acl_policy_srpreport_update
    on regulatory_reporting_srpreport
    for update
    USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity delete
    DROP policy if exists acl_policy_srpreport_delete on regulatory_reporting_srpreport;
    create policy acl_policy_srpreport_delete
    on regulatory_reporting_srpreport
    for delete
    USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

    --enable row based security for srpreportmilestone entity table
    ALTER TABLE regulatory_reporting_srpreportmilestone ENABLE ROW LEVEL SECURITY;
    ALTER TABLE regulatory_reporting_srpreportmilestone FORCE ROW LEVEL SECURITY;
    --following policies define fine grained read/write control on srpreportmilestone entity
    --policy for entity insert (eg. create)
    DROP policy if exists acl_policy_srpreportmilestone_create on regulatory_reporting_srpreportmilestone;
    create policy acl_policy_srpreportmilestone_create
    on regulatory_reporting_srpreportmilestone
    for INSERT
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity select
    DROP policy if exists acl_policy_srpreportmilestone_select on regulatory_reporting_srpreportmilestone;
    create policy acl_policy_srpreportmilestone_select
    on regulatory_reporting_srpreportmilestone
    for select
    USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
    --policy for entity update
    DROP policy if exists acl_policy_srpreportmilestone_update on regulatory_reporting_srpreportmilestone;
    create policy acl_policy_srpreportmilestone_update
    on regulatory_reporting_srpreportmilestone
    for update
    USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity delete
    DROP policy if exists acl_policy_srpreportmilestone_delete on regulatory_reporting_srpreportmilestone;
    create policy acl_policy_srpreportmilestone_delete
    on regulatory_reporting_srpreportmilestone
    for delete
    USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

    --enable row based security for upstreamnotification entity table
    ALTER TABLE regulatory_reporting_upstreamnotification ENABLE ROW LEVEL SECURITY;
    ALTER TABLE regulatory_reporting_upstreamnotification FORCE ROW LEVEL SECURITY;
    --following policies define fine grained read/write control on upstreamnotification entity
    --policy for entity insert (eg. create)
    DROP policy if exists acl_policy_upstreamnotification_create on regulatory_reporting_upstreamnotification;
    create policy acl_policy_upstreamnotification_create
    on regulatory_reporting_upstreamnotification
    for INSERT
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity select
    DROP policy if exists acl_policy_upstreamnotification_select on regulatory_reporting_upstreamnotification;
    create policy acl_policy_upstreamnotification_select
    on regulatory_reporting_upstreamnotification
    for select
    USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
    --policy for entity update
    DROP policy if exists acl_policy_upstreamnotification_update on regulatory_reporting_upstreamnotification;
    create policy acl_policy_upstreamnotification_update
    on regulatory_reporting_upstreamnotification
    for update
    USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity delete
    DROP policy if exists acl_policy_upstreamnotification_delete on regulatory_reporting_upstreamnotification;
    create policy acl_policy_upstreamnotification_delete
    on regulatory_reporting_upstreamnotification
    for delete
    USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

    --enable row based security for srpreportaudit entity table (append-only)
    ALTER TABLE regulatory_reporting_srpreportaudit ENABLE ROW LEVEL SECURITY;
    ALTER TABLE regulatory_reporting_srpreportaudit FORCE ROW LEVEL SECURITY;
    --following policies define read/insert control on srpreportaudit entity (append-only)
    --policy for entity insert (eg. create)
    DROP policy if exists acl_policy_srpreportaudit_create on regulatory_reporting_srpreportaudit;
    create policy acl_policy_srpreportaudit_create
    on regulatory_reporting_srpreportaudit
    for INSERT
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity select
    DROP policy if exists acl_policy_srpreportaudit_select on regulatory_reporting_srpreportaudit;
    create policy acl_policy_srpreportaudit_select
    on regulatory_reporting_srpreportaudit
    for select
    USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

    --enable row based security for srpreportmilestoneaudit entity table (append-only)
    ALTER TABLE regulatory_reporting_srpreportmilestoneaudit ENABLE ROW LEVEL SECURITY;
    ALTER TABLE regulatory_reporting_srpreportmilestoneaudit FORCE ROW LEVEL SECURITY;
    --following policies define read/insert control on srpreportmilestoneaudit entity (append-only)
    --policy for entity insert (eg. create)
    DROP policy if exists acl_policy_srpreportmilestoneaudit_create on regulatory_reporting_srpreportmilestoneaudit;
    create policy acl_policy_srpreportmilestoneaudit_create
    on regulatory_reporting_srpreportmilestoneaudit
    for INSERT
    WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
         AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
    --policy for entity select
    DROP policy if exists acl_policy_srpreportmilestoneaudit_select on regulatory_reporting_srpreportmilestoneaudit;
    create policy acl_policy_srpreportmilestoneaudit_select
    on regulatory_reporting_srpreportmilestoneaudit
    for select
    USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
            """,
        ),
    ]
