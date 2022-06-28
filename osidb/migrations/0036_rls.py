# Created manually on 2022-03-31 23:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0035_alter_tracker_affects'),
    ]

    operations = [
        # setup-rls-data-tables.sql
        migrations.RunSQL(
"""
--enable row based security for following tables
ALTER TABLE osidb_flaw ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flaw FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flaw entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flaw_create on osidb_flaw;
create policy acl_policy_flaw_create
on osidb_flaw
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flaw_select on osidb_flaw;
create policy acl_policy_flaw_select
on osidb_flaw
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flaw_update on osidb_flaw;
create policy acl_policy_flaw_update
on osidb_flaw
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flaw_delete on osidb_flaw;
create policy acl_policy_flaw_delete
on osidb_flaw
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for affects entity table
ALTER TABLE osidb_affect ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_affect FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_affect entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_affect_create on osidb_affect;
create policy acl_policy_affect_create
on osidb_affect
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_affect_select on osidb_affect;
create policy acl_policy_affect_select
on osidb_affect
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_affect_update on osidb_affect;
create policy acl_policy_affect_update
on osidb_affect
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_affect_delete on osidb_affect;
create policy acl_policy_affect_delete
on osidb_affect
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for flawmeta entity table
ALTER TABLE osidb_flawmeta ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawmeta FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawmeta entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_meta_create on osidb_flawmeta;
create policy acl_policy_meta_create
on osidb_flawmeta
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_meta_select on osidb_flawmeta;
create policy acl_policy_meta_select
on osidb_flawmeta
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_meta_update on osidb_flawmeta;
create policy acl_policy_meta_update
on osidb_flawmeta
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_meta_delete on osidb_flawmeta;
create policy acl_policy_meta_delete
on osidb_flawmeta
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for tracker entity table
ALTER TABLE osidb_tracker ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_tracker FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_tracker entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_tracker_create on osidb_tracker;
create policy acl_policy_tracker_create
on osidb_tracker
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_tracker_select on osidb_tracker;
create policy acl_policy_tracker_select
on osidb_tracker
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_tracker_update on osidb_tracker;
create policy acl_policy_tracker_update
on osidb_tracker
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_tracker_delete on osidb_tracker;
create policy acl_policy_tracker_delete
on osidb_tracker
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

"""
        ),

        # setup-rls-event-tables.sql
        migrations.RunSQL(
"""
--enable row based security for following tables
ALTER TABLE osidb_flawevent ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawevent FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawevent entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawevent_create on osidb_flawevent;
create policy acl_policy_flawevent_create
on osidb_flawevent
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flawevent_select on osidb_flawevent;
create policy acl_policy_flawevent_select
on osidb_flawevent
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawevent_update on osidb_flawevent;
create policy acl_policy_flawevent_update
on osidb_flawevent
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawevent_delete on osidb_flawevent;
create policy acl_policy_flawevent_delete
on osidb_flawevent
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for affectevent entity table
ALTER TABLE osidb_affectevent ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_affectevent FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_affectevent entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_affectevent_create on osidb_affectevent;
create policy acl_policy_affectevent_create
on osidb_affectevent
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_affectevent_select on osidb_affectevent;
create policy acl_policy_affectevent_select
on osidb_affectevent
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_affectevent_update on osidb_affectevent;
create policy acl_policy_affectevent_update
on osidb_affectevent
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_affectevent_delete on osidb_affectevent;
create policy acl_policy_affectevent_delete
on osidb_affectevent
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for flawmetaevent entity table
ALTER TABLE osidb_flawmetaevent ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawmetaevent FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawmetaevent entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_meta_create on osidb_flawmetaevent;
create policy acl_policy_meta_create
on osidb_flawmetaevent
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_meta_select on osidb_flawmetaevent;
create policy acl_policy_meta_select
on osidb_flawmetaevent
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_meta_update on osidb_flawmetaevent;
create policy acl_policy_meta_update
on osidb_flawmetaevent
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_meta_delete on osidb_flawmetaevent;
create policy acl_policy_meta_delete
on osidb_flawmetaevent
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for trackerevent entity table
ALTER TABLE osidb_trackerevent ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_trackerevent FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_trackerevent entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_trackerevent_create on osidb_trackerevent;
create policy acl_policy_trackerevent_create
on osidb_trackerevent
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_trackerevent_select on osidb_trackerevent;
create policy acl_policy_trackerevent_select
on osidb_trackerevent
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_trackerevent_update on osidb_trackerevent;
create policy acl_policy_trackerevent_update
on osidb_trackerevent
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_trackerevent_delete on osidb_trackerevent;
create policy acl_policy_trackerevent_delete
on osidb_trackerevent
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
"""
        ),
    ]
