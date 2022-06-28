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
