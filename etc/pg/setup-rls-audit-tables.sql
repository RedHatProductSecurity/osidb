--enable row based security for following tables
ALTER TABLE osidb_flawaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawaudit_create on osidb_flawaudit;
create policy acl_policy_flawaudit_create
on osidb_flawaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flawaudit_select on osidb_flawaudit;
create policy acl_policy_flawaudit_select
on osidb_flawaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawaudit_update on osidb_flawaudit;
create policy acl_policy_flawaudit_update
on osidb_flawaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawaudit_delete on osidb_flawaudit;
create policy acl_policy_flawaudit_delete
on osidb_flawaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for affectaudit entity table
ALTER TABLE osidb_affectaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_affectaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_affectaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_affectaudit_create on osidb_affectaudit;
create policy acl_policy_affectaudit_create
on osidb_affectaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_affectaudit_select on osidb_affectaudit;
create policy acl_policy_affectaudit_select
on osidb_affectaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_affectaudit_update on osidb_affectaudit;
create policy acl_policy_affectaudit_update
on osidb_affectaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_affectaudit_delete on osidb_affectaudit;
create policy acl_policy_affectaudit_delete
on osidb_affectaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
