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

--enable row based security for TrackerAudit
ALTER TABLE osidb_trackeraudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_trackeraudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_trackeraudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_trackeraudit_create on osidb_trackeraudit;
create policy acl_policy_trackeraudit_create
on osidb_trackeraudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_trackeraudit_select on osidb_trackeraudit;
create policy acl_policy_trackeraudit_select
on osidb_trackeraudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_trackeraudit_update on osidb_trackeraudit;
create policy acl_policy_trackeraudit_update
on osidb_trackeraudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_trackeraudit_delete on osidb_trackeraudit;
create policy acl_policy_trackeraudit_delete
on osidb_trackeraudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for FlawAcknowledgmentAudit
ALTER TABLE osidb_flawacknowledgmentaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawacknowledgmentaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawacknowledgmentaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawacknowledgmentaudit_create on osidb_flawacknowledgmentaudit;
create policy acl_policy_flawacknowledgmentaudit_create
on osidb_flawacknowledgmentaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flawacknowledgmentaudit_select on osidb_flawacknowledgmentaudit;
create policy acl_policy_flawacknowledgmentaudit_select
on osidb_flawacknowledgmentaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawacknowledgmentaudit_update on osidb_flawacknowledgmentaudit;
create policy acl_policy_flawacknowledgmentaudit_update
on osidb_flawacknowledgmentaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawacknowledgmentaudit_delete on osidb_flawacknowledgmentaudit;
create policy acl_policy_flawacknowledgmentaudit_delete
on osidb_flawacknowledgmentaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for FlawReferenceAudit
ALTER TABLE osidb_flawreferenceaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawreferenceaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawreferenceaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawreferenceaudit_create on osidb_flawreferenceaudit;
create policy acl_policy_flawreferenceaudit_create
on osidb_flawreferenceaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flawreferenceaudit_select on osidb_flawreferenceaudit;
create policy acl_policy_flawreferenceaudit_select
on osidb_flawreferenceaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawreferenceaudit_update on osidb_flawreferenceaudit;
create policy acl_policy_flawreferenceaudit_update
on osidb_flawreferenceaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawreferenceaudit_delete on osidb_flawreferenceaudit;
create policy acl_policy_flawreferenceaudit_delete
on osidb_flawreferenceaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for FlawCommentAudit
ALTER TABLE osidb_flawcommentaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawcommentaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawcommentaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawcommentaudit_create on osidb_flawcommentaudit;
create policy acl_policy_flawcommentaudit_create
on osidb_flawcommentaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flawcommentaudit_select on osidb_flawcommentaudit;
create policy acl_policy_flawcommentaudit_select
on osidb_flawcommentaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawcommentaudit_update on osidb_flawcommentaudit;
create policy acl_policy_flawcommentaudit_update
on osidb_flawcommentaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawcommentaudit_delete on osidb_flawcommentaudit;
create policy acl_policy_flawcommentaudit_delete
on osidb_flawcommentaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for FlawCVSSAudit
ALTER TABLE osidb_flawcvssaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawcvssaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawcvssaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawcvssaudit_create on osidb_flawcvssaudit;
create policy acl_policy_flawcvssaudit_create
on osidb_flawcvssaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flawcvssaudit_select on osidb_flawcvssaudit;
create policy acl_policy_flawcvssaudit_select
on osidb_flawcvssaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawcvssaudit_update on osidb_flawcvssaudit;
create policy acl_policy_flawcvssaudit_update
on osidb_flawcvssaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawcvssaudit_delete on osidb_flawcvssaudit;
create policy acl_policy_flawcvssaudit_delete
on osidb_flawcvssaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for AffectCVSSAudit
ALTER TABLE osidb_affectcvssaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_affectcvssaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_affectcvssaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_affectcvssaudit_create on osidb_affectcvssaudit;
create policy acl_policy_affectcvssaudit_create
on osidb_affectcvssaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_affectcvssaudit_select on osidb_affectcvssaudit;
create policy acl_policy_affectcvssaudit_select
on osidb_affectcvssaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_affectcvssaudit_update on osidb_affectcvssaudit;
create policy acl_policy_affectcvssaudit_update
on osidb_affectcvssaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_affectcvssaudit_delete on osidb_affectcvssaudit;
create policy acl_policy_affectcvssaudit_delete
on osidb_affectcvssaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for SnippetAudit
ALTER TABLE osidb_snippetaudit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_snippetaudit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_snippetaudit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_snippetaudit_create on osidb_snippetaudit;
create policy acl_policy_snippetaudit_create
on osidb_snippetaudit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_snippetaudit_select on osidb_snippetaudit;
create policy acl_policy_snippetaudit_select
on osidb_snippetaudit
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_snippetaudit_update on osidb_snippetaudit;
create policy acl_policy_snippetaudit_update
on osidb_snippetaudit
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_snippetaudit_delete on osidb_snippetaudit;
create policy acl_policy_snippetaudit_delete
on osidb_snippetaudit
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);