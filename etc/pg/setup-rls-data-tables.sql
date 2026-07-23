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

--enable row based security for alert entity table
ALTER TABLE osidb_alert ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_alert FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_alert entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_alert_create on osidb_alert;
create policy acl_policy_alert_create
on osidb_alert
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_alert_select on osidb_alert;
create policy acl_policy_alert_select
on osidb_alert
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_alert_update on osidb_alert;
create policy acl_policy_alert_update
on osidb_alert
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_alert_delete on osidb_alert;
create policy acl_policy_alert_delete
on osidb_alert
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for flawcvss entity table
ALTER TABLE osidb_flawcvss ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawcvss FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawcvss entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawcvss_create on osidb_flawcvss;
create policy acl_policy_flawcvss_create
on osidb_flawcvss
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_flawcvss_select on osidb_flawcvss;
create policy acl_policy_flawcvss_select
on osidb_flawcvss
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_flawcvss_update on osidb_flawcvss;
create policy acl_policy_flawcvss_update
on osidb_flawcvss
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawcvss_delete on osidb_flawcvss;
create policy acl_policy_flawcvss_delete
on osidb_flawcvss
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for affectcvss entity table
ALTER TABLE osidb_affectcvss ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_affectcvss FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_affectcvss entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_affectcvss_create on osidb_affectcvss;
create policy acl_policy_affectcvss_create
on osidb_affectcvss
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_affectcvss_select on osidb_affectcvss;
create policy acl_policy_affectcvss_select
on osidb_affectcvss
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_affectcvss_update on osidb_affectcvss;
create policy acl_policy_affectcvss_update
on osidb_affectcvss
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_affectcvss_delete on osidb_affectcvss;
create policy acl_policy_affectcvss_delete
on osidb_affectcvss
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for flawcomment entity table
ALTER TABLE osidb_flawcomment ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawcomment FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawcomment entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawcomment_create on osidb_flawcomment;
create policy acl_policy_flawcomment_create
on osidb_flawcomment
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_flawcomment_select on osidb_flawcomment;
create policy acl_policy_flawcomment_select
on osidb_flawcomment
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_flawcomment_update on osidb_flawcomment;
create policy acl_policy_flawcomment_update
on osidb_flawcomment
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawcomment_delete on osidb_flawcomment;
create policy acl_policy_flawcomment_delete
on osidb_flawcomment
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for flawreference entity table
ALTER TABLE osidb_flawreference ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawreference FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawreference entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawreference_create on osidb_flawreference;
create policy acl_policy_flawreference_create
on osidb_flawreference
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_flawreference_select on osidb_flawreference;
create policy acl_policy_flawreference_select
on osidb_flawreference
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_flawreference_update on osidb_flawreference;
create policy acl_policy_flawreference_update
on osidb_flawreference
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawreference_delete on osidb_flawreference;
create policy acl_policy_flawreference_delete
on osidb_flawreference
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for flawacknowledgment entity table
ALTER TABLE osidb_flawacknowledgment ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawacknowledgment FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawacknowledgment entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawacknowledgment_create on osidb_flawacknowledgment;
create policy acl_policy_flawacknowledgment_create
on osidb_flawacknowledgment
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_flawacknowledgment_select on osidb_flawacknowledgment;
create policy acl_policy_flawacknowledgment_select
on osidb_flawacknowledgment
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_flawacknowledgment_update on osidb_flawacknowledgment;
create policy acl_policy_flawacknowledgment_update
on osidb_flawacknowledgment
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_flawacknowledgment_delete on osidb_flawacknowledgment;
create policy acl_policy_flawacknowledgment_delete
on osidb_flawacknowledgment
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for package entity table
ALTER TABLE osidb_package ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_package FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_package entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_package_create on osidb_package;
create policy acl_policy_package_create
on osidb_package
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_package_select on osidb_package;
create policy acl_policy_package_select
on osidb_package
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_package_update on osidb_package;
create policy acl_policy_package_update
on osidb_package
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_package_delete on osidb_package;
create policy acl_policy_package_delete
on osidb_package
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for snippet entity table
ALTER TABLE osidb_snippet ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_snippet FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_snippet entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_snippet_create on osidb_snippet;
create policy acl_policy_snippet_create
on osidb_snippet
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_snippet_select on osidb_snippet;
create policy acl_policy_snippet_select
on osidb_snippet
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_snippet_update on osidb_snippet;
create policy acl_policy_snippet_update
on osidb_snippet
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_snippet_delete on osidb_snippet;
create policy acl_policy_snippet_delete
on osidb_snippet
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);

--enable row based security for upstreamdata entity table
ALTER TABLE osidb_upstreamdata ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_upstreamdata FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_upstreamdata entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_upstreamdata_create on osidb_upstreamdata;
create policy acl_policy_upstreamdata_create
on osidb_upstreamdata
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_upstreamdata_select on osidb_upstreamdata;
create policy acl_policy_upstreamdata_select
on osidb_upstreamdata
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_upstreamdata_update on osidb_upstreamdata;
create policy acl_policy_upstreamdata_update
on osidb_upstreamdata
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_upstreamdata_delete on osidb_upstreamdata;
create policy acl_policy_upstreamdata_delete
on osidb_upstreamdata
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
