-- SECURITY DEFINER lookup functions bypass RLS on source tables so that
-- audit-table policies always see the source object's current ACLs.
-- The COALESCE fallback to the audit row's own ACLs applies only when
-- the source object has been deleted (function returns NULL).

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_flaw(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_flaw WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_flaw(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_flaw(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_flaw WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_flaw(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_affect(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_affect WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_affect(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_affect(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_affect WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_affect(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_tracker(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_tracker WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_tracker(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_tracker(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_tracker WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_tracker(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_flawacknowledgment(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_flawacknowledgment WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_flawacknowledgment(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_flawacknowledgment(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_flawacknowledgment WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_flawacknowledgment(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_flawreference(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_flawreference WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_flawreference(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_flawreference(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_flawreference WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_flawreference(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_flawcomment(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_flawcomment WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_flawcomment(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_flawcomment(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_flawcomment WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_flawcomment(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_flawcvss(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_flawcvss WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_flawcvss(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_flawcvss(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_flawcvss WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_flawcvss(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_affectcvss(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_affectcvss WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_affectcvss(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_affectcvss(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_affectcvss WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_affectcvss(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_read_osidb_flawlabelv2(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_read FROM osidb_flawlabelv2 WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_read_osidb_flawlabelv2(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION _rls_get_acl_write_osidb_flawlabelv2(obj_id uuid)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER
AS $func$ SELECT acl_write FROM osidb_flawlabelv2 WHERE uuid = obj_id; $func$;
REVOKE EXECUTE ON FUNCTION _rls_get_acl_write_osidb_flawlabelv2(uuid) FROM PUBLIC;

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_flaw(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawaudit_update on osidb_flawaudit;
create policy acl_policy_flawaudit_update
on osidb_flawaudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flaw(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_flaw(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_flaw(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_flawaudit_delete on osidb_flawaudit;
create policy acl_policy_flawaudit_delete
on osidb_flawaudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flaw(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_affect(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
--policy for entity update
DROP policy if exists acl_policy_affectaudit_update on osidb_affectaudit;
create policy acl_policy_affectaudit_update
on osidb_affectaudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_affect(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_affect(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_affect(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_affectaudit_delete on osidb_affectaudit;
create policy acl_policy_affectaudit_delete
on osidb_affectaudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_affect(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_tracker(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_trackeraudit_update on osidb_trackeraudit;
create policy acl_policy_trackeraudit_update
on osidb_trackeraudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_tracker(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_tracker(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_tracker(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_trackeraudit_delete on osidb_trackeraudit;
create policy acl_policy_trackeraudit_delete
on osidb_trackeraudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_tracker(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_flawacknowledgment(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawacknowledgmentaudit_update on osidb_flawacknowledgmentaudit;
create policy acl_policy_flawacknowledgmentaudit_update
on osidb_flawacknowledgmentaudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawacknowledgment(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_flawacknowledgment(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_flawacknowledgment(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_flawacknowledgmentaudit_delete on osidb_flawacknowledgmentaudit;
create policy acl_policy_flawacknowledgmentaudit_delete
on osidb_flawacknowledgmentaudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawacknowledgment(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_flawreference(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawreferenceaudit_update on osidb_flawreferenceaudit;
create policy acl_policy_flawreferenceaudit_update
on osidb_flawreferenceaudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawreference(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_flawreference(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_flawreference(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_flawreferenceaudit_delete on osidb_flawreferenceaudit;
create policy acl_policy_flawreferenceaudit_delete
on osidb_flawreferenceaudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawreference(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_flawcomment(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawcommentaudit_update on osidb_flawcommentaudit;
create policy acl_policy_flawcommentaudit_update
on osidb_flawcommentaudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawcomment(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_flawcomment(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_flawcomment(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_flawcommentaudit_delete on osidb_flawcommentaudit;
create policy acl_policy_flawcommentaudit_delete
on osidb_flawcommentaudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawcomment(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_flawcvss(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawcvssaudit_update on osidb_flawcvssaudit;
create policy acl_policy_flawcvssaudit_update
on osidb_flawcvssaudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawcvss(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_flawcvss(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_flawcvss(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_flawcvssaudit_delete on osidb_flawcvssaudit;
create policy acl_policy_flawcvssaudit_delete
on osidb_flawcvssaudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawcvss(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

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
USING (
    COALESCE(
        _rls_get_acl_read_osidb_affectcvss(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_affectcvssaudit_update on osidb_affectcvssaudit;
create policy acl_policy_affectcvssaudit_update
on osidb_affectcvssaudit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_affectcvss(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_affectcvss(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_affectcvss(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_affectcvssaudit_delete on osidb_affectcvssaudit;
create policy acl_policy_affectcvssaudit_delete
on osidb_affectcvssaudit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_affectcvss(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);

--enable row based security for FlawLabelV2Audit
ALTER TABLE osidb_flawlabelv2audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_flawlabelv2audit FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_flawlabelv2audit entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_flawlabelv2audit_create on osidb_flawlabelv2audit;
create policy acl_policy_flawlabelv2audit_create
on osidb_flawlabelv2audit
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
-- Check that read / write ACLs of record to be inserted match ACL of current user
--policy for entity select
DROP policy if exists acl_policy_flawlabelv2audit_select on osidb_flawlabelv2audit;
create policy acl_policy_flawlabelv2audit_select
on osidb_flawlabelv2audit
for select
USING (
    COALESCE(
        _rls_get_acl_read_osidb_flawlabelv2(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
-- Select only records with ACL that matches ACL of current user
--policy for entity update
DROP policy if exists acl_policy_flawlabelv2audit_update on osidb_flawlabelv2audit;
create policy acl_policy_flawlabelv2audit_update
on osidb_flawlabelv2audit
for update
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawlabelv2(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
)
WITH CHECK (
    COALESCE(
        _rls_get_acl_read_osidb_flawlabelv2(pgh_obj_id),
        acl_read
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
    AND
    COALESCE(
        _rls_get_acl_write_osidb_flawlabelv2(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
);
--policy for entity delete
DROP policy if exists acl_policy_flawlabelv2audit_delete on osidb_flawlabelv2audit;
create policy acl_policy_flawlabelv2audit_delete
on osidb_flawlabelv2audit
for delete
USING (
    COALESCE(
        _rls_get_acl_write_osidb_flawlabelv2(pgh_obj_id),
        acl_write
    )::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]
);
