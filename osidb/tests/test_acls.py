import uuid

import pytest

from osidb.acls import ACL

pytestmark = pytest.mark.unit


class TestACLUuidGeneration:
    def test_uses_namespace_url(self):
        expected = uuid.uuid5(
            uuid.NAMESPACE_URL,
            "https://osidb.prod.redhat.com/ns/acls#my-group",
        )
        assert ACL.generate_acl_uuids(["my-group"]) == [expected]

    def test_multi_group_output_is_sorted(self):
        result = ACL.generate_acl_uuids(["z-group", "a-group"])
        assert result == sorted(result) and len(result) == 2

    def test_enum_uuids_match_their_groups(self):
        for member in ACL:
            assert member.uuid_read == ACL.generate_acl_uuids(member.read)
            assert member.uuid_write == ACL.generate_acl_uuids(member.write)


class TestACLOrdering:
    def test_visibility_order_embargo_internal_public(self):
        assert ACL.UNKNOWN < ACL.EMBARGO < ACL.INTERNAL < ACL.PUBLIC
        assert ACL.PUBLIC > ACL.INTERNAL > ACL.EMBARGO > ACL.UNKNOWN
        assert sorted(ACL) == [ACL.UNKNOWN, ACL.EMBARGO, ACL.INTERNAL, ACL.PUBLIC]

    def test_equal_members_are_not_ordered(self):
        assert not (ACL.EMBARGO < ACL.EMBARGO)
        assert ACL.EMBARGO == ACL.EMBARGO
        assert ACL.EMBARGO != ACL.INTERNAL
        assert ACL.UNKNOWN != ACL.EMBARGO


class TestACLStringLookup:
    def test_exact_name(self):
        assert ACL("PUBLIC") is ACL.PUBLIC
        assert ACL("INTERNAL") is ACL.INTERNAL
        assert ACL("EMBARGO") is ACL.EMBARGO

    def test_embargoed_alias(self):
        assert ACL("EMBARGOED") is ACL.EMBARGO

    def test_case_insensitive(self):
        assert ACL("public") is ACL.PUBLIC
        assert ACL("embargoed") is ACL.EMBARGO
        assert ACL("Internal") is ACL.INTERNAL

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            ACL("NONEXISTENT")
