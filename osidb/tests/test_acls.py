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

    def test_case_insensitive(self):
        assert ACL("public") is ACL.PUBLIC
        assert ACL("embargo") is ACL.EMBARGO
        assert ACL("Internal") is ACL.INTERNAL

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            ACL("NONEXISTENT")

    def test_embargoed_alias_no_longer_a_bare_lookup(self):
        # "EMBARGOED" is an ACLMixinVisibility spelling, not an ACL member
        # name; only from_visibility() bridges the two vocabularies.
        with pytest.raises(ValueError):
            ACL("EMBARGOED")


class TestACLFromVisibility:
    def test_exact_names(self):
        assert ACL.from_visibility("INTERNAL") is ACL.INTERNAL
        assert ACL.from_visibility("PUBLIC") is ACL.PUBLIC

    def test_embargoed_maps_to_embargo(self):
        assert ACL.from_visibility("EMBARGOED") is ACL.EMBARGO

    def test_case_insensitive(self):
        assert ACL.from_visibility("embargoed") is ACL.EMBARGO
        assert ACL.from_visibility("public") is ACL.PUBLIC

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            ACL.from_visibility("NONEXISTENT")
