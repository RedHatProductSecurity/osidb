import uuid
from enum import Enum
from functools import total_ordering
from typing import Collection

from django.conf import settings


@total_ordering
class ACL(Enum):
    read: list[str]
    write: list[str]
    uuid_read: list[uuid.UUID]
    uuid_write: list[uuid.UUID]

    @staticmethod
    def generate_acl_uuids(acl: Collection[str]) -> list[uuid.UUID]:
        return sorted(
            uuid.uuid5(  # nosec: deterministic namespace ID, not used for crypto
                uuid.NAMESPACE_URL,
                f"https://osidb.prod.redhat.com/ns/acls#{entry}",
            )
            for entry in acl
        )

    UNKNOWN = ([], [])
    EMBARGO = (settings.EMBARGO_READ_GROUPS, settings.EMBARGO_WRITE_GROUPS)
    INTERNAL = (settings.INTERNAL_READ_GROUPS, settings.INTERNAL_WRITE_GROUPS)
    PUBLIC = (settings.PUBLIC_READ_GROUPS, settings.PUBLIC_WRITE_GROUPS)

    def __init__(self, read_list, write_list=None):
        super().__init__()
        if write_list is None:
            return
        self.read = read_list
        self.write = write_list
        self.uuid_read = self.generate_acl_uuids(read_list)
        self.uuid_write = self.generate_acl_uuids(write_list)

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            return cls._member_map_.get(value.upper())

    @classmethod
    def from_visibility(cls, visibility) -> "ACL":
        """
        Translate an ACLMixin ``visibility`` value (as produced by the
        ACLMixinVisibility choices: EMBARGOED/INTERNAL/PUBLIC, or an
        ACLMixinVisibility member) into the ACL that grants it.

        ACLMixinVisibility and ACL are two vocabularies for the same three
        tiers, and only "EMBARGOED" spells its tier differently from
        "EMBARGO". This is the one place that bridges the two; callers that
        already hold an ACL member name should keep using ACL(value)
        directly instead of special-casing the vocabulary difference again.
        """
        name = str(visibility).upper()
        if name == "EMBARGOED":
            name = "EMBARGO"
        acl = cls._member_map_.get(name)
        if acl is None:
            raise ValueError(f"Unknown visibility: {visibility!r}")
        return acl

    @classmethod
    def from_acl_read(cls, acl_read) -> "ACL":
        """
        Translate an acl_read UUID list (as stored on ACLMixin models) back
        into the ACL tier it was generated from, or ACL.UNKNOWN if it
        doesn't match any known tier.
        """
        for acl in (cls.PUBLIC, cls.INTERNAL, cls.EMBARGO):
            if acl_read == acl.uuid_read:
                return acl
        return cls.UNKNOWN

    def __lt__(self, other: "ACL") -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented

        members = list(self.__class__)
        return members.index(self) < members.index(other)
