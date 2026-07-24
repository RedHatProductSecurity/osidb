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
            name = value.upper()
            if name == "EMBARGOED":
                name = "EMBARGO"
            return cls._member_map_.get(name)

    def __lt__(self, other: "ACL") -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented

        members = list(self.__class__)
        return members.index(self) < members.index(other)
