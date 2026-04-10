"""
core

"""

import uuid

from django.db import connections

from osidb.exceptions import OSIDBException


def generate_acls(groups):
    """
    generate acls
    """
    return tuple(
        str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"https://osidb.prod.redhat.com/ns/acls#{group}",
            )
        )
        for group in groups
    )


def snapshot_user_acl_session() -> dict[str, str | None]:
    """
    Read ``osidb.acl`` from each open DB connection (``None`` if unset).
    """
    snapshot: dict[str, str | None] = {}
    try:
        for db_alias in connections:
            with connections[db_alias].cursor() as cursor:
                cursor.execute("SELECT current_setting('osidb.acl', true)")
                raw = cursor.fetchone()[0]
                snapshot[db_alias] = None if raw in (None, "") else raw
    except Exception:
        raise OSIDBException("Cannot snapshot user acl session")
    return snapshot


def restore_user_acl_session(snapshot: dict[str, str | None]) -> None:
    """
    Restore ``osidb.acl`` on each connection from a :func:`snapshot_user_acl_session` value.
    """
    try:
        for db_alias, raw in snapshot.items():
            if db_alias not in connections:
                continue
            with connections[db_alias].cursor() as cursor:
                if raw is None:
                    cursor.execute("RESET osidb.acl")
                else:
                    cursor.execute("SET osidb.acl = %s", [raw])
    except Exception:
        raise OSIDBException("Cannot restore user acl session")


def set_user_acls(groups) -> None:
    """
    set user acls
    """
    try:
        acls = generate_acls(groups)
        if acls:
            # we must set osidb.acl for every replica at the connection level
            # otherwise we'd set it only in one and then potentially read
            # from another replica without osidb.acl set, resulting in an
            # empty result set.
            for db_alias in connections:
                with connections[db_alias].cursor() as cursor:
                    # in theory psycopg2 should support list conversion but
                    # it seems to be broken, to pass into postgres we need
                    # to convert UUID[] into STRING[] doing some old
                    # fashioned string munging TBD-INVESTIGATE psycopg2
                    cursor.execute("SET osidb.acl = %s", [",".join(acls)])
    except Exception:
        raise OSIDBException("Cannot set user acl")
