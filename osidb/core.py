"""
core

"""

import uuid

from django.db import connection

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


def set_user_acls(groups) -> None:
    """
    set user acls
    """
    try:
        acls = generate_acls(groups)
        if acls:
            # in theory psycopg2 should support list conversion but it seems to be broken,
            # to pass into postgres we need to convert UUID[] into STRING[]
            # doing some old fashioned string munging TBD-INVESTIGATE psycopg2
            with connection.cursor() as cursor:
                cursor.execute("SET osidb.acl = %s", [",".join(acls)])
    except Exception:
        raise OSIDBException("Cannot set user acl")
