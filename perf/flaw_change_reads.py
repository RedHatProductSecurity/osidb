"""Bounded local read-plan reproduction; no migrations, seeding, or maintenance.

Run in the normal local testrunner/service environment from the repository root:
  python perf/flaw_change_reads.py --database osidb --after=-1h --before=+1h
"""

import argparse
import json
import os
import statistics
import sys
from pathlib import Path
from time import perf_counter


def bounded_int(minimum, maximum):
    def parse(value):
        number = int(value)
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"expected {minimum}..{maximum}")
        return number

    return parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database", required=True, help="Explicit local database name"
    )
    parser.add_argument("--after", required=True)
    parser.add_argument("--before", required=True)
    parser.add_argument("--repeats", type=bounded_int(1, 20), default=3)
    parser.add_argument("--limit", type=bounded_int(1, 1000), default=50)
    parser.add_argument("--acl", choices=("public", "all"), default="public")
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings_local"
    import django

    django.setup()
    from django.conf import settings
    from django.db import connection, transaction
    from django.test import override_settings

    from osidb.core import (
        restore_user_acl_session,
        set_user_acls,
        snapshot_user_acl_session,
    )
    from osidb.filters import FlawFilter, FlawV1Filter
    from osidb.flaw_watermarks import flaw_timestamp_field, with_flaw_timestamp
    from osidb.models import Flaw, FlawChangeEvent

    database = connection.settings_dict
    if database["HOST"] not in ("osidb-data", "localhost", "127.0.0.1"):
        parser.error("only the standard local database host is allowed")
    if database["NAME"] != args.database:
        parser.error("--database does not match the local settings database")
    acl = snapshot_user_acl_session()
    try:
        set_user_acls(
            settings.ALL_GROUPS if args.acl == "all" else settings.PUBLIC_READ_GROUPS
        )
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute("SET LOCAL statement_timeout = '10s'")
            cursor.execute("SET LOCAL lock_timeout = '1s'")
            cursor.execute(
                "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"
            )
            role, superuser, bypass = cursor.fetchone()
            if superuser or bypass:
                parser.error("use ordinary restricted application credentials")
            result = {
                "role": role,
                "acl": args.acl,
                "visible_flaws": Flaw.objects.count(),
                # Internal table deliberately has no RLS: this is not a visible-row count.
                "total_events": FlawChangeEvent.objects.count(),
                "repeats": args.repeats,
                "queries": [],
            }
            for enabled in (False, True):
                with override_settings(OSIDB_USE_FLAW_WATERMARK=enabled):
                    for filters in (FlawFilter, FlawV1Filter):
                        f = filters(
                            {"changed_after": args.after, "changed_before": args.before}
                        )
                        if not f.is_valid():
                            parser.error(str(f.errors))
                        qs = f.qs
                        index = with_flaw_timestamp(Flaw.objects.all()).values_list(
                            "uuid", flaw_timestamp_field()
                        )
                        cve_index = with_flaw_timestamp(
                            Flaw.objects.exclude(cve_id__isnull=True)
                        ).values_list("cve_id", flaw_timestamp_field())
                        for name, query in (
                            ("count", qs),
                            ("page", qs[: args.limit]),
                            ("index_uuid", index),
                            ("index_cve", cve_index),
                        ):
                            samples = []

                            def capture(execute, sql, params, many, context):
                                captured[:] = [(sql, params)]
                                return execute(sql, params, many, context)

                            captured = []
                            for _ in range(args.repeats):
                                started = perf_counter()
                                with connection.execute_wrapper(capture):
                                    rows = (
                                        query.count()
                                        if name == "count"
                                        else len(list(query.all()))
                                    )
                                samples.append((perf_counter() - started) * 1000)
                            # Capture Django's actual COUNT/page/index statement,
                            # including its annotation/order elision for COUNT.
                            sql, params = captured[-1]
                            cursor.execute(
                                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql, params
                            )
                            result["queries"].append(
                                {
                                    "events_enabled": enabled,
                                    "filter": filters.__name__,
                                    "operation": name,
                                    "rows": rows,
                                    "median_ms": statistics.median(samples),
                                    "samples_ms": samples,
                                    "plan": cursor.fetchone()[0],
                                }
                            )
            print(json.dumps(result, indent=2, default=str))
    finally:
        restore_user_acl_session(acl)


if __name__ == "__main__":
    main()
