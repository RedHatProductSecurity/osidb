import cProfile
import time
from collections import Counter

from django.conf import settings
from django.db import connection, reset_queries
from django.test.utils import CaptureQueriesContext

from .utils import clean_sql, extract_tables, fingerprint_sql

SLOW_QUERY_THRESHOLD = 0.04
N_PLUS_ONE_THRESHOLD = 3


class PerformanceAuditor:
    """
    Context manager for comprehensive performance auditing.

    Tracks:
      - Database queries (count, duplicates, N+1 patterns, slow queries, mutations)
      - Execution time (total, Python, database)
      - CPU Profiling
    """

    def __init__(self, enable_profiling=True):
        self.total_time = 0
        self.db_time = 0
        self.exact_duplicates = []
        self.query_map = {}
        self.n_plus_one_suspects = []
        self.writes_detected = []
        self.table_counts = Counter()
        self.slow_query_plans = []

        self.profiler = cProfile.Profile() if enable_profiling else None

    def __enter__(self):
        # Ensure DEBUG is disabled to mimic a production environment
        self.old_debug = settings.DEBUG
        settings.DEBUG = False

        # Reset query count and enable capture
        reset_queries()
        self.queries_ctx = CaptureQueriesContext(connection).__enter__()

        self.start_time = time.perf_counter()
        self.start_cpu = time.process_time()

        if self.profiler:
            self.profiler.enable()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.profiler:
            self.profiler.disable()

        # Calculate times
        self.end_time = time.perf_counter()
        self.end_cpu = time.process_time()
        self.total_time = self.end_time - self.start_time
        self.cpu_time = self.end_cpu - self.start_cpu

        # Restore DEBUG
        settings.DEBUG = self.old_debug

        # Stop query capture
        self.queries_ctx.__exit__(exc_type, exc_value, traceback)
        self.queries = self.queries_ctx.captured_queries

        self._analyze_results()

    def _analyze_results(self):
        """
        Process the raw data into more meaningful stats.
        """

        for query in self.queries:
            sql = clean_sql(query["sql"])

            # Calculate DB time (Django stores it as string seconds)
            duration = float(query["time"])
            self.db_time += duration

            # Detect mutations
            if any(
                action in sql for action in ["INSERT INTO", "UPDATE ", "DELETE FROM"]
            ):
                # Ignore savepoints/transaction management
                if "auth_" not in sql:  # ignore session updates
                    self.writes_detected.append(sql)

            # Extract tables accessed
            tables = extract_tables(sql)
            for table in tables:
                self.table_counts[table] += 1

            # Fingerprint query shape
            fp = fingerprint_sql(sql)
            if fp not in self.query_map:
                self.query_map[fp] = {
                    "durations": [],
                    "sql": sql,  # Capture the First raw SQL with this shape
                }
            self.query_map[fp]["durations"].append(duration)

            # Analyze slow queries
            if duration > SLOW_QUERY_THRESHOLD:
                self._run_explain(sql, duration)

        # Detect duplicated queries
        raw_sql_counts = Counter([clean_sql(q["sql"]) for q in self.queries])
        for sql, count in raw_sql_counts.items():
            if count > 1 and "SAVEPOINT" not in sql:
                self.exact_duplicates.append({"sql": sql, "count": count})

        # Detect N+1
        # If the same query structure runs > N_PLUS_ONE_THRESHOLD times, flag it
        for fp, data in self.query_map.items():
            durations = data["durations"]
            count = len(durations)
            if count > N_PLUS_ONE_THRESHOLD:
                self.n_plus_one_suspects.append(
                    {
                        "fingerprint": fp,
                        "sql": data["sql"],
                        "count": count,
                        "avg_time": sum(durations) / count,
                        "total_time": sum(durations),
                    }
                )

    def _run_explain(self, sql, duration):
        # We need to be careful not to break the transaction state
        # Usually safe for SELECTs in tests
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"EXPLAIN ANALYZE {sql}")
                plan = cursor.fetchall()
                # Flatten the result into a single string
                plan_text = "\n".join([row[0] for row in plan])

                self.slow_query_plans.append(
                    {"sql": sql, "duration": duration, "plan": plan_text}
                )
        except Exception as e:
            # Don't crash the test if EXPLAIN fails (syntax errors, etc)
            print(f"Could not explain query: {e}")

    def get_summary(self):
        """Returns a dictionary summary for the report generator."""

        return {
            "total_duration": self.total_time,
            "cpu_duration": self.cpu_time,
            "db_duration": self.db_time,
            "query_count": len(self.queries),
            "exact_duplicates": self.exact_duplicates,
            "n_plus_one_suspects": self.n_plus_one_suspects,
            "writes_detected": self.writes_detected,
            "table_breakdown": dict(
                self.table_counts.most_common()
            ),  # Sorts by most accessed
            "slow_query_plans": self.slow_query_plans,
        }
