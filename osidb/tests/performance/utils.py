import cProfile
import hashlib
import pstats
import re
from collections import defaultdict


def get_safe_filename(test_name):
    """
    Converts a messy Pytest node name into a safe, valid filename.
    Input: "test_endpoint[/api/v1/flaws?id=1]"
    Output: "test_endpoint_api_v1_flaws_id_1_[hash]"
    """
    # 1. Replace URL-like slashes and special chars with underscores
    # Keep only alphanumerics, underscores, and hyphens
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", test_name)

    # 2. Collapse multiple underscores
    safe_name = re.sub(r"_{2,}", "_", safe_name)

    # 3. Truncate if too long (OS limit is usually 255)
    # If we cut it off, we add a hash of the original name to ensure uniqueness
    if len(safe_name) > 100:
        name_hash = hashlib.md5(test_name.encode("utf-8")).hexdigest()[:8]
        safe_name = f"{safe_name[:100]}_{name_hash}"

    return safe_name


def clean_sql(sql: str) -> str:
    """
    Removes pghistory context injection or other middleware noise
    to reveal the actual application query.

    Input: "SELECT set_config('pghistory...', ...); SELECT ..."
    Output: "SELECT ..."
    """
    # Regex explanation:
    # ^SELECT set_config : Must start with the config call
    # \('pghistory\.     : specific to pghistory to avoid false positives
    # .*?                : match arguments non-greedily
    # \);                : match the closing of the config and the semicolon
    # \s* : remove trailing whitespace before next query
    pghistory_pattern = r"^SELECT set_config\('pghistory\..*?\);\s*"

    # Remove the prefix
    cleaned = re.sub(pghistory_pattern, "", sql, flags=re.DOTALL | re.IGNORECASE)

    return cleaned.strip()


def fingerprint_sql(sql: str) -> str:
    """
    Normalizes a SQL query to a generic fingerprint to detect duplicates.

    Transformations:
    1. Replaces specific numeric values with '%d'
    2. Replaces quoted string LITERALS (single quotes) with '%s'
    3. Collapses IN clauses
    4. PRESERVES double-quoted identifiers (tables/columns)
    """
    # 1. Replace hex/binary blobs (e.g. x'05A...')
    sql = re.sub(r"x'[0-9a-f]+'", "'%b'", sql)

    # 2. Collapse IN clauses: IN (1, 2, 3) -> IN (...)
    sql = re.sub(r"\bIN\s*\([^\)]+\)", "IN (...)", sql, flags=re.IGNORECASE)

    # 3. Replace String Literals: 'hello' -> '%s'
    # We match anything inside single quotes.
    # Note: This handles escaped single quotes inside strings if they follow SQL standard ('')
    sql = re.sub(r"'(?:''|[^'])*'", "'%s'", sql)

    # 4. Replace Numbers: 123 -> %d
    # We use \b to ensure we don't break table names like "table_2"
    # But we must be careful not to break UUID casts like '...':uuid
    # The previous single-quote replacement handles the UUID value '...',
    # so the ::uuid part remains as literal text, which is fine.
    sql = re.sub(r"\b\d+\b", "%d", sql)

    # 5. Whitespace cleanup
    return " ".join(sql.split())


def extract_tables(sql: str) -> list[str]:
    """
    Extracts table names from a SQL query.
    Matches: FROM "table_name", JOIN "table_name", UPDATE "table_name", etc.
    """
    # This regex looks for keywords (FROM, JOIN, INTO, UPDATE)
    # followed optionally by whitespace and then the table name (possibly quoted)
    # It handles standard Django SQL generation.
    pattern = r'(?:FROM|JOIN|UPDATE|INTO)\s+(?:"|`?)([a-zA-Z0-9_]+)(?:"|`?)'

    matches = re.findall(pattern, sql, flags=re.IGNORECASE)

    # Deduplicate tables within a single query (e.g. self-joins)
    # or return all to weight complexity? Let's return unique per query.
    return list(set(matches))


def _empty_result():
    """Return empty result structure for edge cases."""
    return {
        "total_time": 0,
        "total_calls": 0,
        "top_functions": [],
        "category_breakdown": {},
    }


def _strip_dirs(filename):
    """Strip common prefixes to shorten paths for readability."""
    # Remove absolute path prefix for the project
    filename = filename.replace("/home/atinocom/Documents/work/osidb/", "")

    # Remove site-packages prefix
    filename = re.sub(r".*/site-packages/", "", filename)

    # Remove usr/lib prefix
    filename = re.sub(r"/usr/lib.*?/python\d+\.\d+/", "", filename)

    return filename


def _categorize_function(filename, func_name):
    """
    Categorizes a function based on Django-specific patterns.

    Categories (in priority order):
    - serializer: DRF serializers
    - view: Django/DRF views and viewsets
    - orm: Database operations (Django ORM, psycopg2)
    - framework: Django/DRF framework code
    - business_logic: Project-specific code
    - stdlib: Python standard library
    - other: Third-party libraries
    """
    # 1. Serializers (check first, specific pattern)
    if any(
        pattern in filename
        for pattern in ["/serializer.py", "/serializers.py", "/serializers/"]
    ):
        return "serializer"
    if "rest_framework.serializers" in filename or "drf_spectacular" in filename:
        return "serializer"

    # 2. Views
    if any(
        pattern in filename
        for pattern in ["/api_views.py", "/views.py", "/viewsets.py"]
    ):
        return "view"
    if any(
        mod in filename
        for mod in ["rest_framework.views", "rest_framework.viewsets", "django.views"]
    ):
        return "view"

    # 3. ORM (database operations)
    if any(
        pattern in filename for pattern in ["/django/db/", "/psycopg2", "/postgresql"]
    ):
        return "orm"
    if (
        "django.db.models" in filename
        or "django.db.backends" in filename
        or "psycopg2" in filename
    ):
        return "orm"
    if any(fn in func_name.lower() for fn in ["execute", "fetch", "cursor"]):
        return "orm"

    # 4. Framework (Django/DRF internals)
    if any(
        pattern in filename
        for pattern in ["/django/", "/rest_framework/", "/celery/", "/redis/"]
    ):
        return "framework"

    # 5. Business Logic (project-specific code)
    if any(pattern in filename for pattern in ["/osidb/", "/apps/", "/collectors/"]):
        if not any(
            exclude in filename for exclude in ["/tests/", "/migrations/", "/test_"]
        ):
            return "business_logic"

    # 6. Stdlib (Python standard library)
    if any(
        pattern in filename
        for pattern in ["/usr/lib/python", "/lib/python", "<frozen", "<built-in>"]
    ):
        return "stdlib"

    # 7. Default to other
    return "other"


def _should_include(func_data, total_time, category):
    """
    Determines if a function should be included in the report.

    Rules:
    - Always include: serializer, orm, view, business_logic, framework
    - Filter unless >5% total time: stdlib, other
    """
    # Always include Django-specific categories
    if category in ["serializer", "orm", "view", "business_logic", "framework"]:
        return True

    # Filter stdlib/other unless >5% threshold
    if category in ["stdlib", "other"]:
        time_percent = (
            (func_data["total_time"] / total_time * 100) if total_time > 0 else 0
        )
        return time_percent >= 5.0

    return True


def _aggregate_by_category(functions, total_time):
    """Aggregate stats by category."""
    breakdown = defaultdict(lambda: {"time": 0, "calls": 0})

    for func in functions:
        cat = func["category"]
        breakdown[cat]["time"] += func["total_time"]
        breakdown[cat]["calls"] += func["call_count"]

    # Calculate percentages
    for cat in breakdown:
        breakdown[cat]["percent"] = (
            (breakdown[cat]["time"] / total_time * 100) if total_time > 0 else 0
        )

    return dict(breakdown)


def get_profile_stats(profile: cProfile.Profile):
    """
    Analyzes a cProfile profile with Django-specific categorization.

    Returns structured data for markdown reporting including:
    - Top 10 time-consuming functions
    - Category breakdown (serializer, orm, view, business_logic, framework, stdlib, other)
    - Filtering of stdlib/other unless >5% of total time
    """

    # 2. Create pstats.Stats object
    stats = pstats.Stats(profile)
    total_time = stats.total_tt

    if total_time == 0:
        return _empty_result()

    # 3. Extract and process all functions
    all_functions = []
    for func_key, (
        prim_calls,
        ncalls,
        tottime,
        cumtime,
        callers,
    ) in stats.stats.items():
        # Parse function key
        filename = func_key[0] if len(func_key) > 0 else "<unknown>"
        line_number = func_key[1] if len(func_key) > 1 else 0
        func_name = func_key[2] if len(func_key) > 2 else "<unknown>"

        # Categorize
        category = _categorize_function(filename, func_name)

        # Build function data dict
        func_data = {
            "function_name": func_name,
            "filename": _strip_dirs(filename),
            "line_number": line_number,
            "category": category,
            "call_count": ncalls,
            "total_time": tottime,
            "cumulative_time": cumtime,
            "time_percent": (tottime / total_time * 100) if total_time > 0 else 0,
            "per_call_time": tottime / ncalls if ncalls > 0 else 0,
        }

        # Apply filtering
        if _should_include(func_data, total_time, category):
            all_functions.append(func_data)

    # 4. Select top 10
    top_functions = sorted(all_functions, key=lambda x: x["total_time"], reverse=True)[
        :10
    ]

    # 5. Calculate category breakdown
    category_breakdown = _aggregate_by_category(all_functions, total_time)

    # 6. Return structured data
    return {
        "total_time": total_time,
        "total_calls": stats.total_calls,
        "top_functions": top_functions,
        "category_breakdown": category_breakdown,
    }
