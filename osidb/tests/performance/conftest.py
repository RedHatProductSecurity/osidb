import os
from datetime import datetime

import pytest

from .auditor import PerformanceAuditor
from .utils import get_profile_stats, get_safe_filename

# Global store for results (Note: incompatible with pytest-xdist parallelization without extra work)
PERFORMANCE_RESULTS = []


@pytest.fixture(scope="function")
def performance_audit(request):
    auditor = PerformanceAuditor()

    # Run the test
    yield auditor

    # Check if the tests actually used the auditor
    # and skip reporting otherwise
    if auditor.total_time == 0:
        return

    summary = auditor.get_summary()
    summary["test_name"] = request.node.name
    summary["profile"] = get_profile_stats(auditor.profiler)
    # We could export the profile with auditor.profiler.dump_stats()
    # for manual review if needed

    PERFORMANCE_RESULTS.append(summary)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """
    Hook to print the summary table at the end of the session.
    """
    if not PERFORMANCE_RESULTS:
        return

    terminalreporter.section("Performance Regression Report")

    # Table Header
    header = f"{'Test Name':<40} | {'Time':<8} | {'CPU Time':<8} | {'DB Time':<8} | {'Queries':<7} | {'Tables':<6} | {'N+1':<4} | {'Writes':<6} | {'Dup Queries':<11} | {'Slow queries':<12}"
    terminalreporter.write_line("-" * len(header))
    terminalreporter.write_line(header)
    terminalreporter.write_line("-" * len(header))

    # Table Rows
    for res in PERFORMANCE_RESULTS:
        name = (
            res["test_name"]
            if len(res["test_name"]) <= 40
            else f"{res['test_name'][:37]}..."
        )
        row = (
            f"{name:<40} | "
            f"{res['total_duration'] * 1000:>6.0f}ms | "
            f"{res['cpu_duration'] * 1000:>6.0f}ms | "
            f"{res['db_duration'] * 1000:>6.0f}ms | "
            f"{res['query_count']:>7} | "
            f"{len(res['table_breakdown'].keys()):>6} | "
            f"{len(res['n_plus_one_suspects']):>4} | "
            f"{len(res['writes_detected']):>6} | "
            f"{len(res['exact_duplicates']):>11} | "
            f"{len(res['slow_query_plans']):>12}"
        )
        terminalreporter.write_line(row)
    generate_markdown_report()


def generate_markdown_report():
    """Generates a detailed GITHUB_STEP_SUMMARY compliant markdown file."""

    def get_color(time):
        if time < 100:
            return "green"
        elif time < 200:
            return "blue"
        elif time < 500:
            return "orange"
        else:
            return "red"

    run_date = datetime.now()

    if (
        "CI" not in os.environ
        or not os.environ["CI"]
        or "GITHUB_RUN_ID" not in os.environ
    ):
        file = f"performance_report_{run_date.strftime('%Y-%m-%d_%H-%M')}.md"
        mode = "w"
    else:
        file = os.environ["GITHUB_STEP_SUMMARY"]
        mode = "a"

    with open(file, mode) as report:
        report.write("# 🚀 Detailed Performance Analysis\n\n")

        # Summary table
        report.write("## 📊 Executive Summary\n")
        report.write(
            "| Test | Time | CPU Time | DB Time | Queries | Tables | N+1 | Writes | Dup Queries | Slow queries |\n"
        )
        report.write("|" + ("---|" * 10) + "\n")
        for res in PERFORMANCE_RESULTS:
            report.write(
                f"| [{res['test_name']}](#{get_safe_filename(res['test_name'])})"
                f"| {res['total_duration'] * 1000:.0f}ms"
                f"| {res['cpu_duration'] * 1000:.0f}ms"
                f"| {res['db_duration'] * 1000:.0f}ms"
                f"| {res['query_count']:>7}"
                f"| {len(res['table_breakdown'].keys())}"
                f"| {len(res['n_plus_one_suspects'])}"
                f"| {len(res['writes_detected'])}"
                f"| {len(res['exact_duplicates'])}"
                f"| {len(res['slow_query_plans'])}|\n"
            )

        # Detailed breakdown per test
        report.write("\n---\n")
        report.write("## 🔬 Deep Dive per Test\n")
        for res in PERFORMANCE_RESULTS:
            total_duration = res["total_duration"] * 1000
            cpu_duration = res["cpu_duration"] * 1000
            db_duration = res["db_duration"] * 1000
            report.write(
                f'\n<h3 id="{get_safe_filename(res["test_name"])}">{res["test_name"]}</h3>\n\n'
            )
            report.write(
                f"![Total Time](https://img.shields.io/badge/total-{total_duration:.0f}ms-{get_color(total_duration)}) "
            )
            report.write(
                f"![CPU Time](https://img.shields.io/badge/cpu-{cpu_duration:.0f}ms-{get_color(cpu_duration)}) "
            )
            report.write(
                f"![DB Time](https://img.shields.io/badge/db-{db_duration:.0f}ms-{get_color(db_duration)})\n\n"
            )

            if res["table_breakdown"]:
                report.write("\n#### 📦 Database Model Access\n")
                report.write("<details>\n")
                report.write(
                    f"<summary><strong>x{len(res['table_breakdown'].keys())}</strong> Tables accessed</summary>\n\n"
                )
                report.write("| Table Name | Access Count |\n")
                report.write("|---|---|\n")
                for table, count in res["table_breakdown"].items():
                    report.write(f"| `{table}` | {count} |\n")
                report.write("</details>\n\n")

            writes = res.get("writes_detected", [])
            if writes:
                report.write("\n#### ⚠️ Mutation Warning\n")
                report.write(
                    f"This endpoint triggered **{len(writes)}** write operations.\n\n"
                )

                report.write("<details>\n<summary>View Write Operations</summary>\n\n")
                for sql in writes:
                    # Truncate very long SQL for readability
                    display_sql = sql[:200] + "..." if len(sql) > 200 else sql
                    report.write(f"- `{display_sql}`\n")
                report.write("</details>\n")

            dupes = res.get("exact_duplicates", [])
            if dupes:
                report.write("\n#### ♻️ Redundant Exact Queries\n")
                report.write(
                    "The exact same SQL (same parameters) was executed multiple times.\n\n"
                )
                report.write("| Count | Query Sample |\n")
                report.write("|---|---|\n")
                for d in dupes:
                    # Clean up newlines for table formatting
                    clean_sql = d["sql"].replace("\n", " ").strip()
                    # Truncate center if too long
                    if len(clean_sql) > 80:
                        short_sql = clean_sql[:40] + " ... " + clean_sql[-35:]
                    else:
                        short_sql = clean_sql
                    report.write(f"| **x{d['count']}** | `{short_sql}` |\n")

            if len(res["n_plus_one_suspects"]) > 0:
                report.write("#### ⚠️ N+1 Detected\n")
                report.write(
                    "The same SQL was executed multiple times with different parameters.\n\n"
                )
                for suspect in res["n_plus_one_suspects"]:
                    report.write("<details>\n")
                    report.write(
                        f"<summary><strong>x{suspect['count']}</strong> queries</summary>\n\n"
                    )
                    report.write("**Fingerprint:**\n")
                    report.write(f"```sql\n{suspect['fingerprint']}\n```\n")
                    report.write("**Example Raw SQL:**\n")
                    report.write(f"```sql\n{suspect['sql']}\n```\n")
                    report.write("</details>\n\n")

            if res["slow_query_plans"]:
                report.write("\n#### 🐢 Slow Query Analysis\n")
                report.write(
                    f"Found **{len(res['slow_query_plans'])}** queries exceeding the threshold.\n\n"
                )

                for i, item in enumerate(res["slow_query_plans"], 1):
                    duration_ms = item["duration"] * 1000
                    report.write("<details>\n")
                    report.write(
                        f"<summary><strong>{i}. Slow Query ({duration_ms:.1f}ms)</strong> - Click to view Plan</summary>\n\n"
                    )
                    report.write("**SQL:**\n")
                    report.write(f"```sql\n{item['sql']}\n```\n")
                    report.write("**PostgreSQL Query Plan:**\n")
                    report.write(f"```yaml\n{item['plan']}\n```\n")
                    report.write("</details>\n\n")

            # CPU Profile Analysis
            profile_data = res.get("profile")
            if profile_data and profile_data.get("top_functions"):
                report.write("\n#### 🔥 CPU Profile Analysis\n")
                report.write(
                    f"**Total profiled time**: {profile_data['total_time'] * 1000:.1f}ms "
                    f"({profile_data['total_calls']:,} function calls)\n\n"
                )

                # Category breakdown (collapsible)
                report.write("<details>\n")
                report.write(
                    "<summary><strong>Category Breakdown</strong></summary>\n\n"
                )
                report.write("| Category | Time (ms) | % of Total | Calls |\n")
                report.write("|---|---:|---:|---:|\n")
                for cat, stats in sorted(
                    profile_data["category_breakdown"].items(),
                    key=lambda x: x[1]["time"],
                    reverse=True,
                ):
                    if stats["time"] > 0:
                        report.write(
                            f"| {cat.replace('_', ' ').title()} | "
                            f"{stats['time'] * 1000:.2f} | "
                            f"{stats['percent']:.1f}% | "
                            f"{stats['calls']:,} |\n"
                        )
                report.write("</details>\n\n")

                # Top 10 functions (collapsible)
                report.write("<details>\n")
                report.write(
                    "<summary><strong>Top 10 Time-Consuming Functions</strong></summary>\n\n"
                )
                report.write("| Function | Category | Calls | Time | % | Per Call |\n")
                report.write("|---|---|---:|---:|---:|---:|\n")
                for func in profile_data["top_functions"]:
                    func_display = f"`{func['filename']}:{func['line_number']}` {func['function_name']}"
                    if len(func_display) > 60:
                        func_display = func_display[:57] + "..."

                    report.write(
                        f"| {func_display} | "
                        f"{func['category']} | "
                        f"{func['call_count']:,} | "
                        f"{func['total_time'] * 1000:.2f}ms | "
                        f"{func['time_percent']:.1f}% | "
                        f"{func['per_call_time'] * 1000:.3f}ms |\n"
                    )
                report.write("</details>\n\n")

            report.write("\n---\n")
