"""
Locustfile for generating traffic against a local OSIDB instance with silk enabled.

Usage:
    # Generate sample data first:
    python manage.py generate_sample_data

    # Start the server with silk:
    OSIDB_ENABLE_SILK=1 python manage.py runserver

    # Run locust (headless, quick burst):
    locust --headless -f perf/silk_profiling.py --host http://localhost:8000 \
        --users 3 --spawn-rate 1 --run-time 30s

    # Or with the web UI:
    locust -f perf/silk_profiling.py --host http://localhost:8000 --modern-ui

    # Then view profiling results at http://localhost:8000/silk/
"""

import os

from locust import HttpUser, between, task

LOCUST_USERNAME = os.environ.get("LOCUST_USERNAME", "testuser")
LOCUST_PASSWORD = os.environ.get("LOCUST_PASSWORD", "password")  # noqa: S105


class ProfilingUser(HttpUser):
    wait_time = between(0.5, 2)
    token = None

    def on_start(self):
        self.client.verify = False
        resp = self.client.post(
            "/auth/token",
            json={"username": LOCUST_USERNAME, "password": LOCUST_PASSWORD},
        )
        if not resp.ok:
            raise RuntimeError(f"Auth failed ({resp.status_code}): {resp.text[:200]}")
        self.token = resp.json().get("access", "")
        if not self.token:
            raise RuntimeError(f"Auth response missing 'access' token: {resp.json()}")

    @property
    def auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    # ── Flaw endpoints ────────────────────────────────────────────────

    @task(10)
    def flaw_list(self):
        self.client.get(
            "/osidb/api/v1/flaws?limit=50&order=-created_dt",
            headers=self.auth_headers,
        )

    @task(5)
    def flaw_list_filtered(self):
        self.client.get(
            "/osidb/api/v1/flaws?impact=CRITICAL&limit=20",
            headers=self.auth_headers,
        )

    @task(3)
    def flaw_list_with_affects(self):
        self.client.get(
            "/osidb/api/v1/flaws?include_fields=cve_id,uuid,impact,title,affects&limit=20",
            headers=self.auth_headers,
        )

    @task(3)
    def flaw_list_embargoed(self):
        self.client.get(
            "/osidb/api/v1/flaws?embargoed=true&limit=20",
            headers=self.auth_headers,
        )

    @task(8)
    def flaw_detail(self):
        self._flaw_subresource(None)

    # ── Affect endpoints ──────────────────────────────────────────────

    @task(5)
    def affect_list(self):
        self.client.get("/osidb/api/v1/affects?limit=50", headers=self.auth_headers)

    @task(3)
    def affect_list_filtered(self):
        self.client.get(
            "/osidb/api/v1/affects?affectedness=AFFECTED&limit=20",
            headers=self.auth_headers,
        )

    # ── Tracker endpoints ─────────────────────────────────────────────

    @task(4)
    def tracker_list(self):
        self.client.get("/osidb/api/v1/trackers?limit=50", headers=self.auth_headers)

    @task(2)
    def tracker_list_filtered(self):
        self.client.get(
            "/osidb/api/v1/trackers?type=JIRA&limit=20", headers=self.auth_headers
        )

    # ── Alert endpoints ───────────────────────────────────────────────

    @task(3)
    def alert_list(self):
        self.client.get("/osidb/api/v1/alerts?limit=50", headers=self.auth_headers)

    # ── Flaw sub-resource endpoints ───────────────────────────────────

    def _flaw_subresource(self, sub):
        suffix = f" ({sub})" if sub else ""
        resp = self.client.get(
            "/osidb/api/v1/flaws?include_fields=uuid&limit=1",
            headers=self.auth_headers,
            name=f"/osidb/api/v1/flaws (get uuid{suffix})",
        )
        if not resp.ok:
            return
        results = resp.json().get("results", [])
        if results:
            uuid = results[0]["uuid"]
            path = f"/osidb/api/v1/flaws/{uuid}"
            name = "/osidb/api/v1/flaws/[uuid]"
            if sub:
                path += f"/{sub}"
                name += f"/{sub}"
            self.client.get(path, headers=self.auth_headers, name=name)

    @task(4)
    def flaw_comments(self):
        self._flaw_subresource("comments")

    @task(3)
    def flaw_cvss_scores(self):
        self._flaw_subresource("cvss_scores")

    @task(2)
    def flaw_references(self):
        self._flaw_subresource("references")

    @task(2)
    def flaw_acknowledgments(self):
        self._flaw_subresource("acknowledgments")

    @task(2)
    def flaw_package_versions(self):
        self._flaw_subresource("package_versions")

    # ── Other endpoints ───────────────────────────────────────────────

    @task(2)
    def status(self):
        self.client.get(
            "/osidb/api/v1/status",
            headers=self.auth_headers,
        )

    @task(1)
    def whoami(self):
        self.client.get(
            "/osidb/whoami",
            headers=self.auth_headers,
        )

    # ── v2 endpoints ──────────────────────────────────────────────────

    @task(3)
    def flaw_list_v2(self):
        self.client.get(
            "/osidb/api/v2/flaws?limit=20",
            headers=self.auth_headers,
        )

    @task(2)
    def affect_list_v2(self):
        self.client.get(
            "/osidb/api/v2/affects?limit=20",
            headers=self.auth_headers,
        )

    @task(2)
    def tracker_list_v2(self):
        self.client.get(
            "/osidb/api/v2/trackers?limit=20",
            headers=self.auth_headers,
        )
