from locust import HttpUser, between, constant_pacing, task


class SFM2User(HttpUser):
    wait_time = between(1, 3)
    weight = 3

    @task
    def get_nvd_cvss_scores(self):
        self.client.get("/osidb/api/v1/flaws?include_fields=cve_id,nvd_cvss2,nvd_cvss3")


class SDEngineUser(HttpUser):
    wait_time = between(1, 3)
    weight = 3

    @task(1)
    def get_status(self):
        payload = {"username": "testuser", "password": "password"}
        headers = {"Content-Type": "application/json"}
        with self.client.post("/auth/token", json=payload, headers=headers) as r:
            token = r.json()["access"]
        self.client.get(
            "/collectors/api/v1/status",
            headers={"Authorization": f"Bearer {token}"},
        )

    @task(4)
    def get_cve_ids(self):
        self.client.get("/osidb/api/v1/flaws?include_fields=cve_id")

    @task(5)
    def get_cve_data(self):
        self.client.get(
            "/osidb/api/v1/flaws?include_meta_attr=mitigation,cvss3_comment,bz_id,bz_summary&exclude_fields=comments,classification&changed_after=2015-01-01T09:00:00Z&limit=60"
        )


class GriffonUser(HttpUser):
    wait_time = between(1, 3600)
    weight = 1

    @task
    def get_affects_from_ps_product(self):
        self.client.get(
            "/osidb/api/v1/flaws?affects__affectedness=AFFECTED&affects__ps_module=cost-management&affects__resolution=FIX&include_fields=cve_id,title,resolution,impact,affects&limit=50"
        )
