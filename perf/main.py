from locust import HttpUser, constant_pacing, task


class ChangedFlawsUser(HttpUser):
    wait_time = constant_pacing(1)

    @task
    def changed_after(self):
        self.client.get("/osidb/api/v1/flaws?changed_after=2022-12-01T00:00:00Z")


class ChangedIncludeFlawsUser(HttpUser):
    wait_time = constant_pacing(1)

    @task
    def changed_after(self):
        self.client.get(
            "/osidb/api/v1/flaws?include_fields=cve_id&changed_after=2022-12-01T00:00:00Z"
        )
