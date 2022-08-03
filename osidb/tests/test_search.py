import uuid

import pytest

from osidb.models import Flaw, FlawImpact, FlawResolution, FlawType

from .factories import FlawFactory

pytestmark = pytest.mark.unit


class TestSearch:
    def test_search_flaws_on_create(self, auth_client, test_api_uri):
        """Test Flaw text-search vectors for each text field are created when Flaw is inserted"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="TITLE",
            description="DESCRIPTION",
            summary="SUMMARY",
            statement="STATEMENT",
        )

        response = auth_client.get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client.get(f"{test_api_uri}/flaws?search=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client.get(f"{test_api_uri}/flaws?search=summary")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client.get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

    def test_search_flaws_on_update(
        self,
        auth_client,
        test_api_uri,
        good_cve_id,
        datetime_with_tz,
    ):
        """Test Flaw text-search vectors are updated when corresponding fields are updated"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        acls = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        meta_attr = {"test": 1}

        flaw = Flaw(
            cve_id=good_cve_id,
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            type=FlawType.VULN,
            title="TITLE",
            description="DESCRIPTION",
            impact=FlawImpact.CRITICAL,
            summary="SUMMARY",
            statement="STATEMENT",
            resolution=FlawResolution.NOVALUE,
            acl_read=acls,
            acl_write=acls,
            # META
            meta_attr=meta_attr,
        )

        assert flaw.save() is None

        response = auth_client.get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.title = "NOMORETITLE"
        assert flaw.save() is None

        response = auth_client.get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client.get(f"{test_api_uri}/flaws?search=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.description = "NOMOREDESCRIPTION"
        assert flaw.save() is None

        response = auth_client.get(f"{test_api_uri}/flaws?search=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client.get(f"{test_api_uri}/flaws?search=summary")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.summary = "NOMORESUMMARY"
        assert flaw.save() is None

        response = auth_client.get(f"{test_api_uri}/flaws?search=summary")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client.get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.statement = "NOMORESTATEMENT"
        assert flaw.save() is None

        response = auth_client.get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    def test_search_flaws_rankings(self, auth_client, test_api_uri):
        """Test Flaw search results are ranked based on relevance, weighted based on which field matched"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="words",
            description="words",
            summary="words",
            statement="words",
        )

        FlawFactory(title="words")

        FlawFactory(description="words")

        FlawFactory(summary="words")

        FlawFactory(statement="words")

        response = auth_client.get(
            f"{test_api_uri}/flaws?search=word"  # Full-text search for "word" in any text field
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 5
        )  # 5 Flaws have "words" in a text field, "word" should match due to stemming
        # First / most relevant match should be the Flaw with "words" in every field (most number of matches)
        assert body["results"][0]["title"] == "words"
        assert body["results"][0]["description"] == "words"
        assert body["results"][0]["summary"] == "words"
        assert body["results"][0]["statement"] == "words"

        # Following results are ranked based on what field "word" appears in
        # Matches in title are weighted highest (1.0), followed by description (0.4), summary (0.2), and statement (0.1)
        assert body["results"][1]["title"] == "words"
        assert body["results"][2]["description"] == "words"
        assert body["results"][3]["summary"] == "words"
        assert body["results"][4]["statement"] == "words"

    def test_search_flaws_on_particular_columns(self, auth_client, test_api_uri):
        """Test Flaws can be searched based on a specified text column instead of all text columns"""
        response = auth_client.get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            description="description",
            summary="summary",
            statement="statement",
        )

        # Full-text search only in title column
        response = auth_client.get(f"{test_api_uri}/flaws?title=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client.get(f"{test_api_uri}/flaws?description=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client.get(f"{test_api_uri}/flaws?summary=summary")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client.get(f"{test_api_uri}/flaws?statement=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
