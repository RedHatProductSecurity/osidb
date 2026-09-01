import uuid

import pytest

from osidb.models import (
    AliasLabel,
    BULabel,
    BULabelDefinition,
    CollaboratorLabel,
    CollaboratorLabelDefinition,
    Flaw,
    FlawSource,
    Impact,
    ProductFamilyLabel,
    WorkflowLabel,
)

from .factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestSearch:
    def _assert_query_results(self, auth_client, test_api_uri, cases):
        for query, expected_cve_ids in cases:
            response = auth_client().get(f"{test_api_uri}/flaws?query={query}")
            assert response.status_code == 200, (query, response.json())
            body = response.json()
            assert {flaw["cve_id"] for flaw in body["results"]} == expected_cve_ids, (
                query,
                body,
            )
            assert body["count"] == len(expected_cve_ids), (query, body)

    def test_search_flaws_on_create(self, auth_client, test_api_uri):
        """Test Flaw text-search vectors for each text field are created when Flaw is inserted"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="CVE-2022-1234 kernel: TITLE",
            comment_zero="COMMENT_ZERO",
            cve_description="CVE_DESCRIPTION",
            statement="STATEMENT",
            embargoed=False,
        )

        response = auth_client().get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=cve_description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=statement")
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
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        acl_read = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        acl_write = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]
        meta_attr = {"test": 1}

        flaw = Flaw(
            cve_id=good_cve_id,
            cwe_id="CWE-1",
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            title="TITLE",
            comment_zero="COMMENT_ZERO",
            impact=Impact.CRITICAL,
            components=["kernel"],
            source=FlawSource.INTERNET,
            cve_description="CVE_DESCRIPTION",
            statement="STATEMENT",
            acl_read=acl_read,
            acl_write=acl_write,
            # META
            meta_attr=meta_attr,
        )

        assert flaw.save() is None
        AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.title = "NOMORETITLE"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client().get(f"{test_api_uri}/flaws?search=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.comment_zero = "NOMORECOMMENT_ZERO"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client().get(f"{test_api_uri}/flaws?search=cve_description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.cve_description = "NOMORECVEDESCRIPTION"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=cve_description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client().get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.statement = "NOMORESTATEMENT"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    def test_search_flaws_rankings(self, auth_client, test_api_uri):
        """Test Flaw search results are ranked based on relevance, weighted based on which field matched"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="CVE-2022-1234 kernel: words",
            comment_zero="words",
            cve_description="words",
            statement="words",
            embargoed=False,
        )

        FlawFactory(embargoed=False, title="CVE-2022-1234 kernel: words")

        FlawFactory(comment_zero="words", embargoed=False)

        FlawFactory(cve_description="words")

        FlawFactory(statement="words")

        response = auth_client().get(
            f"{test_api_uri}/flaws?search=word"  # Full-text search for "word" in any text field
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 5
        )  # 5 Flaws have "words" in a text field, "word" should match due to stemming
        # First / most relevant match should be the Flaw with "words" in every field (most number of matches)
        assert body["results"][0]["title"] == "CVE-2022-1234 kernel: words"
        assert body["results"][0]["comment_zero"] == "words"
        assert body["results"][0]["cve_description"] == "words"
        assert body["results"][0]["statement"] == "words"

        # Following results are ranked based on what field "word" appears in
        # Matches in title are weighted highest (1.0), followed by comment_zero (0.4), cve_description (0.2), and statement (0.1)
        assert body["results"][1]["title"] == "CVE-2022-1234 kernel: words"
        assert body["results"][2]["comment_zero"] == "words"
        assert body["results"][3]["cve_description"] == "words"
        assert body["results"][4]["statement"] == "words"

    def test_search_flaws_on_particular_columns(self, auth_client, test_api_uri):
        """Test Flaws can be searched based on a specified text column instead of all text columns"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            owner="example@redhat.com",
            workflow_state="TRIAGE",
        )

        FlawFactory(
            title="other summary",
            comment_zero="this is a flaw",
            cve_description="spooky flaw",
            embargoed=False,
            statement="other",
            owner="example_two@redhat.com",
            workflow_state="NEW",
        )

        # Full-text search only in title column
        response = auth_client().get(f"{test_api_uri}/flaws?title=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?comment_zero=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(
            f"{test_api_uri}/flaws?cve_description=cve_description"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?statement=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?owner=example@redhat.com")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?workflow_state=TRIAGE")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?workflow_state=NEW,TRIAGE")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2

    def test_search_flaws_by_similar_cve(self, auth_client, test_api_uri):
        """Test searching flaws by similar or partial CVEs."""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0414",
        )
        FlawFactory(
            title="other flaw",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0489",
        )
        FlawFactory(
            title="flaw with different CVE",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2008-0514",
        )

        # Search with partial CVE
        response = auth_client().get(f"{test_api_uri}/flaws?search=CVE-2001-04")
        assert response.status_code == 200
        body = response.json()
        # The third flaw should not be found with this query
        assert body["count"] == 2
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"
        assert body["results"][1]["cve_id"] == "CVE-2001-0489"

        # Search with similar CVE
        response = auth_client().get(f"{test_api_uri}/flaws?search=CVE-2001-0417")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"

    def test_search_flaws_by_query(self, auth_client, test_api_uri):
        """Test searching flaws by djangoql query."""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0414",
        )
        FlawFactory(
            title="other flaw",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0489",
        )
        FlawFactory(
            title="other flaw",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=True,
            statement="statement",
            cve_id="CVE-2001-0494",
        )
        FlawFactory(
            title="flaw with different CVE",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2008-0514",
        )

        # Search with djangoql query
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=title startswith "flaw"'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == "CVE-2008-0514"

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=cve_id startswith "CVE-2001" and title = "title"'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"

        # Combine djangoql query with search
        response = auth_client().get(
            f'{test_api_uri}/flaws?embargoed=False&order=cve_id&query=cve_id startswith "CVE-2001"'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"
        assert body["results"][1]["cve_id"] == "CVE-2001-0489"

    def test_search_flaws_by_labels_query(self, auth_client, test_api_uri):
        """Test searching flaws by labels using djangoql query"""
        CollaboratorLabelDefinition.objects.create(name="label_a")
        CollaboratorLabelDefinition.objects.create(name="label_b")
        CollaboratorLabelDefinition.objects.create(name="label_c")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        flaw1.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw1.save()
        CollaboratorLabel.objects.create(
            flaw=flaw1,
            name="label_a",
            state=CollaboratorLabel.State.NEW,
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        flaw2.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw2.save()
        CollaboratorLabel.objects.create(
            flaw=flaw2,
            name="label_a",
            state=CollaboratorLabel.State.NEW,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw2,
            name="label_b",
            state=CollaboratorLabel.State.NEW,
        )

        flaw3 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw3)
        flaw3.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw3.save()
        CollaboratorLabel.objects.create(
            flaw=flaw3,
            name="label_a",
            state=CollaboratorLabel.State.NEW,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw3,
            name="label_b",
            state=CollaboratorLabel.State.NEW,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw3,
            name="label_c",
            state=CollaboratorLabel.State.NEW,
        )

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 3
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw1.cve_id,
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_b")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_b","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == flaw3.cve_id

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == flaw3.cve_id

        response = auth_client().get(f'{test_api_uri}/flaws?query=labels != "label_a"')
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        # Repeated operands must not inflate the required label count.
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_a")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 3
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw1.cve_id,
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels not in ("label_c","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw1.cve_id,
            flaw2.cve_id,
        }

    def test_search_labels_not_exposed(self, auth_client, test_api_uri):
        """Fields not whitelisted in FLAW_LABEL_PROPERTY_FIELDS stay unreachable via dotted access"""
        FlawFactory(embargoed=False)

        # Note: this must be a name that also doesn't happen to be a real
        # field on Flaw itself. resolve_name()'s fallback for dotted access
        # doesn't treat the flat "labels" field as a relation, so on the 2nd
        # segment it re-checks against Flaw's own fields (e.g. "labels.foo"
        # would wrongly resolve to Flaw.foo if such a field existed). "uuid"
        # is whitelisted precisely to avoid that trap (see FlawLabelUuidField).
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels.nonexistent = "test"'
        )
        assert response.status_code == 400
        assert "Unknown field: nonexistent" in response.json()["detail"]

    def test_search_flaws_by_label_name_and_type(self, auth_client, test_api_uri):
        """
        "labels.name" and "labels.type" are queryable via dotted access, same as
        "labels.contributor"/"labels.state"/"labels.relevant". Unlike those,
        "name" and "type" live on the base FlawLabel rather than a subclass:
        "name" behaves exactly like the bare "labels" field, and "type" maps
        the LabelType enum value (e.g. "context_based") to the polymorphic
        content type of the matching subclass, since it isn't a real column.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        CollaboratorLabel.objects.create(
            flaw=flaw1, name="collab-a", state=CollaboratorLabel.State.NEW
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        alias_label = AliasLabel.objects.create(flaw=flaw2, name="CVE-1234-ALIAS")

        cases = [
            ('labels.name = "collab-a"', {flaw1.cve_id}),
            ('labels.type = "context_based"', {flaw1.cve_id}),
            ('labels.type = "alias"', {flaw2.cve_id}),
            ('labels.type != "alias"', {flaw1.cve_id}),
            (f'labels.uuid = "{alias_label.uuid}"', {flaw2.cve_id}),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

        # Values outside the LabelType enum are rejected rather than
        # silently matching nothing.
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels.type = "bogus"'
        )
        assert response.status_code == 400

    def test_search_flaws_by_labels_query_operators(self, auth_client, test_api_uri):
        """
        The "labels" DjangoQL field is a StrField, so the UI/schema legally offers
        the full set of string operators (~, !~, startswith, endswith and their
        "not" variants), not just "=", "!=", "in" and "not in".

        FlawLabelsField.get_lookup() routes all of them through the shared
        StrField operator mapping, so each must filter by label name correctly.
        """
        CollaboratorLabelDefinition.objects.create(name="kernel-fix")
        CollaboratorLabelDefinition.objects.create(name="other")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        CollaboratorLabel.objects.create(
            flaw=flaw1, name="kernel-fix", state=CollaboratorLabel.State.NEW
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        CollaboratorLabel.objects.create(
            flaw=flaw2, name="other", state=CollaboratorLabel.State.NEW
        )

        cases = [
            ('labels ~ "kernel"', {flaw1.cve_id}),
            ('labels !~ "kernel"', {flaw2.cve_id}),
            ('labels startswith "kernel"', {flaw1.cve_id}),
            ('labels not startswith "kernel"', {flaw2.cve_id}),
            ('labels endswith "fix"', {flaw1.cve_id}),
            ('labels not endswith "fix"', {flaw2.cve_id}),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_properties(self, auth_client, test_api_uri):
        """
        Fields that only exist on FlawLabel subclasses (contributor, state, relevant)
        are queryable via DjangoQL through dotted access on the flat "labels"
        field, e.g. "labels.contributor = ...", including their "!=" negation.

        FlawQLSchema.resolve_name() routes these dotted names to
        FlawLabelPropertyField, which OR's the lookup across whichever FlawLabel
        subclasses actually define the property. "labels.name" and
        "labels.type" are covered separately in
        test_search_flaws_by_label_name_and_type; fields not whitelisted at
        all stay unreachable (see test_search_labels_not_exposed).
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        CollaboratorLabelDefinition.objects.create(name="collab-b")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        CollaboratorLabel.objects.create(
            flaw=flaw1,
            name="collab-a",
            contributor="alice@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        # A second matching label on the same flaw, so a query joining
        # through "labels" fans out to multiple rows before dedup.
        CollaboratorLabel.objects.create(
            flaw=flaw1,
            name="collab-b",
            contributor="alice@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        CollaboratorLabel.objects.create(
            flaw=flaw2,
            name="collab-a",
            contributor="bob@example.com",
            state=CollaboratorLabel.State.DONE,
            relevant=False,
        )

        # A flaw with no CollaboratorLabel at all, only BULabel and
        # ProductFamilyLabel, so the OR-across-subclasses lookup in
        # FlawLabelPropertyField is actually exercised for those subclasses
        # too, not just CollaboratorLabel.
        BULabelDefinition.objects.create(name="bu-a")
        flaw3 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw3)
        BULabel.objects.create(
            flaw=flaw3,
            name="bu-a",
            contributor="carol@example.com",
            state=BULabel.State.REQ,
            relevant=True,
        )
        ProductFamilyLabel.objects.create(flaw=flaw3, name="pf-a", relevant=True)

        cases = [
            ('labels.contributor = "alice@example.com"', {flaw1.cve_id}),
            ('labels.contributor = "bob@example.com"', {flaw2.cve_id}),
            # BULabel-only flaw: proves the "bulabel" branch of the OR works.
            ('labels.contributor = "carol@example.com"', {flaw3.cve_id}),
            ('labels.state = "DONE"', {flaw2.cve_id}),
            ('labels.state = "REQ"', {flaw3.cve_id}),
            # flaw3 is relevant via its BULabel/ProductFamilyLabel rows.
            ("labels.relevant = True", {flaw1.cve_id, flaw3.cve_id}),
            ("labels.relevant = False", {flaw2.cve_id}),
            # "!=" exercises the invert branch of
            # FlawLabelPropertyField.get_lookup(). flaw3 has no
            # CollaboratorLabel/BULabel contributor/state equal to the
            # excluded value, so it satisfies these negations too.
            ('labels.contributor != "alice@example.com"', {flaw2.cve_id, flaw3.cve_id}),
            ('labels.state != "DONE"', {flaw1.cve_id, flaw3.cve_id}),
            ("labels.relevant != True", {flaw2.cve_id}),
        ]
        # flaw1 has two matching labels for some of these queries; make
        # sure the fan-out join is deduplicated before pagination.
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_any_parity(self, auth_client, test_api_uri):
        """
        "labels.any.<field>" and "labels.all.<field>" are new dotted-name
        quantifiers for the FlawLabelPropertyField family (contributor,
        state, relevant only - name/uuid/type stay bare-only). Unlike the
        bare 2-part "labels.<field>" form (which ORs matching rows and then
        negates the whole OR for "!="), the quantifiers evaluate the
        operator literally per row:

            labels.any.<field> <op> <value> - True if at least one
                qualifying label row satisfies the condition as written.
            labels.all.<field> <op> <value> - True only if every qualifying
                label row satisfies the condition as written, and False (not
                vacuously True) when there are zero qualifying rows.

        Each scenario in this test group uses its own isolated flaw
        fixtures: a query like "labels.all.contributor != <value>" is
        legitimately true for any flaw whose labels never contain that
        value, so sharing fixtures across scenarios would let unrelated
        flaws satisfy each other's assertions.

        This one: labels.any.<field> behaves like bare labels.<field> for a
        positive operator.
        """
        CollaboratorLabelDefinition.objects.create(name="solo")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        CollaboratorLabel.objects.create(
            flaw=flaw,
            name="solo",
            contributor="alice-parity@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        cases = [
            ('labels.any.contributor = "alice-parity@example.com"', {flaw.cve_id}),
            ('labels.contributor = "alice-parity@example.com"', {flaw.cve_id}),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_all_positive_operator(
        self, auth_client, test_api_uri
    ):
        """
        ALL with a positive operator: matches only when every qualifying
        row satisfies it. Isolated fixtures - see
        test_search_flaws_by_label_any_parity for why.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        CollaboratorLabelDefinition.objects.create(name="collab-b")

        flaw_match = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_match)
        CollaboratorLabel.objects.create(
            flaw=flaw_match,
            name="collab-a",
            contributor="alice-allpos@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_match,
            name="collab-b",
            contributor="alice-allpos@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        flaw_nomatch = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_nomatch)
        CollaboratorLabel.objects.create(
            flaw=flaw_nomatch,
            name="collab-a",
            contributor="carol-allpos@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_nomatch,
            name="collab-b",
            contributor="dave-allpos@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        cases = [
            (
                'labels.all.contributor = "alice-allpos@example.com"',
                {flaw_match.cve_id},
            ),
            ('labels.all.contributor = "carol-allpos@example.com"', set()),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_all_negative_operator(
        self, auth_client, test_api_uri
    ):
        """
        ALL with a negative operator. Isolated fixtures - see
        test_search_flaws_by_label_any_parity for why.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        CollaboratorLabelDefinition.objects.create(name="collab-b")

        flaw_match = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_match)
        CollaboratorLabel.objects.create(
            flaw=flaw_match,
            name="collab-a",
            contributor="eve-allneg@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_match,
            name="collab-b",
            contributor="frank-allneg@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        flaw_nomatch = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_nomatch)
        CollaboratorLabel.objects.create(
            flaw=flaw_nomatch,
            name="collab-a",
            contributor="zack-excluded@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_nomatch,
            name="collab-b",
            contributor="yara-allneg@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        cases = [
            # Neither flaw has this exact contributor anywhere, so every row
            # of both flaws satisfies "!= <value>" -> both match.
            (
                'labels.all.contributor != "analyst-does-not-exist@example.com"',
                {flaw_match.cve_id, flaw_nomatch.cve_id},
            ),
            # flaw_nomatch has a row whose contributor *is*
            # "zack-excluded@example.com", so that row violates "!= zack" ->
            # only flaw_match, which has no such row, matches.
            (
                'labels.all.contributor != "zack-excluded@example.com"',
                {flaw_match.cve_id},
            ),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_any_all_zero_qualifying_rows(
        self, auth_client, test_api_uri
    ):
        """
        Zero qualifying rows: False for both ANY and ALL, regardless of
        operator sign, on a label-less flaw and on a flaw whose only labels
        (Workflow/Alias) don't define "contributor" at all. Isolated
        fixtures - see test_search_flaws_by_label_any_parity for why (a
        query like "contributor != x" for an "x" that appears nowhere would
        otherwise also match any *other* flaw's qualifying rows sharing the
        same test).
        """
        flaw_empty = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_empty)

        flaw_no_contrib_subclass = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_no_contrib_subclass)
        WorkflowLabel.objects.create(flaw=flaw_no_contrib_subclass, name="wf-a")
        AliasLabel.objects.create(flaw=flaw_no_contrib_subclass, name="CVE-9999-ALIAS")

        cases = [
            ('labels.all.contributor = "x"', set()),
            ('labels.all.contributor != "x"', set()),
            ('labels.any.contributor = "x"', set()),
            ('labels.any.contributor != "x"', set()),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_any_all_polymorphic_subclass_spread(
        self, auth_client, test_api_uri
    ):
        """
        .any/.all OR/AND across subclass tables (BULabel + CollaboratorLabel
        both define "contributor"), not just within one. Isolated fixtures -
        see test_search_flaws_by_label_any_parity for why.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        BULabelDefinition.objects.create(name="bu-a")

        flaw_bu_only = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_bu_only)
        BULabel.objects.create(
            flaw=flaw_bu_only,
            name="bu-a",
            contributor="grace-poly@example.com",
            state=BULabel.State.REQ,
            relevant=True,
        )

        flaw_and_match = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_and_match)
        BULabel.objects.create(
            flaw=flaw_and_match,
            name="bu-a",
            contributor="henry-poly@example.com",
            state=BULabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_and_match,
            name="collab-a",
            contributor="henry-poly@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        flaw_and_nomatch = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_and_nomatch)
        BULabel.objects.create(
            flaw=flaw_and_nomatch,
            name="bu-a",
            contributor="ian-poly@example.com",
            state=BULabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_and_nomatch,
            name="collab-a",
            contributor="jane-poly@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        cases = [
            (
                'labels.any.contributor = "grace-poly@example.com"',
                {flaw_bu_only.cve_id},
            ),
            (
                'labels.all.contributor = "grace-poly@example.com"',
                {flaw_bu_only.cve_id},
            ),
            (
                'labels.all.contributor = "henry-poly@example.com"',
                {flaw_and_match.cve_id},
            ),
            (
                'labels.any.contributor = "ian-poly@example.com"',
                {flaw_and_nomatch.cve_id},
            ),
            ('labels.all.contributor = "ian-poly@example.com"', set()),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_any_all_in_not_in_operator(
        self, auth_client, test_api_uri
    ):
        """
        Operator breadth: in/not in on contributor. Isolated fixtures - see
        test_search_flaws_by_label_any_parity for why.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        CollaboratorLabelDefinition.objects.create(name="collab-b")

        flaw_in_match = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_in_match)
        CollaboratorLabel.objects.create(
            flaw=flaw_in_match,
            name="collab-a",
            contributor="kevin-in@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_in_match,
            name="collab-b",
            contributor="laura-in@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        flaw_in_nomatch = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_in_nomatch)
        CollaboratorLabel.objects.create(
            flaw=flaw_in_nomatch,
            name="collab-a",
            contributor="kevin-in@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_in_nomatch,
            name="collab-b",
            contributor="mia-in@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        flaw_notin_match = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_notin_match)
        CollaboratorLabel.objects.create(
            flaw=flaw_notin_match,
            name="collab-a",
            contributor="nora-notin@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_notin_match,
            name="collab-b",
            contributor="oscar-notin@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        cases = [
            (
                'labels.any.contributor in ("kevin-in@example.com", "laura-in@example.com")',
                {flaw_in_match.cve_id, flaw_in_nomatch.cve_id},
            ),
            (
                'labels.all.contributor in ("kevin-in@example.com", "laura-in@example.com")',
                {flaw_in_match.cve_id},
            ),
            (
                'labels.any.contributor not in ("kevin-in@example.com", "laura-in@example.com")',
                {flaw_in_nomatch.cve_id, flaw_notin_match.cve_id},
            ),
            (
                'labels.all.contributor not in ("kevin-in@example.com", "laura-in@example.com")',
                {flaw_notin_match.cve_id},
            ),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_any_all_state(self, auth_client, test_api_uri):
        """
        .any.state / .all.state with =/!=. Isolated fixtures - see
        test_search_flaws_by_label_any_parity for why.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        CollaboratorLabelDefinition.objects.create(name="collab-b")

        flaw_mixed = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_mixed)
        CollaboratorLabel.objects.create(
            flaw=flaw_mixed,
            name="collab-a",
            contributor="p-state@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_mixed,
            name="collab-b",
            contributor="q-state@example.com",
            state=CollaboratorLabel.State.DONE,
            relevant=True,
        )

        flaw_alldone = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_alldone)
        CollaboratorLabel.objects.create(
            flaw=flaw_alldone,
            name="collab-a",
            contributor="r-state@example.com",
            state=CollaboratorLabel.State.DONE,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_alldone,
            name="collab-b",
            contributor="s-state@example.com",
            state=CollaboratorLabel.State.DONE,
            relevant=True,
        )

        cases = [
            ('labels.any.state = "DONE"', {flaw_mixed.cve_id, flaw_alldone.cve_id}),
            ('labels.all.state = "DONE"', {flaw_alldone.cve_id}),
            ('labels.any.state != "DONE"', {flaw_mixed.cve_id}),
            ('labels.all.state != "DONE"', set()),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_any_all_relevant(self, auth_client, test_api_uri):
        """
        .any.relevant / .all.relevant (BoolField) with =/!=. Isolated
        fixtures - see test_search_flaws_by_label_any_parity for why.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        CollaboratorLabelDefinition.objects.create(name="collab-b")

        flaw_mixed = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_mixed)
        CollaboratorLabel.objects.create(
            flaw=flaw_mixed,
            name="collab-a",
            contributor="t-rel@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_mixed,
            name="collab-b",
            contributor="u-rel@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=False,
        )

        flaw_alltrue = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw_alltrue)
        CollaboratorLabel.objects.create(
            flaw=flaw_alltrue,
            name="collab-a",
            contributor="v-rel@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw_alltrue,
            name="collab-b",
            contributor="w-rel@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        cases = [
            (
                "labels.any.relevant = True",
                {flaw_mixed.cve_id, flaw_alltrue.cve_id},
            ),
            ("labels.all.relevant = True", {flaw_alltrue.cve_id}),
            ("labels.any.relevant = False", {flaw_mixed.cve_id}),
            ("labels.all.relevant = False", set()),
            ("labels.any.relevant != True", {flaw_mixed.cve_id}),
            ("labels.all.relevant != True", set()),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_flaws_by_label_any_all_validation(self, auth_client, test_api_uri):
        """
        Unknown quantifier segment, and quantifier applied to a field
        outside the whitelisted three (contributor/state/relevant) both fall
        through to the same "Unknown field" 400 as any other unresolvable
        dotted name.
        """
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels.every.contributor = "x"'
        )
        assert response.status_code == 400
        assert "Unknown field" in response.json()["detail"]

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels.any.name = "x"'
        )
        assert response.status_code == 400
        assert "Unknown field" in response.json()["detail"]

    def test_search_flaws_by_label_contributor_bug_regression(
        self, auth_client, test_api_uri
    ):
        """
        Regression test for the original bug report: a team wants to find
        flaws that have an "unclaimed" label of theirs (contributor not the
        team's own address), but the bare 2-part "labels.contributor not in
        (...)" form ORs across all matching rows and then negates the whole
        thing, so it means "no row has this contributor" rather than "some
        row lacks this contributor" - it can't express the latter. That's
        exactly what "labels.any.contributor" is for.
        """
        CollaboratorLabelDefinition.objects.create(name="middleware_bu")
        CollaboratorLabelDefinition.objects.create(name="openshift_bu")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        CollaboratorLabel.objects.create(
            flaw=flaw,
            name="middleware_bu",
            contributor="analyst@redhat.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        # "unclaimed" - no contributor set for this team's label.
        CollaboratorLabel.objects.create(
            flaw=flaw,
            name="openshift_bu",
            contributor="",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        cases = [
            # The bare "labels.contributor not in (...)" half is evaluated
            # independently across all label rows (it means "no row has
            # this contributor"), not correlated to the "middleware_bu" row
            # matched by labels.name. Expected result is still empty here
            # because analyst@redhat.com *is* a contributor on a label
            # (middleware_bu) - pure regression guard, must stay green
            # independently of the any/all work.
            (
                'labels.name = "middleware_bu" and labels.contributor not in ("analyst@redhat.com")',
                set(),
            ),
            # New capability: "is any label unclaimed by this team" - the
            # openshift_bu row (contributor "") satisfies it.
            ('labels.any.contributor not in ("analyst@redhat.com")', {flaw.cve_id}),
            # ALL requires every row to be unclaimed; middleware_bu violates
            # it.
            ('labels.all.contributor not in ("analyst@redhat.com")', set()),
            # Same contrast with "!=": any is a new capability, bare is
            # unaffected (means "no row equals this", which is false here
            # since middleware_bu does).
            ('labels.any.contributor != "analyst@redhat.com"', {flaw.cve_id}),
            ('labels.contributor != "analyst@redhat.com"', set()),
        ]
        self._assert_query_results(auth_client, test_api_uri, cases)

    def test_search_websearch_exclusion(self, auth_client, test_api_uri):
        """websearch_to_tsquery supports -exclusion, verify it works after query refactor."""
        flaw = FlawFactory(
            title="kernel buffer overflow",
            embargoed=False,
        )
        flaw.refresh_from_db()
        assert flaw.search_vector is not None, "DB trigger must populate search_vector"
        FlawFactory(
            title="userspace buffer overflow",
            embargoed=False,
        )

        response = auth_client().get(
            f"{test_api_uri}/flaws?search=buffer overflow -kernel"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert "userspace" in body["results"][0]["title"]

    def test_search_fts_no_match_returns_empty(self, auth_client, test_api_uri):
        """Verify no false positives from either FTS or trigram path."""
        FlawFactory(title="something else entirely", embargoed=False)

        response = auth_client().get(
            f"{test_api_uri}/flaws?search=nonexistent xyzzy zzzzz"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 0

    def test_search_trigram_partial_cve(self, auth_client, test_api_uri):
        """A partial CVE-ID matches via trigram similarity but not unrelated CVEs."""
        FlawFactory(
            title="Apache Traffic Server vulnerability",
            cve_id="CVE-2024-99999",
            embargoed=False,
        )
        FlawFactory(
            title="unrelated flaw",
            cve_id="CVE-2024-12345",
            embargoed=False,
        )

        response = auth_client().get(f"{test_api_uri}/flaws?search=CVE-2024-1234")
        assert response.status_code == 200
        cve_ids = [r["cve_id"] for r in response.json()["results"]]
        assert "CVE-2024-12345" in cve_ids
        assert "CVE-2024-99999" not in cve_ids

    def test_search_helper_rejects_model_without_search_vector(self):
        """search_helper raises ValueError when called with falsy field_names on a non-Flaw model."""
        from osidb.filters import search_helper
        from osidb.models import Affect

        with pytest.raises(ValueError, match="has no search_vector column"):
            search_helper(Affect.objects.get_queryset(), (), "kernel")
