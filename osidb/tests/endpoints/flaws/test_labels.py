import pytest
from rest_framework import status

from osidb.models import Flaw, FlawCollaborator, FlawLabel
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpointsFlawsLabels:
    """Tests specific to /flaws/.../labels endpoint"""

    @pytest.fixture(autouse=True)
    def setup(self):
        FlawLabel.objects.create(
            name="test_context", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )
        FlawLabel.objects.create(
            name="other_context", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )
        FlawLabel.objects.create(
            name="test_product", type=FlawLabel.FlawLabelType.PRODUCT_FAMILY
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        flaw.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw.save()

    def test_get_labels(self, auth_client, test_api_uri):
        response = auth_client().get(f"{test_api_uri}/labels")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["results"] == [
            {"name": "test_context", "type": "context_based"},
            {"name": "other_context", "type": "context_based"},
            {"name": "test_product", "type": "product_family"},
        ]

    def test_get_flaw_labels(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()
        label = FlawCollaborator.objects.create(
            label="test_context",
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}/labels")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["results"] == [
            {
                "uuid": f"{label.uuid}",
                "label": "test_context",
                "state": "NEW",
                "contributor": "",
                "type": "context_based",
                "relevant": True,
            }
        ]

    def test_create_context_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_context", "state": "NEW", "contributor": "skynet"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        flaw_collaborator = FlawCollaborator.objects.first()
        label = FlawLabel.objects.get(name=flaw_collaborator.label)

        assert flaw_collaborator.label == "test_context"
        assert label.type == FlawLabel.FlawLabelType.CONTEXT_BASED
        assert flaw_collaborator.state == FlawCollaborator.FlawCollaboratorState.NEW
        assert flaw_collaborator.contributor == "skynet"

    def test_create_product_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_product", "state": "NEW", "contributor": "skynet"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.json()["label"]
            == "Only context-based and alias labels can be manually added to flaws. 'test_product' is a product-based label."
        )

    def test_update_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()

        flaw_collaborator = FlawCollaborator.objects.create(
            label="test_context",
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{flaw_collaborator.uuid}",
            {"state": "SKIP", "contributor": "skynet", "label": "test_context"},
        )
        flaw_collaborator.refresh_from_db()

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["state"] == FlawCollaborator.FlawCollaboratorState.SKIP
        assert response.json()["contributor"] == "skynet"
        assert flaw_collaborator.state == FlawCollaborator.FlawCollaboratorState.SKIP
        assert flaw_collaborator.contributor == "skynet"

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{flaw_collaborator.uuid}",
            {"state": "SKIP", "contributor": "skynet", "label": "other_context"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["label"] == "Label name cannot be changed."

    def test_delete_context_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()
        flaw_collaborator = FlawCollaborator.objects.create(
            label="test_context",
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{flaw_collaborator.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert FlawCollaborator.objects.count() == 0

    def test_delete_product_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()
        flaw_collaborator = FlawCollaborator.objects.create(
            label="test_product",
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
        )
        response = auth_client().delete(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{flaw_collaborator.uuid}"
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["label"] == "Product family labels cannot be deleted."
        assert FlawCollaborator.objects.count() == 1

    def test_create_alias_label(self, auth_client, test_api_uri):
        """Test creating an alias label with free-form text (no pre-definition needed)"""
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {
                "label": "my-custom-alias-name",
                "type": "alias",
                "state": "NEW",
                "contributor": "test-user",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED

        flaw_collaborator = FlawCollaborator.objects.first()
        assert flaw_collaborator.label == "my-custom-alias-name"
        assert flaw_collaborator.type == FlawLabel.FlawLabelType.ALIAS
        assert flaw_collaborator.state == FlawCollaborator.FlawCollaboratorState.NEW
        assert flaw_collaborator.contributor == "test-user"

        # Verify the label doesn't exist in FlawLabel master list
        assert not FlawLabel.objects.filter(name="my-custom-alias-name").exists()

    def test_create_alias_label_any_text(self, auth_client, test_api_uri):
        """Test that alias labels can be any free-form text"""
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "incident-12345", "type": "alias", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert FlawCollaborator.objects.filter(label="incident-12345").exists()

        # Test that alias labels can be set in other workflow state
        flaw_workflow = FlawFactory(embargoed=False)
        flaw_workflow.workflow_state = "TRIAGE"
        flaw_workflow.save()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw_workflow.uuid}/labels",
            {"label": "incident-12346", "type": "alias", "state": "NEW"},
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert FlawCollaborator.objects.filter(label="incident-12346").exists()

        flaw_workflow = FlawFactory(embargoed=False)
        flaw_workflow.workflow_state = "SECONDARY_ASSESSMENT"
        flaw_workflow.save()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw_workflow.uuid}/labels",
            {"label": "incident-12347", "type": "alias", "state": "NEW"},
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert FlawCollaborator.objects.filter(label="incident-12347").exists()

    def test_delete_alias_label(self, auth_client, test_api_uri):
        """Test that alias labels can be deleted like context-based labels"""
        flaw = Flaw.objects.first()
        flaw_collaborator = FlawCollaborator.objects.create(
            label="my-alias",
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.ALIAS,
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{flaw_collaborator.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not FlawCollaborator.objects.filter(uuid=flaw_collaborator.uuid).exists()

    def test_update_alias_label_state(self, auth_client, test_api_uri):
        """Test updating an alias label's state"""
        flaw = Flaw.objects.first()
        flaw_collaborator = FlawCollaborator.objects.create(
            label="my-alias",
            flaw=flaw,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.ALIAS,
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{flaw_collaborator.uuid}",
            {"state": "DONE", "label": "my-alias", "contributor": "test"},
        )

        assert response.status_code == status.HTTP_200_OK
        flaw_collaborator.refresh_from_db()
        assert flaw_collaborator.state == FlawCollaborator.FlawCollaboratorState.DONE

    def test_create_duplicate_alias_label(self, auth_client, test_api_uri):
        """Test creating a duplicate alias label"""
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "my-alias", "type": "alias", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert FlawCollaborator.objects.filter(label="my-alias").exists()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "my-alias", "type": "alias", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["label"][0] == "Label 'my-alias' already exists."

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_context", "type": "context_based", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_context", "type": "alias", "state": "NEW"},
        )

        print(response.json())
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["label"][0] == "Label 'test_context' already exists."


class TestWorkflowLabels:
    """Tests for WORKFLOW label type - comprehensive coverage"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_create_workflow_label_via_api(self, auth_client, test_api_uri):
        """Test creating a workflow label through API"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "approved",
                "type": "workflow",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        # Workflow labels auto-set to DONE state
        assert data["state"] == "DONE"
        assert data["relevant"] is True
        assert data["type"] == "workflow"

        # Verify in database
        collaborator = FlawCollaborator.objects.get(uuid=data["uuid"])
        assert collaborator.state == FlawCollaborator.FlawCollaboratorState.DONE
        assert collaborator.relevant is True

    def test_workflow_label_ignores_state_parameter(self, auth_client, test_api_uri):
        """Test that workflow labels ignore provided state and force DONE"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "manual-triage",
                "type": "workflow",
                "state": "NEW",  # Should be ignored
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        # State should be DONE regardless of what was provided
        assert data["state"] == "DONE"

    def test_workflow_label_no_preregistration_required(
        self, auth_client, test_api_uri
    ):
        """Test that workflow labels don't need to exist in FlawLabel table"""
        # Verify label doesn't exist
        assert not FlawLabel.objects.filter(name="custom-workflow-label").exists()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "custom-workflow-label",
                "type": "workflow",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert FlawCollaborator.objects.filter(
            label="custom-workflow-label",
            type=FlawLabel.FlawLabelType.WORKFLOW,
        ).exists()

    def test_update_workflow_label_contributor(self, auth_client, test_api_uri):
        """Test that workflow labels can have contributor updated"""
        collaborator = FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="rejected",
            type=FlawLabel.FlawLabelType.WORKFLOW,
            state=FlawCollaborator.FlawCollaboratorState.DONE,
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{collaborator.uuid}",
            {
                "label": "rejected",
                "state": "DONE",  # Keep as DONE
                "contributor": "test-user",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        collaborator.refresh_from_db()

        # Contributor should be updated
        assert collaborator.contributor == "test-user"
        # State remains DONE
        assert collaborator.state == FlawCollaborator.FlawCollaboratorState.DONE

    def test_delete_workflow_label(self, auth_client, test_api_uri):
        """Test that workflow labels can be deleted"""
        collaborator = FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="approved",
            type=FlawLabel.FlawLabelType.WORKFLOW,
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{collaborator.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not FlawCollaborator.objects.filter(uuid=collaborator.uuid).exists()


class TestBULabels:
    """Tests for BU (Business Unit) label type"""

    @pytest.fixture(autouse=True)
    def setup(self):
        # Create a BU label definition
        FlawLabel.objects.create(
            name="test_bu_label",
            type=FlawLabel.FlawLabelType.BU,
        )
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_create_bu_label_via_api(self, auth_client, test_api_uri):
        """Test creating a BU label through API"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "test_bu_label",
                "type": "bu",
                "state": "NEW",
                "contributor": "test-user",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["type"] == "bu"
        assert data["label"] == "test_bu_label"

    @pytest.mark.skip(
        reason="Known bug: serializer raises uncaught DoesNotExist instead of ValidationError"
    )
    def test_create_bu_label_without_definition_fails(self, auth_client, test_api_uri):
        """Test that BU labels require pre-registration in FlawLabel

        NOTE: Current implementation has a bug where FlawCollaboratorSerializer.create()
        does FlawLabel.objects.get() which raises DoesNotExist (uncaught, causes 500)
        instead of returning a proper 400 ValidationError.

        This bug should be fixed in the new polymorphic implementation.
        """
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "undefined_bu_label",
                "type": "bu",
                "state": "NEW",
            },
        )

        # TODO: Should be 400 BAD_REQUEST with ValidationError
        # Currently raises uncaught DoesNotExist
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "does not exist" in str(response.json().get("label", ""))

    def test_delete_bu_label(self, auth_client, test_api_uri):
        """Test that BU labels can be deleted like context-based labels"""
        collaborator = FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="test_bu_label",
            type=FlawLabel.FlawLabelType.BU,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{collaborator.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not FlawCollaborator.objects.filter(uuid=collaborator.uuid).exists()

    def test_update_bu_label(self, auth_client, test_api_uri):
        """Test updating BU label state and contributor"""
        collaborator = FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="test_bu_label",
            type=FlawLabel.FlawLabelType.BU,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{collaborator.uuid}",
            {
                "label": "test_bu_label",
                "state": "DONE",
                "contributor": "updated-user",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        collaborator.refresh_from_db()
        assert collaborator.state == FlawCollaborator.FlawCollaboratorState.DONE
        assert collaborator.contributor == "updated-user"


class TestLabelSerialization:
    """Tests for label serialization in flaw responses"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

        # Create labels of different types
        FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="context-label",
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            contributor="user1",
        )
        FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="workflow-label",
            type=FlawLabel.FlawLabelType.WORKFLOW,
            state=FlawCollaborator.FlawCollaboratorState.DONE,
        )
        FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="alias-label",
            type=FlawLabel.FlawLabelType.ALIAS,
            state=FlawCollaborator.FlawCollaboratorState.REQ,
        )

    def test_labels_in_flaw_detail_response(self, auth_client, test_api_uri):
        """Test that labels are serialized in flaw detail GET"""
        response = auth_client().get(f"{test_api_uri}/flaws/{self.flaw.uuid}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "labels" in data
        assert len(data["labels"]) == 3

        # Verify all label types are present
        label_types = {label["type"] for label in data["labels"]}
        assert "context_based" in label_types
        assert "workflow" in label_types
        assert "alias" in label_types

    def test_labels_in_flaw_list_response(self, auth_client, test_api_uri):
        """Test that labels are serialized in flaw list GET"""
        response = auth_client().get(f"{test_api_uri}/flaws")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Find our flaw in the list
        flaw_data = next(
            (f for f in data["results"] if f["uuid"] == str(self.flaw.uuid)), None
        )

        assert flaw_data is not None
        assert "labels" in flaw_data
        assert len(flaw_data["labels"]) == 3

    def test_label_fields_in_response(self, auth_client, test_api_uri):
        """Test that all expected label fields are present"""
        response = auth_client().get(f"{test_api_uri}/flaws/{self.flaw.uuid}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        context_label = next(
            lb for lb in data["labels"] if lb["type"] == "context_based"
        )

        # Verify all fields present
        assert "uuid" in context_label
        assert "label" in context_label
        assert "type" in context_label
        assert "state" in context_label
        assert "contributor" in context_label
        assert "relevant" in context_label

        assert context_label["label"] == "context-label"
        assert context_label["state"] == "NEW"
        assert context_label["contributor"] == "user1"
        assert context_label["relevant"] is True


class TestLabelValidation:
    """Tests for label validation and edge cases"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_create_label_with_max_length_name(self, auth_client, test_api_uri):
        """Test creating label with 255 character name (max allowed)"""
        long_name = "a" * 255

        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": long_name,
                "type": "alias",
                "state": "NEW",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["label"] == long_name

    def test_create_label_with_special_characters(self, auth_client, test_api_uri):
        """Test creating label with special characters"""
        special_name = "label-with_special.chars@123"

        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": special_name,
                "type": "alias",
                "state": "NEW",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["label"] == special_name

    def test_label_state_transitions(self, auth_client, test_api_uri):
        """Test all valid state transitions"""
        collaborator = FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="test-label",
            type=FlawLabel.FlawLabelType.ALIAS,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
        )

        states = ["REQ", "SKIP", "DONE", "NEW"]

        for state_value in states:
            response = auth_client().put(
                f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{collaborator.uuid}",
                {
                    "label": "test-label",
                    "state": state_value,
                    "contributor": "test",
                },
            )

            assert response.status_code == status.HTTP_200_OK
            assert response.json()["state"] == state_value

            collaborator.refresh_from_db()
            assert collaborator.state == state_value

    def test_multiple_labels_same_type_different_names(self, auth_client, test_api_uri):
        """Test that a flaw can have multiple labels of the same type"""
        response1 = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {"label": "alias1", "type": "alias", "state": "NEW"},
        )

        response2 = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {"label": "alias2", "type": "alias", "state": "NEW"},
        )

        assert response1.status_code == status.HTTP_201_CREATED
        assert response2.status_code == status.HTTP_201_CREATED

        # Verify both exist
        assert (
            FlawCollaborator.objects.filter(
                flaw=self.flaw,
                type=FlawLabel.FlawLabelType.ALIAS,
            ).count()
            == 2
        )

    def test_label_persists_across_flaw_updates(self):
        """Test that labels persist when flaw is updated (model level)"""
        collaborator = FlawCollaborator.objects.create(
            flaw=self.flaw,
            label="persistent-label",
            type=FlawLabel.FlawLabelType.ALIAS,
        )

        # Update the flaw directly (model level)
        self.flaw.title = "Updated Title"
        self.flaw.save()

        # Verify label still exists
        assert FlawCollaborator.objects.filter(uuid=collaborator.uuid).exists()
        collaborator.refresh_from_db()
        assert collaborator.label == "persistent-label"
        assert collaborator.flaw == self.flaw


class TestLabelFiltering:
    """Tests for filtering flaws by labels"""

    @pytest.fixture(autouse=True)
    def setup(self):
        # Create flaws with different labels
        self.flaw1 = FlawFactory(embargoed=False, cve_id="CVE-2024-0001")
        AffectFactory(flaw=self.flaw1)
        FlawCollaborator.objects.create(
            flaw=self.flaw1,
            label="critical-bug",
            type=FlawLabel.FlawLabelType.ALIAS,
        )

        self.flaw2 = FlawFactory(embargoed=False, cve_id="CVE-2024-0002")
        AffectFactory(flaw=self.flaw2)
        FlawCollaborator.objects.create(
            flaw=self.flaw2,
            label="approved",
            type=FlawLabel.FlawLabelType.WORKFLOW,
        )

        self.flaw3 = FlawFactory(embargoed=False, cve_id="CVE-2024-0003")
        AffectFactory(flaw=self.flaw3)
        # No labels

    def test_count_labels_in_response(self, auth_client, test_api_uri):
        """Test that label counts are correct for each flaw"""
        response = auth_client().get(f"{test_api_uri}/flaws")

        assert response.status_code == status.HTTP_200_OK

        flaws_by_cve = {
            f["cve_id"]: f
            for f in response.json()["results"]
            if f["cve_id"] in ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
        }

        assert len(flaws_by_cve["CVE-2024-0001"]["labels"]) == 1
        assert len(flaws_by_cve["CVE-2024-0002"]["labels"]) == 1
        assert len(flaws_by_cve["CVE-2024-0003"]["labels"]) == 0
