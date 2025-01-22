import pytest
from rest_framework import status

from apps.workflows.workflow import WorkflowModel
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
        flaw.workflow_state = WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
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
            == "Only context-based labels can be manually added to flaws. 'test_product' is a product-based label."
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
