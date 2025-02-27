import pytest
from django.core.exceptions import ValidationError

from apps.workflows.workflow import WorkflowModel
from osidb.models import FlawCollaborator, FlawLabel
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestFlawCollaborator:
    def test_unique_constraint(self):
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        flaw.workflow_state = WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        flaw.save()

        label = FlawLabel.objects.create(
            name="test_label", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )

        FlawCollaborator.objects.create(
            flaw=flaw,
            label=label.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            contributor="test_contributor",
        )

        with pytest.raises(ValidationError):
            FlawCollaborator.objects.create(
                flaw=flaw,
                label=label.name,
                state=FlawCollaborator.FlawCollaboratorState.NEW,
                contributor="another_contributor",
            )

    @pytest.mark.enable_signals
    def test_create_labels_on_promote(self):
        FlawLabel.objects.create(
            name="test_component_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_components=["test_component"],
        )
        FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=["test_module"],
        )
        FlawLabel.objects.create(
            name="test_context_label",
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
            ps_modules=["test_module"],
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, ps_component="test_component", ps_module="test_module")
        AffectFactory(
            flaw=flaw, ps_component="test_component", ps_module="other_module"
        )

        assert flaw.labels.count() == 0
        flaw.workflow_state = WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        flaw.save()
        assert flaw.labels.count() == 2

    @pytest.mark.enable_signals
    def test_update_label_on_affect_update(self):
        FlawLabel.objects.create(
            name="test_component_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_components=["test_component"],
        )
        FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=["test_module"],
        )

        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw, ps_component="test_component", ps_module="test_module"
        )
        flaw.workflow_state = WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        flaw.save()

        assert flaw.labels.count() == 2

        affect.ps_module = "other_module"
        affect.save()

        assert flaw.labels.count() == 2
        assert FlawCollaborator.objects.filter(flaw=flaw, relevant=False).count() == 1

    @pytest.mark.enable_signals
    def test_legacy_label(self):
        label = FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=["test_module"],
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, ps_module="test_module")
        flaw.workflow_state = WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        flaw.save()

        assert flaw.labels.count() == 1

        label.delete()
        collaborator = FlawCollaborator.objects.first()
        collaborator.contributor = "skynet"

        # This should not raise an error
        collaborator.save()

    def test_create_from_flaw(self):
        flaw = FlawFactory(
            embargoed=False,
            workflow_state=WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
        )
        FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=["test_module"],
        )

        # This should not raise an error
        FlawCollaborator.objects.create_from_flaw(flaw)
        assert FlawCollaborator.objects.count() == 0

        AffectFactory(flaw=flaw, ps_module="test_module", ps_component="test_component")
        FlawCollaborator.objects.create_from_flaw(flaw)
        assert FlawCollaborator.objects.count() == 1
