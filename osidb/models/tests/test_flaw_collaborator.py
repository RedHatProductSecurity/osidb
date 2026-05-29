import pytest
from django.core.exceptions import ValidationError

from apps.workflows.workflow import WorkflowModel
from osidb.models import FlawCollaborator, FlawLabel
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
)

pytestmark = pytest.mark.unit


class TestFlawCollaborator:
    def test_unique_constraint(self):
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
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
        ps_module = PsModuleFactory()
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module)
        FlawLabel.objects.create(
            name="test_component_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_components=["test_component"],
        )
        FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=[ps_module.name],
        )
        FlawLabel.objects.create(
            name="test_context_label",
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
            ps_modules=[ps_module.name],
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(
            flaw=flaw,
            ps_component="test_component",
            ps_update_stream=ps_update_stream1.name,
        )
        AffectFactory(
            flaw=flaw,
            ps_component="test_component",
            ps_update_stream=ps_update_stream2.name,
        )

        assert flaw.labels.count() == 0
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save()
        assert flaw.labels.count() == 2

    @pytest.mark.enable_signals
    def test_update_label_on_affect_update(self):
        ps_module = PsModuleFactory()
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        ps_update_stream2 = PsUpdateStreamFactory()
        FlawLabel.objects.create(
            name="test_component_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_components=["test_component"],
        )
        FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=[ps_module.name],
        )

        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="test_component",
            ps_update_stream=ps_update_stream1.name,
        )
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save()

        assert flaw.labels.count() == 2

        affect.ps_update_stream = ps_update_stream2.name
        affect.save()

        assert flaw.labels.count() == 2
        assert FlawCollaborator.objects.filter(flaw=flaw, relevant=False).count() == 1

    @pytest.mark.enable_signals
    def test_legacy_label(self):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        label = FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=[ps_module.name],
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, ps_update_stream=ps_update_stream.name)
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save()

        assert flaw.labels.count() == 1

        label.delete()
        collaborator = FlawCollaborator.objects.first()
        collaborator.contributor = "skynet"

        # This should not raise an error
        collaborator.save()

    def test_create_from_flaw(self):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(
            embargoed=False,
            workflow_state=WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT,
        )
        FlawLabel.objects.create(
            name="test_module_label",
            type=FlawLabel.FlawLabelType.PRODUCT_FAMILY,
            ps_modules=[ps_module.name],
        )

        # This should not raise an error
        FlawCollaborator.objects.create_from_flaw(flaw)
        assert FlawCollaborator.objects.count() == 0

        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="test_component",
        )
        FlawCollaborator.objects.create_from_flaw(flaw)
        assert FlawCollaborator.objects.count() == 1

    @pytest.mark.parametrize(
        "workflow_state",
        [
            WorkflowModel.WorkflowState.NOVALUE,
            WorkflowModel.WorkflowState.NEW,
            WorkflowModel.WorkflowState.TRIAGE,
            WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT,
            WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            WorkflowModel.WorkflowState.DONE,
        ],
    )
    def test_labels_can_be_created_in_any_workflow_state(self, workflow_state):
        """Test that labels can be created and updated in any workflow state"""
        label = FlawLabel.objects.create(
            name="test_label", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        flaw.workflow_state = workflow_state
        flaw.save()

        collaborator = FlawCollaborator.objects.create(
            flaw=flaw,
            label=label.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            contributor="test_contributor",
        )
        assert collaborator.pk is not None

    def test_automation_label_prerequisite_no_cve(self):
        """Test for automation label cannot be applied to flaw without a CVE"""
        FlawLabel.objects.get_or_create(
            name="auto-affects",
            defaults={"type": FlawLabel.FlawLabelType.AUTO_AFFECTS},
        )
        flaw = FlawFactory(
            embargoed=False,
            cve_id=None,
            workflow_state=WorkflowModel.WorkflowState.NEW,
        )

        with pytest.raises(ValidationError) as e:
            FlawCollaborator.objects.create(
                flaw=flaw,
                label="auto-affects",
                state=FlawCollaborator.FlawCollaboratorState.NEW,
                type=FlawLabel.FlawLabelType.AUTO_AFFECTS,
            )
        assert "Flaw must have a CVE" in str(e)

    def test_automation_label_mutual_exclusivity(self):
        """Test for applying a new automation label which removes the existing one"""
        FlawLabel.objects.get_or_create(
            name="auto-affects",
            defaults={"type": FlawLabel.FlawLabelType.AUTO_AFFECTS},
        )
        FlawLabel.objects.get_or_create(
            name="auto-rejected",
            defaults={"type": FlawLabel.FlawLabelType.AUTO_REJECTED},
        )
        flaw = FlawFactory(
            embargoed=False,
            workflow_state=WorkflowModel.WorkflowState.NEW,
        )
        AffectFactory(flaw=flaw)

        FlawCollaborator.objects.create(
            flaw=flaw,
            label="auto-affects",
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.AUTO_AFFECTS,
        )
        assert FlawCollaborator.objects.filter(
            flaw=flaw, type=FlawLabel.FlawLabelType.AUTO_AFFECTS
        ).exists()

        FlawCollaborator.objects.create(
            flaw=flaw,
            label="auto-rejected",
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.AUTO_REJECTED,
        )
        assert not FlawCollaborator.objects.filter(
            flaw=flaw, type=FlawLabel.FlawLabelType.AUTO_AFFECTS
        ).exists()
        assert FlawCollaborator.objects.filter(
            flaw=flaw, type=FlawLabel.FlawLabelType.AUTO_REJECTED
        ).exists()

    def test_automation_label_potential_rejection_additive(self):
        """Test for potential-rejection label does not remove other automation label"""
        FlawLabel.objects.get_or_create(
            name="auto-affects",
            defaults={"type": FlawLabel.FlawLabelType.AUTO_AFFECTS},
        )
        FlawLabel.objects.get_or_create(
            name="potential-rejection",
            defaults={"type": FlawLabel.FlawLabelType.POTENTIAL_REJECTION},
        )
        flaw = FlawFactory(
            embargoed=False,
            workflow_state=WorkflowModel.WorkflowState.NEW,
        )
        AffectFactory(flaw=flaw)

        FlawCollaborator.objects.create(
            flaw=flaw,
            label="auto-affects",
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.AUTO_AFFECTS,
        )
        FlawCollaborator.objects.create(
            flaw=flaw,
            label="potential-rejection",
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.POTENTIAL_REJECTION,
        )

        assert FlawCollaborator.objects.filter(
            flaw=flaw, type=FlawLabel.FlawLabelType.AUTO_AFFECTS
        ).exists()
        assert FlawCollaborator.objects.filter(
            flaw=flaw, type=FlawLabel.FlawLabelType.POTENTIAL_REJECTION
        ).exists()
