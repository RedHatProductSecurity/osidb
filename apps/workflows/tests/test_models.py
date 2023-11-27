import pytest

from apps.workflows.exceptions import LastStateException, MissingRequirementsException
from apps.workflows.models import Check, State, Workflow
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from osidb.models import Affect, Flaw, FlawSource, Impact
from osidb.tests.factories import (
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    PackageFactory,
)

pytestmark = pytest.mark.unit


def assert_state_equals(current, expected):
    message = f'flaw classified as {current.name}, expected {expected["name"]}'
    assert current.name == expected["name"], message


def assert_workflow_equals(current, expected):
    message = f"flaw classified in {current.name} workflow, expected {expected.name}"
    assert current.name == expected.name, message


class TestCheck:
    @pytest.mark.parametrize(
        "field,factory",
        [
            ("affects", lambda flaw: AffectFactory(flaw=flaw)),
            ("cvss_scores", lambda flaw: FlawCVSSFactory(flaw=flaw)),
            ("package_versions", lambda flaw: PackageFactory(flaw=flaw)),
        ],
    )
    def test_relational_property(self, field, factory):
        """
        test that properties from a relationship with flaw reject
        an empty list and accept it while having at least one element
        """
        flaw = FlawFactory(source=FlawSource.CVE, embargoed=False)
        check = Check(f"has {field}")
        assert not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'

        factory(flaw)
        assert check(flaw), f'check for "{check.name}" failed.'

    def test_function_value(self):
        """
        test if a function without parameters can be used as condition can be checked
        """
        check = Check("is_major_incident_temp")
        # alias
        check_alias = Check("is major incident")

        flaw = FlawFactory(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        AffectFactory(flaw=flaw)
        assert check(flaw) and check_alias(flaw), f'check for "{check.name}" failed.'

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        assert not check_alias(flaw) and not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'

    @pytest.mark.parametrize(
        "field",
        [
            "cve_id",
            "cwe_id",
            "created_dt",
            "impact",
            "description",
            "title",
            "summary",
            "cvss3",
            "source",
        ],
    )
    def test_property_positive(self, field):
        """
        test that flaw containing requested properties passes in check
        """
        # most of properties are being auto generated as non-null by factory
        flaw = FlawFactory(cwe_id="CWE-1", summary="random summary")
        check = Check(f"has {field}")

        assert check(flaw), f'check for "{check.name}" failed.'

    @pytest.mark.parametrize(
        "field,novalue",
        [
            ("cve_id", ""),
            ("cwe_id", ""),
            ("created_dt", ""),
            ("impact", Impact.NOVALUE),
            ("description", ""),
            ("title", ""),
            ("summary", ""),
            ("cvss3", ""),
            ("source", ""),
        ],
    )
    def test_property_negative(self, field, novalue):
        """
        test that flaw only passes a a check if it not contains
        an excluded properties
        """
        flaw = FlawFactory()
        setattr(flaw, field, novalue)
        check = Check(f"not {field}")

        assert check(flaw), f'check for "{check.name}" failed.'

    @pytest.mark.parametrize(
        "field,alias",
        [
            ("cve_id", "cve"),
            ("cwe_id", "cwe"),
        ],
    )
    def test_property_alias(self, field, alias):
        """
        test that check can use aliases
        """
        flaw = FlawFactory()
        setattr(flaw, field, "any value")
        check = Check(f"has {alias}")
        assert check(flaw), f'check for "{check.name}" failed.'

        setattr(flaw, field, "")
        assert not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'

    def test_equals_check(self):
        """
        test that check equals operand
        """
        flaw = FlawFactory(cwe_id="CWE-99")

        check = Check("cwe equals CWE-99")
        assert check(flaw), f'check for "{check.name}" failed.'

        flaw = FlawFactory(cwe_id="CWE-100")
        assert not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'

    def test_not_equals_check(self):
        """
        test that check not equals operand
        """
        flaw = FlawFactory(cwe_id="CWE-100")

        check = Check("cwe not equals CWE-99")
        assert check(flaw), f'check for "{check.name}" failed.'

        flaw = FlawFactory(cwe_id="CWE-99")
        assert not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'


class TestState:
    def test_empty_requirements(self):
        """test that a state with empty requirements accepts any flaw"""
        state = State(
            {
                "name": "random name",
                "requirements": [],
            }
        )
        flaw = FlawFactory()  # random flaw
        assert state.accepts(flaw), "state with no requirements rejects a flaw"

    def test_requirements(self):
        """test that a state accepts a flaw which satisfies its requirements"""

        requirements = [
            "has cve_id",
            "has impact",
            "has cvss3",
            "not cwe",
            "not description",
            "not title",
        ]
        state = State(
            {
                "name": "random name",
                "requirements": requirements,
            }
        )
        flaw = FlawFactory()
        # fields set outside factory to skip validation
        flaw.cwe_id = ""
        flaw.description = ""
        flaw.title = ""

        assert state.accepts(
            flaw
        ), f'flaw doesn\'t met the requirements "{requirements}"'

        flaw.cwe_id = "CWE-1"
        assert not state.accepts(
            flaw
        ), f'state accepted flaw without the requirements "{requirements}"'

        flaw.cwe_id = ""
        flaw.impact = Impact.NOVALUE
        assert not state.accepts(
            flaw
        ), f'state accepted flaw without the requirements "{requirements}"'


class TestWorkflow:
    def test_empty_conditions(self):
        """test that a workflow with empty conditions accepts any flaw"""
        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory()  # random flaw
        assert workflow.accepts(flaw), "workflow with no conditions rejects a flaw"

    @pytest.mark.parametrize(
        "conditions",
        [
            ["has description"],
            ["has description", "has title"],
            ["not description"],
            ["not description", "not title"],
            ["has description", "not title"],
        ],
    )
    def test_satisfied_conditions(self, conditions):
        """test that a workflow accepts a flaw which satisfies its conditions"""

        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": conditions,
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory()
        for condition in conditions:
            mode, attr = condition.split(" ", maxsplit=1)
            attr = attr.replace(" ", "_")
            if mode == "has":
                setattr(flaw, attr, "valid value")
            elif mode == "not":
                setattr(flaw, attr, "")

        assert workflow.accepts(
            flaw
        ), f'flaw was rejected by workflow conditions "{conditions}"'

    @pytest.mark.parametrize(
        "conditions",
        [
            ["has description"],
            ["has description", "has title"],
            ["not description"],
            ["not description", "not title"],
            ["has description", "not title"],
        ],
    )
    def test_unsatisfied_conditions(self, conditions):
        """test that a workflow accepts a flaw which satisfies its conditions"""

        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": conditions,
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory()
        for condition in conditions:
            mode, attr = condition.split(" ", maxsplit=1)
            attr = attr.replace(" ", "_")
            if mode == "has":
                setattr(flaw, attr, "")
            elif mode == "not":
                setattr(flaw, attr, "invalid value in a 'not' condition")

        assert not workflow.accepts(
            flaw
        ), f'flaw was wrongly accepted by workflow conditions "{conditions}"'

        # conditions partially satisfied
        if len(conditions) > 1:
            mode, attr = conditions[0].split(" ", maxsplit=1)
            attr = attr.replace(" ", "_")

            if mode == "has":
                setattr(flaw, attr, "valid value")
            elif mode == "not":
                setattr(flaw, attr, "")
        assert not workflow.accepts(
            flaw
        ), f'flaw was wrongly accepted by workflow conditions "{conditions}"'

    def test_classify(self):
        """test that a flaw is correctly classified in the workflow states"""
        state_new = {
            "name": "new",
            "requirements": [],
        }
        state_first = {"name": "first state", "requirements": ["has description"]}
        state_second = {"name": "second state", "requirements": ["has title"]}

        workflow = Workflow(
            {
                "name": "test workflow",
                "description": "a three step workflow to test classification",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )
        flaw = Flaw()
        assert_state_equals(workflow.classify(flaw), state_new)

        flaw.description = "valid description"
        assert_state_equals(workflow.classify(flaw), state_first)

        flaw.title = "valid title"
        assert_state_equals(workflow.classify(flaw), state_second)

        # Test that a flaw having a later state requirements
        # does not bypass previous states without requirements
        bypass_flaw = Flaw()
        bypass_flaw.cwe_id = "CWE-1"
        assert_state_equals(workflow.classify(bypass_flaw), state_new)


class TestWorkflowFramework:
    def test_classify_priority(self):
        """
        test that a flaw is always classified in the most prior accepting workflow
        """
        new_low = {
            "name": "new low priority state",
            "requirements": [],
        }
        new_high = {
            "name": "new high priority state",
            "requirements": [],
        }

        workflow_low = Workflow(
            {
                "name": "test zero priority workflow",
                "description": "a test workflow",
                "priority": 0,
                "conditions": [],
                "states": [new_low],
            }
        )
        workflow_high = Workflow(
            {
                "name": "test one priority workflow",
                "description": "another test workflow",
                "priority": 1,
                "conditions": [],
                "states": [new_high],
            }
        )

        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow_high)
        workflow_framework.register_workflow(workflow_low)

        flaw = Flaw()
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_high)
        assert_state_equals(classified_state, new_high)

        # register order should not matter
        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow_low)
        workflow_framework.register_workflow(workflow_high)

        flaw = Flaw()
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_high)
        assert_state_equals(classified_state, new_high)

    def test_classify_complete(self):
        """test flaw classification in both workflow and state"""
        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
        }
        state_first = {
            "name": WorkflowModel.WorkflowState.TRIAGE,
            "requirements": ["has description"],
        }
        state_second = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": ["has title"],
        }

        workflow_main = Workflow(
            {
                "name": "main workflow",
                "description": "a three step workflow to test classification",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )

        state_not_affected = {
            "name": WorkflowModel.WorkflowState.REJECTED,
            "requirements": [],
        }

        workflow_reject = Workflow(
            {
                "name": "reject workflow",
                "description": "a worflow for rejected flaws",
                "priority": 1,
                "conditions": ["has affects", "affects notaffected"],
                "states": [state_not_affected],
            }
        )

        workflow_framework = WorkflowFramework()
        # remove yml workflows
        workflow_framework._workflows = []
        workflow_framework.register_workflow(workflow_main)
        workflow_framework.register_workflow(workflow_reject)

        flaw = FlawFactory()
        flaw.description = ""
        flaw.title = ""

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_main)
        assert_state_equals(classified_state, state_new)

        flaw.description = "valid description"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_first)

        flaw.title = "valid title"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_second)

        affect = AffectFactory(
            flaw=flaw,
            resolution=Affect.AffectResolution.FIX,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_main)
        assert_state_equals(classified_state, state_second)

        affect.resolution = Affect.AffectResolution.NOVALUE
        affect.affectedness = Affect.AffectAffectedness.NOTAFFECTED
        affect.save()
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_reject)
        assert_state_equals(classified_state, state_not_affected)


class TestFlaw:
    def test_init(self):
        """test that flaw gets workflow:state assigned on creation"""
        flaw = Flaw()
        assert flaw.workflow_name
        assert flaw.workflow_state

    def test_classification(self):
        """test flaw classification property"""
        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
        }
        state_first = {
            "name": WorkflowModel.WorkflowState.TRIAGE,
            "requirements": ["has description"],
        }
        state_second = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": ["has title"],
        }

        workflow_main = Workflow(
            {
                "name": "main workflow",
                "description": "a three step workflow to test classification",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )

        state_not_affected = {
            "name": WorkflowModel.WorkflowState.REJECTED,
            "requirements": [],
        }

        workflow_reject = Workflow(
            {
                "name": "reject workflow",
                "description": "a worflow for rejected flaws",
                "priority": 1,
                "conditions": ["has affects", "affects notaffected"],
                "states": [state_not_affected],
            }
        )

        workflow_framework = WorkflowFramework()
        # remove yml workflows
        workflow_framework._workflows = []
        workflow_framework.register_workflow(workflow_main)
        workflow_framework.register_workflow(workflow_reject)

        flaw = Flaw()

        # stored classification
        assert flaw.workflow_name == flaw.classification["workflow"]
        assert flaw.workflow_state == flaw.classification["state"]
        # computed classification
        old_computed_workflow = flaw.classify()["workflow"]
        old_computed_state = flaw.classify()["state"]
        assert flaw.workflow_name == old_computed_workflow
        assert flaw.workflow_state == old_computed_state
        # assing new and different classification
        for workflow in WorkflowFramework().workflows:
            if workflow.name != flaw.workflow_name:
                for state in workflow.states:
                    if state.name != flaw.workflow_state:
                        new_stored_workflow = workflow.name
                        new_stored_state = state.name
                        flaw.classification = {
                            "workflow": new_stored_workflow,
                            "state": new_stored_state,
                        }
                # prevent asigning same workflow depending on order in the framework
                break

        # stored classification has changed
        assert flaw.workflow_name == new_stored_workflow
        assert flaw.workflow_name == flaw.classification["workflow"]
        assert flaw.workflow_state == new_stored_state
        assert flaw.workflow_state == flaw.classification["state"]
        # computed classification has not changed
        new_computed_workflow = flaw.classify()["workflow"]
        new_computed_state = flaw.classify()["state"]
        assert old_computed_workflow == new_computed_workflow
        assert old_computed_state == new_computed_state
        assert flaw.workflow_name != new_computed_workflow
        assert flaw.workflow_state != new_computed_state

    def test_adjust(self):
        """test flaw classification adjustion after metadata change"""
        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = State(
            {
                "name": WorkflowModel.WorkflowState.NEW,
                "requirements": [],
            }
        )
        state_first = State(
            {
                "name": WorkflowModel.WorkflowState.TRIAGE,
                "requirements": ["has description"],
            }
        )
        state_second = State(
            {
                "name": WorkflowModel.WorkflowState.DONE,
                "requirements": ["has title"],
            }
        )

        states = [state_new, state_first, state_second]

        # initialize default workflow first so there is
        # always some workflow to classify the flaw in
        workflow = Workflow(
            {
                "name": "default workflow",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        # major incident workflow
        workflow = Workflow(
            {
                "name": "major incident workflow",
                "description": "random description",
                "priority": 1,  # is more prior than default one
                "conditions": [
                    "is_major_incident_temp"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "major incident workflow"

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "default workflow"

    def test_adjust_no_change(self):
        """test that adjusting classification has no effect without flaw modification"""
        flaw = FlawFactory()  # random flaw
        classification = flaw.classification
        flaw.adjust_classification()
        assert classification == flaw.classification

    def test_promote(self):
        """test flaw state promotion after data change"""
        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
        }

        state_first = {
            "name": WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            "requirements": ["has cwe"],
        }

        state_second = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": ["has summary"],
        }

        workflow = Workflow(
            {
                "name": "default workflow",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(cwe_id="", summary="")
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "default workflow"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW

        with pytest.raises(MissingRequirementsException, match="has cwe"):
            flaw.promote()
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW

        flaw.cwe_id = "CWE-1"
        assert flaw.promote() is None
        assert (
            flaw.classification["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        with pytest.raises(MissingRequirementsException, match="has summary"):
            flaw.promote()
        assert (
            flaw.classification["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        flaw.summary = "valid summary"
        assert flaw.promote() is None
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.DONE

        with pytest.raises(LastStateException):
            flaw.promote()
