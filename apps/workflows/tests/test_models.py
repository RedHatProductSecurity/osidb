import pytest

from apps.workflows.checks import CheckParser
from apps.workflows.models import Check, Condition, State, Workflow
from apps.workflows.workflow import WorkflowFramework
from osidb.mixins import ACLMixinVisibility
from osidb.models import (
    Affect,
    Flaw,
    FlawCVSS,
    FlawReference,
    FlawSource,
    Impact,
    NotAffectedJustification,
    Tracker,
    WorkflowLabel,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PackageFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestCheckParser:
    """Test CheckParser functionality"""

    def test_parameterized_method_check(self):
        """test that parameterized method checks work correctly"""
        parser = CheckParser()

        # Test has_label_rejected
        doc, check_func = parser.parse("has_label_rejected")
        assert "has_label" in doc
        assert "rejected" in doc

        flaw = FlawFactory()
        assert not check_func(flaw)

        WorkflowLabel.objects.create(flaw=flaw, name="rejected")
        assert check_func(flaw)

    def test_parameterized_method_multiple_labels(self):
        """test parameterized checks with different labels"""
        parser = CheckParser()

        _, check_rejected = parser.parse("has_label_rejected")
        _, check_approved = parser.parse("has_label_approved")

        flaw = FlawFactory()
        assert not check_rejected(flaw)
        assert not check_approved(flaw)

        WorkflowLabel.objects.create(flaw=flaw, name="rejected")
        assert check_rejected(flaw)
        assert not check_approved(flaw)

        WorkflowLabel.objects.create(flaw=flaw, name="approved")
        assert check_rejected(flaw)
        assert check_approved(flaw)

    def test_parameterized_vs_property_precedence(self):
        """test that exact property matches take precedence over parameterized"""
        parser = CheckParser()

        # This should match the property, not be parsed as parameterized
        # (assuming there's a property that could match this pattern)
        doc, _ = parser.parse("has_owner")
        # Should be the has_ non-empty check, not parameterized
        assert "has a value set" in doc

    def test_negative_parameterized_method(self):
        """test negative parameterized method checks"""
        parser = CheckParser()

        doc, check_func = parser.parse("not_has_label_rejected")
        assert "negative of:" in doc
        assert "has_label" in doc
        assert "rejected" in doc

        flaw = FlawFactory()
        # Flaw has no rejected label, so not_has_label_rejected should be True
        assert check_func(flaw)

        WorkflowLabel.objects.create(flaw=flaw, name="rejected")
        # Now flaw has rejected label, so not_has_label_rejected should be False
        assert not check_func(flaw)


def assert_state_equals(current, expected):
    message = f"flaw classified as {current.name}, expected {expected['name']}"
    assert current.name == expected["name"], message


def assert_workflow_equals(current, expected):
    message = f"flaw classified in {current.name} workflow, expected {expected.name}"
    assert current.name == expected.name, message


class TestCheck:
    @pytest.mark.parametrize(
        "field,factory",
        [
            ("affects", lambda flaw: AffectFactory(flaw=flaw)),
            (
                "cvss_scores",
                lambda flaw: FlawCVSSFactory(
                    flaw=flaw, issuer=FlawCVSS.CVSSIssuer.NIST
                ),
            ),
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
        assert not check(flaw), (
            f'check for "{check.name}" should have failed, but passed.'
        )

        factory(flaw)
        assert check(flaw), f'check for "{check.name}" failed.'

    @pytest.mark.parametrize(
        "field",
        [
            "cve_id",
            "cwe_id",
            "created_dt",
            "impact",
            "comment_zero",
            "title",
            "cve_description",
            "source",
        ],
    )
    def test_property_positive(self, field):
        """
        test that flaw containing requested properties passes in check
        """
        # most of properties are being auto generated as non-null by factory
        flaw = FlawFactory(cwe_id="CWE-1", cve_description="random cve_description")
        check = Check(f"has {field}")

        assert check(flaw), f'check for "{check.name}" failed.'

    @pytest.mark.parametrize(
        "field,novalue",
        [
            ("cve_id", ""),
            ("cwe_id", ""),
            ("created_dt", ""),
            ("impact", Impact.NOVALUE),
            ("comment_zero", ""),
            ("title", ""),
            ("cve_description", ""),
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
        assert not check(flaw), (
            f'check for "{check.name}" should have failed, but passed.'
        )

    @pytest.mark.parametrize(
        "attribute,value,check_desc",
        [
            ("cve_id", "CVE-2000-12345", "CVE is CVE-2000-12345"),
            ("cwe_id", "CWE-100", "CWE is CWE-100"),
            ("impact", Impact.CRITICAL, "impact is critical"),
            ("source", FlawSource.CUSTOMER, "source is customer"),
            ("title", "whatever", "title is whatever"),
        ],
    )
    def test_equals(self, attribute, value, check_desc):
        """
        test equality check parsing and resolution
        """
        flaw = FlawFactory()
        setattr(flaw, attribute, value)
        check = Check(check_desc)

        assert check.name == check_desc
        # here we do a case insensitive check as there is
        # a different case handling for the text choices
        assert (
            check.description.lower()
            == f"check that Flaw attribute {attribute} has a value equal to {value}".lower()
        )
        assert check(flaw), f"Check failed: {check.name}"

    def test_equals_failed(self):
        """
        test that equality check fails with unexpected value
        """
        check = Check("cwe is CWE-99")
        assert not check(FlawFactory(cwe_id="CWE-100")), (
            f'check for "{check.name}" should have failed, but passed.'
        )

    def test_equals_text_choices_property(self):
        """
        test comparison check parsing and resolution
        of the property returning TextChoices values
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False, impact=Impact.LOW)
        affect = AffectFactory(
            flaw=flaw,
            impact=None,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        check = Check("aggregated impact is low", cls=Tracker)
        assert check(tracker), f"Check failed: {check.name}"

    @pytest.mark.parametrize(
        "attribute,value,not_value,check_desc",
        [
            ("cve_id", "CVE-2000-12345", "CVE-2000-3000", "CVE is not CVE-2000-3000"),
            ("cwe_id", "CWE-100", "CWE-200", "CWE is not CWE-200"),
            ("impact", Impact.CRITICAL, "low", "impact is not low"),
            ("source", FlawSource.CUSTOMER, "internet", "source is not internet"),
            ("title", "whatever", "banana", "title is not banana"),
        ],
    )
    def test_not_equals(self, attribute, value, not_value, check_desc):
        """
        test negative equality check parsing and resolution
        """
        flaw = FlawFactory()
        setattr(flaw, attribute, value)
        check = Check(check_desc)

        assert check.name == check_desc
        # here we do a case insensitive check as there is
        # a different case handling for the text choices
        assert (
            check.description.lower()
            == f"negative of: check that Flaw attribute {attribute} has a value equal to {not_value}".lower()
        )
        assert check(flaw), f"Check failed: {check.name}"

    def test_not_equals_failed(self):
        """
        test that negative equality check fails with expected value
        """
        check = Check("cwe not is CWE-100")
        assert not check(FlawFactory(cwe_id="CWE-100")), (
            f'check for "{check.name}" should have failed, but passed.'
        )

    @pytest.mark.parametrize(
        "cls,factory,field,value",
        [
            (Affect, AffectFactory, "impact", Impact.CRITICAL),
            (Flaw, FlawFactory, "impact", Impact.CRITICAL),
            (FlawReference, FlawReferenceFactory, "url", "http://example.com"),
            # we should be theoretically able to apply this to an arbitrary model
            # class so let us test just a few of them and assume it generally works
        ],
    )
    def test_parametrized_model(self, cls, factory, field, value):
        """
        test that check model parametrization works correctly
        """
        instance = factory()
        setattr(instance, field, value)
        # non-emptyness check is very simple to define
        # and it is enough here to use any type of check
        check = Check(f"has {field}", cls)

        assert check.name == f"has {field}"
        assert (
            check.description
            == f"check that {cls.__name__} attribute {field} has a value set"
        )
        assert check(instance), f"Check failed: {check.name}"

    @pytest.mark.parametrize(
        "affectedness,resolution,trackers_required",
        [
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.NOVALUE,
                True,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.DEFER,
                False,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.OOSS,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                True,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DEFER,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.OOSS,
                False,
            ),
            (
                Affect.AffectAffectedness.NOTAFFECTED,
                Affect.AffectResolution.NOVALUE,
                False,
            ),
        ],
    )
    def test_has_trackers(self, affectedness, resolution, trackers_required):
        """
        test that the check of the filed trackers works correctly
        """
        flaw = FlawFactory()

        check = Check("has trackers", Flaw)
        assert check.name == "has trackers"
        # the auto-generated description is
        # actually not great for this case
        assert check.description == (
            "check that all affects in\n"
            "NEW:NOVALUE or AFFECTED:DELEGATED\n"
            "have associated trackers filed"
        )
        # with no affects there is nothing which should have trackers
        assert check(flaw), f"Check failed: {check.name}"

        affect = AffectFactory(
            flaw=flaw,
            impact=Impact.LOW,
            affectedness=affectedness,
            resolution=resolution,
        )

        if not trackers_required:
            assert check(flaw)

        else:
            assert not check(flaw)
            tracker = TrackerFactory.build()
            tracker.save(raise_validation_error=False)
            affect.tracker = tracker
            affect.save(raise_validation_error=False)
            assert check(flaw)

    def test_equals_with_spaces(self):
        """
        test that equality checks work correctly for values containing spaces
        (regression test for OSIDB-4956)
        """
        ps_product = PsProductFactory(
            short_name="rhel", name="Red Hat Enterprise Linux"
        )
        ps_module = PsModuleFactory(
            bts_name="bugzilla", name="rhel-8", ps_product=ps_product
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module, name="rhel-8.10.0"
        )
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="kpatch",
            ps_update_stream=ps_update_stream.name,
        )

        check = Check("PS product is Red Hat Enterprise Linux", cls=Affect)

        assert check.name == "PS product is Red Hat Enterprise Linux"
        assert (
            check.description
            == "check that Affect attribute ps_product has a value equal to Red Hat Enterprise Linux"
        )

        # The check should pass when ps_product matches
        assert check(affect), f"Check failed: {check.name}"


class TestCondition:
    @pytest.mark.parametrize(
        "cve_id,impact,accepted",
        [
            ("CVE-2000-12345", Impact.CRITICAL, True),
            ("CVE-2000-54321", Impact.CRITICAL, False),
            ("CVE-2000-12345", Impact.MODERATE, False),
            ("CVE-2000-54321", Impact.MODERATE, False),
        ],
    )
    def test_and_condition(self, cve_id, impact, accepted):
        """Test the AND condition"""
        condition_desc = {
            "condition": "AND",
            "requirements": ["CVE is CVE-2000-12345", "impact is critical"],
        }
        flaw = FlawFactory(cve_id=cve_id, impact=impact)
        condition = Condition(**condition_desc)
        assert condition.accepts(flaw) == accepted

    @pytest.mark.parametrize(
        "cve_id,impact,accepted",
        [
            ("CVE-2000-12345", Impact.CRITICAL, True),
            ("CVE-2000-54321", Impact.CRITICAL, True),
            ("CVE-2000-12345", Impact.MODERATE, True),
            ("CVE-2000-54321", Impact.MODERATE, False),
        ],
    )
    def test_or_condition(self, cve_id, impact, accepted):
        """Test the OR condition"""
        condition_desc = {
            "condition": "OR",
            "requirements": ["CVE is CVE-2000-12345", "impact is critical"],
        }
        flaw = FlawFactory(cve_id=cve_id, impact=impact)
        condition = Condition(**condition_desc)
        assert condition.accepts(flaw) == accepted

    @pytest.mark.parametrize(
        "cve_id,impact,title,accepted",
        [
            ("CVE-2000-12345", Impact.CRITICAL, "maracuya", True),
            ("CVE-2000-54321", Impact.CRITICAL, "maracuya", False),
            ("CVE-2000-12345", Impact.MODERATE, "maracuya", True),
            ("CVE-2000-12345", Impact.MODERATE, "gulupa", False),
            ("CVE-2000-12345", Impact.CRITICAL, "gulupa", True),
            ("CVE-2000-54321", Impact.MODERATE, "gulupa", False),
        ],
    )
    def test_nested_condition(self, cve_id, impact, title, accepted):
        """Test nested conditions of different types"""
        condition_desc = {
            "condition": "AND",
            "requirements": [
                "CVE is CVE-2000-12345",
                {
                    "condition": "OR",
                    "requirements": ["impact is critical", "title is maracuya"],
                },
            ],
        }
        flaw = FlawFactory(cve_id=cve_id, impact=impact, title=title)
        condition = Condition(**condition_desc)
        assert condition.accepts(flaw) == accepted

    def test_wrong_condition(self):
        """Test that using a non-implemented condition raises an error"""
        condition_desc = {
            "condition": "MULT",
            "requirements": ["CVE is CVE-2000-12345", "impact is critical"],
        }
        flaw = FlawFactory()
        condition = Condition(**condition_desc)
        with pytest.raises(ValueError, match="MULT"):
            condition.accepts(flaw)


class TestState:
    def test_empty_requirements(self):
        """test that a state with empty requirements accepts any flaw"""
        state = State(
            {
                "name": "random name",
                "requirements": [],
                "jira_state": "New",
                "jira_resolution": None,
            }
        )
        flaw = FlawFactory()  # random flaw
        assert state.accepts(flaw), "state with no requirements rejects a flaw"

    def test_requirements(self):
        """test that a state accepts a flaw which satisfies its requirements"""

        requirements = [
            "has cve_id",
            "has impact",
            "not cwe",
            "not comment_zero",
            "not title",
        ]
        state = State(
            {
                "name": "random name",
                "requirements": requirements,
                "jira_state": "To do",
                "jira_resolution": None,
            }
        )
        flaw = FlawFactory()
        # fields set outside factory to skip validation
        flaw.cwe_id = ""
        flaw.comment_zero = ""
        flaw.title = ""

        assert state.accepts(flaw), (
            f'flaw doesn\'t met the requirements "{requirements}"'
        )

        flaw.cwe_id = "CWE-1"
        assert not state.accepts(flaw), (
            f'state accepted flaw without the requirements "{requirements}"'
        )

        flaw.cwe_id = ""
        flaw.impact = Impact.NOVALUE
        assert not state.accepts(flaw), (
            f'state accepted flaw without the requirements "{requirements}"'
        )

    def test_condition_requirements(self):
        """
        Test that a state can take conditional requirements to accept flaws
        """
        requirements = [
            {
                "condition": "OR",
                "requirements": ["has affects", "impact is low", "impact is moderate"],
            },
        ]
        state = State(
            {
                "name": "state with conditions",
                "requirements": requirements,
                "jira_state": "To do",
                "jira_resolution": None,
            }
        )

        flaw = FlawFactory(impact=Impact.LOW)
        assert state.accepts(flaw)

        flaw.impact = Impact.CRITICAL
        assert not state.accepts(flaw)

        AffectFactory(
            flaw=flaw,
            impact=flaw.impact,
            resolution=Affect.AffectResolution.DELEGATED,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )

        assert state.accepts(flaw)

    def test_visibility_parsed_from_yaml(self):
        """Test that the optional visibility field is parsed from state definition"""
        state_with = State(
            {
                "name": "PUBLIC_STATE",
                "jira_state": "To Do",
                "jira_resolution": None,
                "visibility": "PUBLIC",
                "requirements": [],
            }
        )
        assert state_with.visibility == "PUBLIC"

        state_without = State(
            {
                "name": "NO_VIS_STATE",
                "jira_state": "New",
                "jira_resolution": None,
                "requirements": [],
            }
        )
        assert state_without.visibility is None

    def test_visibility_invalid_value_rejected(self):
        """Test that an invalid visibility value is rejected during state creation"""
        with pytest.raises(ValueError):
            State(
                {
                    "name": "BAD_STATE",
                    "jira_state": "New",
                    "jira_resolution": None,
                    "visibility": "PUBLC",
                    "requirements": [],
                }
            )


class TestEffectiveVisibility:
    def test_effective_visibility_from_current_state(self):
        """
        Test that effective visibility is returned when the current state
        has a visibility property
        """
        wf = WorkflowFramework()
        vis = wf.get_effective_visibility("DEFAULT", "PRE_SECONDARY_ASSESSMENT")
        assert vis == ACLMixinVisibility.PUBLIC

    def test_effective_visibility_inherited_from_earlier_state(self):
        """
        Test that effective visibility is inherited from an earlier state
        when the current state has no visibility property (e.g. DONE
        inherits PUBLIC from PRE_SECONDARY_ASSESSMENT)
        """
        wf = WorkflowFramework()
        vis = wf.get_effective_visibility("DEFAULT", "DONE")
        assert vis == ACLMixinVisibility.PUBLIC

    def test_effective_visibility_none_before_gate(self):
        """
        Test that states before any visibility gate return None
        """
        wf = WorkflowFramework()
        vis = wf.get_effective_visibility("DEFAULT", "NEW")
        assert vis is None

        vis = wf.get_effective_visibility("DEFAULT", "TRIAGE")
        assert vis is None

    def test_effective_visibility_none_for_rejected(self):
        """
        Test that the REJECTED workflow has no visibility gates
        """
        wf = WorkflowFramework()
        vis = wf.get_effective_visibility("REJECTED", "DONE")
        assert vis is None

    def test_effective_visibility_none_for_embargoed(self):
        """
        Test that the EMBARGOED workflow has no visibility gates
        """
        wf = WorkflowFramework()
        vis = wf.get_effective_visibility("EMBARGOED", "PRE_SECONDARY_ASSESSMENT")
        assert vis is None

    def test_effective_visibility_none_for_unknown(self):
        """
        Test that unknown workflow/state combinations return None
        """
        wf = WorkflowFramework()
        assert wf.get_effective_visibility("NONEXISTENT", "NEW") is None
        assert wf.get_effective_visibility("DEFAULT", "NONEXISTENT") is None

    def test_effective_visibility_picks_widest(self):
        """
        Test that if multiple states define visibility, the widest is used
        """
        wf = WorkflowFramework()
        wf._workflows = []
        wf.register_workflow(
            Workflow(
                {
                    "name": "TEST",
                    "description": "test",
                    "priority": 0,
                    "conditions": [],
                    "states": [
                        {
                            "name": "A",
                            "jira_state": "New",
                            "jira_resolution": None,
                            "visibility": "INTERNAL",
                            "requirements": [],
                        },
                        {
                            "name": "B",
                            "jira_state": "To Do",
                            "jira_resolution": None,
                            "visibility": "PUBLIC",
                            "requirements": [],
                        },
                        {
                            "name": "C",
                            "jira_state": "In Progress",
                            "jira_resolution": None,
                            "visibility": "INTERNAL",
                            "requirements": [],
                        },
                    ],
                }
            )
        )

        assert wf.get_effective_visibility("TEST", "A") == ACLMixinVisibility.INTERNAL
        assert wf.get_effective_visibility("TEST", "B") == ACLMixinVisibility.PUBLIC
        assert wf.get_effective_visibility("TEST", "C") == ACLMixinVisibility.PUBLIC

        wf._workflows = []
        wf.load_workflows()


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
            ["has comment_zero"],
            ["has comment_zero", "has title"],
            ["not comment_zero"],
            ["not comment_zero", "not title"],
            ["has comment_zero", "not title"],
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

        assert workflow.accepts(flaw), (
            f'flaw was rejected by workflow conditions "{conditions}"'
        )

    @pytest.mark.parametrize(
        "conditions",
        [
            ["has comment_zero"],
            ["has comment_zero", "has title"],
            ["not comment_zero"],
            ["not comment_zero", "not title"],
            ["has comment_zero", "not title"],
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

        assert not workflow.accepts(flaw), (
            f'flaw was wrongly accepted by workflow conditions "{conditions}"'
        )

        # conditions partially satisfied
        if len(conditions) > 1:
            mode, attr = conditions[0].split(" ", maxsplit=1)
            attr = attr.replace(" ", "_")

            if mode == "has":
                setattr(flaw, attr, "valid value")
            elif mode == "not":
                setattr(flaw, attr, "")
        assert not workflow.accepts(flaw), (
            f'flaw was wrongly accepted by workflow conditions "{conditions}"'
        )

    def test_condition_with_or(self):
        """test that a workflow condition can use an OR logical condition"""
        workflow = Workflow(
            {
                "name": "test",
                "description": "test",
                "priority": 0,
                "conditions": [
                    {
                        "condition": "OR",
                        "requirements": [
                            "has comment_zero",
                            "has title",
                        ],
                    }
                ],
                "states": [],
            }
        )

        flaw = FlawFactory()
        flaw.comment_zero = ""
        flaw.title = ""
        assert not workflow.accepts(flaw)

        flaw.comment_zero = "some comment"
        assert workflow.accepts(flaw)

        flaw.comment_zero = ""
        flaw.title = "some title"
        assert workflow.accepts(flaw)

    def test_classify(self):
        """test that a flaw is correctly classified in the workflow states"""
        state_new = {
            "name": "new",
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }
        state_first = {
            "name": "first state",
            "requirements": ["has comment_zero"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }
        state_second = {
            "name": "second state",
            "requirements": ["has title"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

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

        flaw.comment_zero = "valid comment_zero"
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
            "jira_state": "New",
            "jira_resolution": None,
        }
        new_high = {
            "name": "new high priority state",
            "requirements": [],
            "jira_state": "To Do",
            "jira_resolution": None,
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

        flaw = Flaw(task_key="TASK-123")
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_high)
        assert_state_equals(classified_state, new_high)

        # register order should not matter
        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow_low)
        workflow_framework.register_workflow(workflow_high)

        flaw = Flaw(task_key="TASK-123")
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_high)
        assert_state_equals(classified_state, new_high)

    def test_classify_complete(self):
        """test flaw classification in both workflow and state"""
        state_new = {
            "name": "NEW",
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }
        state_first = {
            "name": "TRIAGE",
            "requirements": ["has comment_zero"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }
        state_second = {
            "name": "DONE",
            "requirements": ["has title"],
            "jira_state": "Refinement",
            "jira_resolution": None,
        }

        workflow_main = Workflow(
            {
                "name": "DEFAULT",
                "description": "a three step workflow to test classification",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )

        state_not_affected = {
            "name": "DONE",
            "requirements": [],
            "jira_state": "Done",
            "jira_resolution": "Won't Do",
        }

        workflow_reject = Workflow(
            {
                "name": "REJECT",
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

        flaw = FlawFactory(task_key="TASK-123")
        flaw.comment_zero = ""
        flaw.title = ""

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_main)
        assert_state_equals(classified_state, state_new)

        flaw.comment_zero = "valid comment_zero"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_first)

        flaw.title = "valid title"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_second)

        affect = AffectFactory(
            flaw=flaw,
            resolution=Affect.AffectResolution.DELEGATED,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_main)
        assert_state_equals(classified_state, state_second)

        affect.resolution = Affect.AffectResolution.NOVALUE
        affect.affectedness = Affect.AffectAffectedness.NOTAFFECTED
        affect.not_affected_justification = (
            NotAffectedJustification.INLINE_MITIGATIONS_ALREADY_EXIST
        )
        affect.save()
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_reject)
        assert_state_equals(classified_state, state_not_affected)


class TestFlaw:
    @pytest.mark.enable_signals
    def test_init(self):
        """test that flaw without task_key has empty workflow fields"""
        flaw = FlawFactory()
        # Flaws without task_key should have empty workflow fields
        assert flaw.workflow_name == ""
        assert flaw.workflow_state == ""

    @pytest.mark.enable_signals
    def test_adjust(self):
        """test flaw classification adjustion after metadata change"""
        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = State(
            {
                "name": "NEW",
                "jira_state": "New",
                "jira_resolution": None,
                "requirements": [],
            }
        )
        state_first = State(
            {
                "name": "TRIAGE",
                "jira_state": "To Do",
                "jira_resolution": None,
                "requirements": ["has comment_zero"],
            }
        )
        state_second = State(
            {
                "name": "DONE",
                "jira_state": "In Progress",
                "jira_resolution": None,
                "requirements": ["has title"],
            }
        )

        states = [state_new, state_first, state_second]

        # initialize default workflow first so there is
        # always some workflow to classify the flaw in
        workflow = Workflow(
            {
                "name": "DEFAULT",
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
                "name": "MAJOR_INCIDENT",
                "description": "random description",
                "priority": 1,  # is more prior than default one
                "conditions": [
                    "major_incident_state_is_major_incident_approved"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            task_key="TASK-123",  # Required for workflow classification
        )
        AffectFactory(flaw=flaw)
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "MAJOR_INCIDENT"

        flaw.major_incident_state = Flaw.FlawMajorIncident.MAJOR_INCIDENT_REJECTED
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "DEFAULT"

    @pytest.mark.enable_signals
    def test_adjust_no_change(self):
        """test that adjusting classification has no effect without flaw modification"""
        # Flaw without task_key should have empty workflow fields
        flaw = FlawFactory()
        classification = flaw.classification
        flaw.adjust_classification()
        assert classification == flaw.classification
        # Verify workflow fields remain empty without task_key
        assert flaw.workflow_name == ""
        assert flaw.workflow_state == ""

    @pytest.mark.enable_signals
    def test_rejected_label_classifies_to_rejected_workflow(self):
        """test that adding a rejected workflow label classifies flaw into REJECTED workflow using parameterized check"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-456")
        AffectFactory(flaw=flaw)
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "DEFAULT"

        # Add rejected label - workflow uses has_label_rejected parameterized check
        WorkflowLabel.objects.create(flaw=flaw, name="rejected")
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "REJECTED"
        assert flaw.classification["state"] == "DONE"

    @pytest.mark.enable_signals
    def test_removing_rejected_label_falls_back_to_default(self):
        """test that removing the rejected label causes fallback to DEFAULT workflow"""
        flaw = FlawFactory(embargoed=False, task_key="TASK-789")
        AffectFactory(flaw=flaw)

        workflow_label = WorkflowLabel.objects.create(flaw=flaw, name="rejected")
        flaw.adjust_classification()
        assert flaw.classification["workflow"] == "REJECTED"

        workflow_label.delete()
        flaw.adjust_classification()
        assert flaw.classification["workflow"] == "DEFAULT"

    def test_has_label_method(self):
        """test the has_label method on Flaw"""
        flaw = FlawFactory()
        assert not flaw.has_label("rejected")
        assert not flaw.has_label("approved")

        WorkflowLabel.objects.create(flaw=flaw, name="rejected")
        assert flaw.has_label("rejected")
        assert not flaw.has_label("approved")

        WorkflowLabel.objects.create(flaw=flaw, name="approved")
        assert flaw.has_label("rejected")
        assert flaw.has_label("approved")
