# Workflow Framework

The workflow framework defines the consecutive phases a flaw goes through to
get fully processed. A classification consisting of a *workflow* and *state* is
automatically derived from the flaw's data on every save, describing its
current progress without requiring any manual state transitions.

## Design Philosophy

The central principle is that **classification is a pure function of flaw data**.
A flaw's workflow and state are not independent attributes to be set manually;
they are derived values, computed automatically from the flaw's current data on
every save.

This principle has three consequences:

1. **Automatic classification.** When a flaw is saved, the framework evaluates
   which workflow applies and how far through that workflow's states the flaw
   can progress. No human action is needed to advance or revert a flaw --
   changing the underlying data is sufficient.

2. **No circular dependencies.** Because classification is derived from data,
   the classification itself must never be an input to its own computation.
   External systems (Jira) receive the computed classification; they never
   dictate it back.

3. **Determinism.** Given the same flaw data, the framework must always produce
   the same classification. There is no hidden state, no history dependence, no
   ordering sensitivity.

### What classification is NOT

Classification is not a user action. A user changes flaw data (assigns an
owner, sets an impact, creates affects, files trackers, ...), and the framework
automatically recognizes that the flaw has reached the next state. The workflow
framework observes data; it does not create it.

### Requirement vs. Validation

Not every data constraint belongs in the workflow. The distinction:

- **Workflow requirement** -- represents *processing progress*. Answers: "has
  the analyst or agent done the work expected at this phase?" Examples:
  assigning an owner, creating affects, filing trackers.
- **Model validation** -- represents *data sanity*. Answers: "is this data
  internally consistent?" Examples: CVSS score consistency, date format
  validity, CVE description length.

Model validations belong in `osidb/models/` validators and are enforced on
every save regardless of workflow state. Workflow requirements belong in YAML
and gate state progression.

State requirements should cover as much of the data constraints as possible.
Validations are stateless and applied all the time, but most data requirements
do not have to hold always. A non-triaged flaw in NEW can rightfully miss
attributes. Likewise, we do not need full data on REJECTED flaws, but
model-level validations would block the rejection of incomplete flaws.

## Architecture

### Workflow Definitions (YAML)

Workflows are defined in YAML files under `apps/workflows/workflows/`.
The YAML files are the single source of truth for workflow definitions
-- they are designed to be both human-readable and machine-parsable.
The README describes the design intent and concepts; for exact requirements
and conditions, refer to the YAML files directly.

Each workflow specifies:

- **name** -- identifier
- **priority** -- integer; higher priority workflows are evaluated first
- **conditions** -- checks the flaw must satisfy for this workflow to apply;
  empty conditions mean the workflow is unconditional (a catch-all)
- **states** -- ordered list; each state has a name and a list of requirements

### Workflow Selection

`WorkflowFramework.classify()` iterates workflows sorted by descending
priority. The first workflow whose conditions all pass is selected. Because the
`DEFAULT` workflow has empty conditions, it serves as the universal fallback.

### State Classification Algorithm

Within the selected workflow, states are evaluated in order by
`Workflow.classify()` (`apps/workflows/models.py`):

```
last_accepting = None
for state in workflow.states:
    if state does not accept the flaw:
        break
    last_accepting = state
return last_accepting
```

The flaw is classified in the **last accepting state not preceded by any
non-accepting state**. The scan stops at the first failure. This means:

- The initial state must have empty requirements so that when a flaw is
  classified to a workflow it is accepted by some state.
- Requirements are **cumulative by construction**: reaching state N requires
  that the requirements of all states 1 through N are satisfied, because the
  scan would have stopped at the first non-accepting state.

### Cumulative Requirements

This property is fundamental. To reach state N, a flaw must satisfy the
requirements of **all** states 1 through N. This is not enforced by checking
all prior states explicitly -- it is a natural consequence of the linear scan
algorithm. The algorithm breaks at the first non-accepting state, so it is
impossible to "skip over" an unsatisfied state.

If a requirement that was fulfilled in a prior state becomes unfulfilled (e.g.
owner is cleared), the flaw automatically regresses to the last state whose
requirements are still fully met. No manual action is needed.

### State Names

State names are free-form strings defined in the YAML workflow files. Each
workflow can define its own set of states. By convention, NEW represents the
initial point and DONE the final one, which is useful for consistent querying,
but this is not enforced by the framework.

### WORKFLOW Label Type

The `FlawLabel.FlawLabelType.WORKFLOW` type was introduced for labels that
drive workflow classification. Unlike context-based labels, WORKFLOW labels
do not require pre-registration in the `FlawLabel` table

This type is designed to be reusable for future workflow-driving labels beyond
approval and rejection labels.

## Automatic Classification

Auto-classification is essential for the automated and agentic approach where
multiple different actors (analysts, bots, agents) collectively process a flaw.
OSIDB ensures the workflow transitions when one actor is done, allowing the next
one to follow -- they do not click the next button, they do the actual work.

### Signal-Driven Classification

Classification runs on every flaw save via a Django `pre_save` signal.
The signal calls `adjust_classification(save=False)` which computes `classify()`
and stores the result on the instance before it reaches the database.

Classification also triggers when related models change. Django `post_save` and
`post_delete` signals on Affect, Tracker, etc. re-save the
parent flaw (`osidb/signals.py`), which triggers the classification.

When the classification actually changes, `adjust_classification()` emits the
custom `classification_changed` signal (`apps/workflows/signals.py`) carrying the
old and new classification. Listening for the signal allows downstream consumers
to know what the transition was without having to manually compute it.

### resolved_dt

`adjust_classification()` maintains a `resolved_dt` timestamp on the
`WorkflowModel`: it is stamped with the current time when the instance first
enters the DONE state and cleared whenever the instance is not in DONE. This
gives a reliable "when was this finished" marker that follows the automatic
classification, including regressions out of DONE.

### Idempotency

Because `classify()` is a pure function of flaw data, calling
`adjust_classification()` multiple times with the same data produces the same
result. There is no risk of double-promoting or oscillating states.

### Reclassification Exclusion for Old Flaws

Flaws created before the `OSIDB_WORKFLOW_RECLASSIFICATION_START_DATE` cutoff that
are already in the `DONE` workflow state are excluded from automatic
(re)classification. They were closed under historical `DONE` criteria, so
re-classifying them would reopen them; the exclusion keeps them frozen. An unset
cutoff means no time restriction and all flaws are subject to classification.

This exclusion is **opt-out per flaw** via a workflow label. Adding the
`classify` workflow label to an excluded flaw removes the exclusion, bringing the
flaw fully under automatic classification again -- this is how an incorrectly
classified old flaw is corrected. Removing the label re-excludes the flaw.
Post-cutoff flaws are unaffected and always follow normal classification.

When the exclusion actually suppresses a change -- i.e. automatic classification
would move the flaw to a different workflow/state but is held back -- the flaw
carries a non-blocking alert explaining the exclusion and noting that adding the
`classify` label will opt it back in.

### Classification Change Tracking

Every classification change is automatically recorded with human-readable
reasoning in the `classification_meta` JSONField on the WorkflowModel. This
provides visibility into why automatic reclassification occurred.

The tracking system records the following classification changes:

1. **Initial classification** - The first workflow/state classification
2. **State progression** - Same workflow, state advances (NEW → TRIAGE)
3. **State regression** - Same workflow, state moves backward
   (SECONDARY_ASSESSMENT → TRIAGE when owner is cleared)
4. **Workflow promotion** - Classified to higher priority workflow
   (DEFAULT → REJECTED when rejected label is applied)
5. **Workflow demotion** - Classified to lower priority workflow
   (EMBARGOED → DEFAULT when embargo is lifted)

#### Change Record Structure

Each change record is stored as a JSON object in the `classification_meta` list:

```json
{
    "timestamp": "2026-06-19T14:30:00Z",
    "change_type": "STATE_PROGRESSION",
    "workflow": "DEFAULT",
    "state": "TRIAGE",
    "reason": {
        "requirements_satisfied": [
            {
                "name": "has CWE",
                "description": "check that Flaw attribute cwe_id has a value set"
            }
        ],
        "explanation": "State progressed from NEW to TRIAGE by satisfying: has CWE"
    }
}
```

The `reason` object contains:
- **requirements_satisfied/unsatisfied** - For state changes within the same
  workflow, lists which requirements became satisfied or unsatisfied
- **conditions_satisfied/unsatisfied** - For workflow changes, lists which
  conditions triggered the workflow switch
- **explanation** - Human-readable summary of what triggered the change

## Workflow Definitions

For exact requirements and conditions, see the YAML files in
`apps/workflows/workflows/`. The following describes the design intent.

Several workflows coexist, each capturing a different processing scenario
(routine automated handling, human triage, embargo, rejection). They are
evaluated in descending priority order and the first workflow whose conditions
all pass is selected; the unconditional DEFAULT workflow is the catch-all. The
subsections below describe the intent of each -- their their complete both
human and machine readable definitions live in the YAML files.

### DEFAULT Workflow (`default.yml`)

The default vulnerability workflow. All flaws that do not match
a higher-priority workflow are classified here. It has no conditions
(empty list), making it the universal fallback.

The DONE state requires human approval via a workflow label. This is
intentional: DONE represents a state of the *data*, not the state of a process.
If the approved label is removed or a prior requirement is unfulfilled, the
flaw automatically regresses to the appropriate state -- DONE can be undone.

### MANUAL Workflow (`manual.yml`)

The MANUAL workflow handles flaws that need human triage rather than the fully
automated path -- for example when a flaw has been flagged for manual attention
or its impact warrants it. It takes priority over DEFAULT, so a flaw that
qualifies is steered onto the human-triage track instead of being processed
automatically.

This workflow is intended for the cases the automation cannot fully handle.
However, it does not mean that all the remaining work has to be done manually.
Whenever the problematic step of the workflow is handled, the analyst can
un-flag the flaw and it will fall back into the automatic workflow where
it will continue being processed automatically.

### EMBARGOED Workflow (`embargoed.yml`)

The EMBARGOED workflow handles flaws under embargo. It is selected when the
flaw has embargo ACLs (`is embargoed` condition).

The DONE state requires the flaw to no longer be embargoed, which conflicts
with the workflow's own entry condition. This makes DONE effectively
unreachable within the EMBARGOED workflow -- by design. An embargoed flaw
progresses through its states based on data, but cannot complete until the
embargo is lifted.

When the embargo is lifted, the `is embargoed` condition fails and the flaw
falls to the next matching workflow, where it is classified normally and can
reach DONE through the standard approval process.

### REJECTED Workflow (`rejected.yml`)

The REJECTED workflow handles flaws that have been rejected during triage. It is
driven by a **workflow label** marking the flaw as rejected, whether by a human
or by automation (such as ACE).

Because REJECTED has the highest priority, it is evaluated first. While such a
label is present, the flaw is classified into REJECTED/DONE regardless of other
data. When the label is removed, the condition fails and the flaw is classified
again.

REJECTED is not a state -- it is a workflow. A rejected flaw is classified as
REJECTED:DONE because DONE represents "fully processed", and a rejected flaw
has been fully processed by the act of rejecting it. The Jira resolution
distinguishes rejection ("Won't Do") from completion ("Done").

### Visibility and ACL Adjustment

Workflow states can specify a `visibility` field (PUBLIC, INTERNAL, or
EMBARGOED) in their YAML definitions. When a flaw reaches a state with explicit
visibility, its ACLs are automatically adjusted to match.

The effective visibility for a state is the **widest visibility** defined across
all states from the beginning up to and including the current state. This
ensures that:

1. Visibility gates are not skipped when a flaw is classified multiple states
   ahead
2. A later state cannot narrow visibility set by an earlier one (visibility can
   only widen, never narrow)

ACL adjustment happens automatically in `adjust_acls()` (called from
`adjust_classification()`). It looks up the effective visibility for the current
state and, only if that target is wider than the current ACL, widens the flaw's
ACLs and propagates the change to nested objects and history. ACLs are therefore
only ever widened, never narrowed, and only flaws reaching a state that declares
a `visibility` are affected.

## Jira Integration

The data flow between OSIDB and Jira is strictly one-directional for workflow
classification:

**OSIDB to Jira:** When classification changes, it gets transitioned to the
Jira task using the forward mapping. The Jira state/resolution metadata in YAML
workflow definitions specifies the mapping.

**Jira to OSIDB:** Only task metadata updates from Jira. It does
not map Jira status/resolution back to workflow fields.

> The `task_key` guard ensures that only flaws with a Jira task are classified.
> Flaws without a task (legacy flaws) keep empty workflow fields.

Concrete models may also veto re-classification via the
`_skip_reclassification()` hook. `Flaw` overrides it to leave already-DONE flaws
that were created before `WORKFLOW_RECLASSIFICATION_START_DATE` untouched: those
were closed under earlier DONE criteria and must not be silently reopened by the
current requirements. An unset cutoff date means no such time restriction.

## API

### Authentication

All workflow API and graph endpoints are publicly accessible (unauthenticated).
Workflow definitions are not sensitive and classification visibility is governed
by flaw-level ACLs enforced at the database level -- if a flaw is embargoed,
an unauthenticated request simply cannot retrieve it.

The deprecated mutation endpoints (`promote`, `revert`, `reset`, `reject`,
`adjust`) remain authenticated for backwards compatibility but are no-ops.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/workflows/api/v1/workflows` | GET | List all workflow definitions |
| `/workflows/api/v1/workflows/{id}` | GET | Get computed classification for a flaw |
| `/workflows/api/v1/workflows/{id}/adjust` | POST | **Deprecated** no-op, returns current classification |
| `/workflows/api/v1/graph/workflows` | GET | Visual (Mermaid) diagram of all workflows |
| `/workflows/api/v1/graph/workflows/{id}` | GET | Visual diagram with flaw classification highlighted |

The classification endpoint (`/workflows/{id}`) accepts optional query parameters:

- **`?verbose=true`** - Includes all workflow definitions with per-workflow,
  per-state, and per-requirement `accepts` booleans showing the classification
  reasoning. Each accepting workflow also contains a `classified_state` field
  naming the state the flaw is classified in (or `null` for non-selected
  workflows).

- **`?next=true`** - Includes the `next` field containing the next state in the
  workflow with its requirements and their acceptance status. Returns `null` if
  the flaw is already in the final state. Useful for determining what
  requirements must be satisfied to progress to the next state.

- **`?history=true`** - Includes the `history` field containing all
  classification changes recorded in `classification_meta`. Each change record
  shows the timestamp, change type (initial classification, progression, regression, promotion, demotion),
  resulting workflow/state, and human-readable reasoning explaining
  what requirements or conditions triggered the change.

Classification is automatic based on flaw data and cannot be manually changed.

### Graph Endpoints

The graph endpoints render an HTML page with Mermaid flowchart diagrams of
workflow states. The plain `/graph/workflows` shows all workflow definitions.
The `/graph/workflows/{id}` variant classifies a specific flaw and highlights
states with color: blue for the classified state, green for accepting, red for
non-accepting.

### Deprecated Mutation Endpoints

The mutation endpoints (`promote`, `revert`, `reset`, `reject`) live under
`/osidb/api/v1/flaws/{id}/` in the main OSIDB URL configuration, not the
workflows app. The `adjust` endpoint (`/workflows/api/v1/workflows/{id}/adjust`)
is in the workflows app. All are no-ops that return the current classification
with deprecation warnings and will be removed in a future version.

To change workflow state, update flaw data directly.
Classification updates automatically on every flaw save.
