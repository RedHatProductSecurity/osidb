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

Classification is not a user action. There is no "promote button" in the
correct design. A user changes flaw data (assigns an owner, sets an impact,
creates affects, files trackers), and the framework automatically recognizes
that the flaw has reached the next state. The workflow framework observes data;
it does not create it.

## Architecture

### Workflow Definitions (YAML)

Workflows are defined in YAML files under `apps/workflows/workflows/` - TODO
move the workflow definitions to PS constants. Each workflow specifies:

- **name** -- identifier (e.g. `DEFAULT`, `REJECTED`)
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

- The initial state (e.g. `NEW`) must have empty requirements so that every
  flaw is accepted into at least the first state.
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
requirements are still fully met. No manual "revert" is needed.

**Current bug in `validate_classification()`:** (TODO fix) The
`Workflow.validate_classification()` method, used by the manual `promote()` and
`revert()` methods, only checks the target state's own requirements. It does
not check the requirements of all preceding states. This allows manual promote
to bypass cumulative requirements. The bug becomes irrelevant once
classification is fully automatic, because `classify()` already implements
cumulative requirements correctly.

## Automatic Classification

### Signal-Driven Classification

Classification runs on every flaw save via a Django `pre_save` signal in
`apps/workflows/signals.py`.

**Current behavior (broken):** (TODO fix) The signal only classifies when `task_key` is
set AND both `workflow_name` and `workflow_state` are empty:

```python
if instance.task_key and not all([instance.workflow_name, instance.workflow_state]):
    instance.adjust_classification(save=False)
```

This means classification runs only once (on initial assignment) and never
again. All subsequent state changes require manual API calls.

**Correct behavior:** The signal must reclassify on every save:

```python
if instance.task_key:
    instance.adjust_classification(save=False)
```

The `task_key` guard remains: flaws without a Jira task have no meaningful
classification (their workflow fields stay empty -- this excludes legacy flaws).
But once a task exists, classification is recomputed on every save, reflecting
whatever data changed.

### The `adjust_classification()` Method

`WorkflowModel.adjust_classification()` calls `classify()`, compares the result
to the stored classification, and updates if different. This is the correct
implementation -- it delegates to the pure function and stores the result.

### Idempotency

Because `classify()` is a pure function of flaw data, calling
`adjust_classification()` multiple times with the same data produces the same
result. There is no risk of double-promoting or oscillating states.

## DEFAULT Workflow Requirements

### Current State (Stripped - TODO enrich)

The current YAML definitions have been stripped of most requirements because
people working with manual transitions found them annoying:

| State | Current Requirements |
|---|---|
| NEW | (none) |
| TRIAGE | has owner |
| PRE_SECONDARY_ASSESSMENT | has source, has title |
| SECONDARY_ASSESSMENT | has owner |
| DONE | OR(has trackers, impact is low, impact is moderate) |

Notable: `has affects` was commented out from PRE_SECONDARY_ASSESSMENT, and
`has impact` was never a requirement.

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

### Planned Restorations (TODO restore)

The following requirements should be restored to PRE_SECONDARY_ASSESSMENT:

- `has affects` -- a flaw cannot progress past triage without at least one
  affect identifying which products are impacted
- `has impact` -- impact assessment is a core triage output

Further enrichment of requirements across all states is planned but requires
deeper analysis of the processing phases and team input.

## REJECTED Workflow Redesign (TODO redesign)

### The Problem

Currently, rejection is a manual API action (`POST /flaws/{id}/reject`). The
`reject()` method directly sets `workflow_name = "REJECTED"` and
`workflow_state = "REJECTED"` with no underlying data feature. This violates
the core principle: classification is action-driven, not data-driven.

The REJECTED workflow has `conditions: []` (empty) and `priority: 0` (lower
than DEFAULT's 1). This means `classify()` never selects it -- the REJECTED
state is unreachable through automatic classification.

### The Solution

Rejection must be driven by a flaw data attribute. When this attribute is set,
the REJECTED workflow's conditions match and -- because REJECTED must then have
higher priority than DEFAULT -- the flaw is automatically classified into the
REJECTED workflow. When the attribute is cleared, the flaw falls back to
DEFAULT.

The specific data attribute is **TBD** pending team discussion. Options under
consideration include a dedicated `resolution` field (mirroring Jira's concept,
extensible to values like DUPLICATE, OUT_OF_SCOPE) or using flaw labels.

### Required YAML Changes

Once the data attribute is chosen:

1. REJECTED workflow priority must be raised above DEFAULT (e.g. 2 > 1)
2. A condition must be added referencing the chosen attribute (e.g.
   `resolution is rejected`)
3. Existing REJECTED flaws must be migrated to have the attribute set

## Jira Decoupling

### The Cyclic Dependency

The current data flow between OSIDB and Jira is bidirectional for workflow
state:

**OSIDB to Jira (correct):** When `workflow_state` changes, `tasksync()`
transitions the Jira task via `JiraTaskmanQuerier.transition_task()`, using the
forward mapping from `flaw.jira_status()`. This is the desired direction.

**Jira to OSIDB (incorrect):** (TODO remove) The jiraffe collector
(`collectors/jiraffe/convertors.py`, `JiraTaskConvertor._normalize()`) reads
Jira's status and resolution, calls `WorkflowFramework().jira_to_state()` to
reverse-map them, and writes `workflow_name` and `workflow_state` back to the
flaw. This creates a cycle: OSIDB sets Jira status based on workflow state, and
the collector overwrites workflow state based on Jira status.

If Jira status and OSIDB state ever diverge (e.g. someone manually changes the
Jira issue), the collector forces OSIDB to match Jira -- overriding the
data-driven classification.

### The Fix: One-Directional Flow

The data flow must be strictly **OSIDB to Jira, never the reverse**:

- OSIDB computes `workflow:state` from flaw data
- OSIDB tells Jira what status/resolution to be in (via `transition_task()`)
- The jiraffe collector must **not** map Jira status/resolution back to
  workflow fields

Concrete changes:

- Remove the `jira_to_state()` call and `workflow_state`/`workflow_name` from
  `JiraTaskConvertor._normalize()` in `collectors/jiraffe/convertors.py`
- Deprecate `WorkflowFramework.jira_to_state()`
- The forward mapping (`jira_status()`) and the Jira state/resolution metadata
  in YAML definitions remain -- they are needed for the OSIDB-to-Jira direction

## API Versions

### V2 API (Current)

This is the recommended API for workflow introspection. It provides read-only
endpoints for viewing workflow definitions and computed classifications.

**Available endpoints:**

| Endpoint | Method | Description |
|---|---|---|
| `/workflows/api/v2/workflows` | GET | List all workflow definitions |
| `/workflows/api/v2/workflows/{id}` | GET | Get computed classification for a flaw |

Classification is automatic based on flaw data and cannot be manually changed.

### V1 API (Deprecated)

**The entire v1 API is deprecated.** All clients should migrate to v2.

**Read-only endpoints (deprecated, but functional):**

| Endpoint | Method | Status | Description |
|---|---|---|---|
| `/workflows/api/v1/workflows` | GET | **DEPRECATED** | Use v2 endpoint instead - functionally identical |
| `/workflows/api/v1/workflows/{id}` | GET | **DEPRECATED** | Use v2 endpoint instead - functionally identical |

These endpoints still work correctly but are deprecated. Use the equivalent v2
endpoints instead.

**Mutation endpoints (deprecated NO-OP):**

| Endpoint | Status | Behavior |
|---|---|---|
| `POST /osidb/api/v1/flaws/{id}/promote` | **DEPRECATED NO-OP** | Returns current classification without making any changes |
| `POST /osidb/api/v1/flaws/{id}/revert` | **DEPRECATED NO-OP** | Returns current classification without making any changes |
| `POST /osidb/api/v1/flaws/{id}/reset` | **DEPRECATED NO-OP** | Returns current classification without making any changes |
| `POST /osidb/api/v1/flaws/{id}/reject` | **DEPRECATED NO-OP** | Returns current classification without making any changes |
| `POST /workflows/api/v1/workflows/{id}/adjust` | **DEPRECATED NO-OP** | Returns current classification without making any changes |

These endpoints no longer perform any workflow state mutations. They return
HTTP 200 with the current computed classification and deprecation warnings.
This maintains API compatibility while preventing any manual state manipulation
that would be immediately overridden by automatic classification.

**Migration path:**

- Stop calling mutation endpoints - they no longer change state
- Update flaw data directly instead (assign owner, create affects, file
  trackers, set impact, etc.)
- Workflow classification updates automatically on every flaw save
- Use `GET /workflows/api/v2/workflows/{id}` to view computed classification

**Deprecation timeline:**

Phase 1 (current): Mutation endpoints are no-ops that return compatible
responses with deprecation warnings. No state changes occur.

Phase 2 (TBD): Mutation endpoints will be removed entirely. Only v2 endpoints will remain.
