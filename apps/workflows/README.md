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

### Fixed State Set

All workflows share a fixed set of states defined in `WorkflowState`. Each
workflow uses a subset of these states. NEW represents the initial point and
DONE the final one, which is useful for convenient querying, but this is a soft
convention.

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

### Idempotency

Because `classify()` is a pure function of flaw data, calling
`adjust_classification()` multiple times with the same data produces the same
result. There is no risk of double-promoting or oscillating states.

## Workflow Definitions

For exact requirements and conditions, see the YAML files in
`apps/workflows/workflows/`. The following describes the design intent.

### DEFAULT Workflow (`default.yml`)

The default vulnerability workflow. All flaws that do not match
a higher-priority workflow are classified here. It has no conditions
(empty list), making it the universal fallback.

The DONE state requires human approval via a workflow label. This is
intentional: DONE represents a state of the *data*, not the state of a process.
If the approved label is removed or a prior requirement is unfulfilled, the
flaw automatically regresses to the appropriate state -- DONE can be undone.

### EMBARGOED Workflow (`embargoed.yml`)

The EMBARGOED workflow handles flaws under embargo. It is selected when the
flaw has embargo ACLs (`is embargoed` condition).

The DONE state requires the flaw to no longer be embargoed, which conflicts
with the workflow's own entry condition. This makes DONE effectively
unreachable within the EMBARGOED workflow -- by design. An embargoed flaw
progresses through its states based on data, but cannot complete until the
embargo is lifted.

When the embargo is lifted, the `is embargoed` condition fails and the flaw
falls to the DEFAULT workflow, where it is classified normally and can reach
DONE through the standard approval process.

### REJECTED Workflow (`rejected.yml`)

The REJECTED workflow handles flaws that have been rejected during triage. It
is driven by a **workflow label** `rejected` on a flaw.

Because REJECTED has the highest priority, it is evaluated first. When a
*rejected* workflow label exists, the flaw is classified into REJECTED/DONE
regardless of other data. When the label is removed, the condition fails
and the flaw classified again.

REJECTED is not a state -- it is a workflow. A rejected flaw is classified as
REJECTED:DONE because DONE represents "fully processed", and a rejected flaw
has been fully processed by the act of rejecting it. The Jira resolution
distinguishes rejection ("Won't Do") from completion ("Done").

### ACL Handling

Rejected and embargoed flaws with internal ACLs are **not** promoted to public
even though their workflow state is DONE. The `adjust_acls` method only
promotes flaws in the DEFAULT workflow.

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

The classification endpoint (`/workflows/{id}`) accepts an optional
`?verbose=true` query parameter. When set, the response includes all workflow
definitions with per-workflow, per-state, and per-requirement `accepts`
booleans showing the classification reasoning. Each accepting workflow also
contains a `classified_state` field naming the state the flaw is classified in
(or `null` for non-selected workflows).

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
