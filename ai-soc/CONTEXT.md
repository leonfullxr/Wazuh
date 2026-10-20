# AI SOC

A read-only Wazuh SOC assistant: an analyst asks a question, deterministic planning splits it into topics, bounded reads gather evidence per topic, and a tool-free model judges each topic independently. The service and wire contracts are documented in [docs/contracts.md](docs/contracts.md) and [docs/specification.md](docs/specification.md); this file fixes the words used when talking about the code.

## Language

**Topic**:
A human-reviewed subject (for example LDAP) with aliases, a document, optional playbook and finding templates; the unit of planning, evidence and judgment.
_Avoid_: intent, skill, category

**Topic plan**:
The deterministic plan for one topic within a question: its fetches, whether a playbook runs, and whether judgment was requested.
_Avoid_: job, task

**Evidence pack**:
The hashed, topic-bound set of fetch results, check results and evidence items that a judgment may cite.
_Avoid_: context, prompt data

**Topic evidence**:
The module that runs a topic plan's playbook and fetches as the analyst and returns the tables, checks, evidence pack and the fetch specs it actually executed.
_Avoid_: enrichment service, topic runner

**Topic judgment**:
The module that turns one topic's evidence pack into a judgment result or a left-out, sequencing eligibility, token counting, reservation against the question budget, the model call, finding validation and settlement. Eligibility rules themselves stay in the judgment engine port.
_Avoid_: judgment engine, LLM call, analysis service

**Question budget**:
The per-question token allowance, stored as the `QuestionBudget` row, against which each model call is reserved and then settled; owner and service daily limits apply on top.
_Avoid_: budget store (that is the storage adapter), quota

**Left-out**:
A topic stage that did not complete in this answer, with a reason and whether an explicit continuation may retry it.
_Avoid_: skipped, failed topic
