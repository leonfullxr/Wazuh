# Wazuh project audit

Baseline: main at `cccb1e8`. The repository inventory is monorepo-wide. The user confirmed all eight repairs and six product proposals. The implementation target is the Python MCP server, its tests, operator documentation and repository workflow.

## Repository state

| Evidence | Result |
|---|---|
| Current work | Local main matches the origin/main tracking ref. The root ignore file has an existing edit and ai-soc/web/dist-demo is untracked. The MCP plans are untracked working documents from the previous review. |
| History | The MCP package entered main in 0912f97 (#20). The package tree on feat/wazuh-mcp is identical to main despite different post-squash commit IDs. Recent main commits #26 through #30 focus on AI SOC and deployment, alongside ce0d7fc documentation updates. |
| Branches and worktrees | Separate branches cover AI SOC, Kubernetes, integrations, SCA and knowledge-base work. Active worktrees include UI polish, knowledge base and Sigma/KQL. Those checkouts have independent owners. |
| Upstream queue | Live read-only queries to leonfullxr/Wazuh returned zero open issues and zero open PRs. The eight MCP items originate in the local audit. |
| Documentation inventory | 185 tracked Markdown, AsciiDoc or reStructuredText files across the checkout, including 19 under mcp-server. The root index describes independent operational guides, integrations and packages. AI SOC is a separate application with its own contributor instructions and pipeline. |
| Source markers | No uppercase TODO/FIXME markers in tracked MCP Python or workflow source. Three markers in scripts/diagnosis/diagnosis.sh concern node coverage, diagnostic file selection and naming. |
| CI and runners | Only .github/workflows/ai-soc-ci.yml exists at baseline. It filters on AI SOC, pins actions and runs on ubuntu-24.04. MCP has a Python package, Docker and Compose entry points, local-model evals and 27 integration test modules. The dev extra includes Ruff, pytest, branch coverage and GCF. |
| Measured baseline | Python 3.11 package suite passed 641 tests and reported 65.77% coverage against a 37% minimum. Ruff and pip check passed. This is local package evidence. Live Wazuh, real IdP, hosted Actions and a Python 3.13 run need separate verification. |

## Current contracts and gaps

The MCP docs cover authentication, running behind a proxy, local model toolsets, multi-cluster deployment, configuration and nine API-reference pages. The operations and security guides explicitly document process-local OAuth state and rate limits. Multi-cluster readiness probes the environment connection. The compatibility guide covers Wazuh 4.8–4.14.7, including two deprecated Manager statistics endpoints. Package metadata advertises Python 3.11–3.13. A source comment refers to a security audit workflow absent from this checkout.

| ID | Gap observed at baseline | Missing proof |
|---|---|---|
| 001 | Resource handlers expose backend data independently of effective read scope. | Current-token checks for both HTTP eras. |
| 002 | A successful partial vulnerability collection can report a perfect A.8.8 score. | Exact totals and search completeness through board, aggregate and gap outputs. |
| 003 | Stored legacy session lookup, activity and deletion use a supplied ID without validating ownership. | Verified caller identity and denial without a store mutation. |
| 004 | Redaction occurs after serialization and backend exception text can reach clients. | Same sanitized data across JSON, GCF, fallback and error responses. |
| 005 | A failed Redis SCAN can appear as an empty healthy store. | Probe readiness through initialization, paginated failure, timeout and recovery. |
| 006 | Resource reads use the environment client while tools resolve the registry default. | Named-default and single-cluster parity across resource variants. |
| 007 | Adding OAuth parameters with a fresh question mark changes existing callback queries. | Exact callback validation and exchange across success and error paths. |
| 008 | Package changes bypass CI. | Scoped workflow plus an equivalent local verification command. |

Product gaps identified in the [design](../mcp-server/plans/PRODUCT-DESIGN.md) are an evidence-linked timeline, smaller task catalogs, saved investigations, a client viewer, per-cluster grants and executable compatibility checks. The response-approval component is specified as a stub-only design experiment. Offline verification and a deployment against a real service carry different evidence levels.

## How to reproduce the inventory

Use git status, git log scoped to mcp-server, git worktree list, git diff main feat/wazuh-mcp -- mcp-server, and read-only gh-axi issue list and pr list. Count documentation from git ls-files. Read pyproject.toml, the root workflow, the package README, WAZUH_COMPATIBILITY.md and docs before interpreting test counts as support claims. The eight executor handoffs contain exact file references, failure descriptions and focused commands. [Work packages](../mcp-server/plans/README.md)
