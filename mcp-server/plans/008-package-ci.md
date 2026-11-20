# Run the MCP package checks on pull requests

P2 · Small · Low change risk · Independent. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

The only repository workflow, ../.github/workflows/ai-soc-ci.yml:5, filters on `ai-soc/**`. This package has Ruff, pytest, branch coverage and a 37% configured coverage floor in pyproject.toml. The documented development install is `pip install -e '.[dev]'`. A socket-capable Python 3.11 environment passed 641 tests at the planning revision.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `../.github/workflows/mcp-server-ci.yml`

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- ../.github/workflows/mcp-server-ci.yml`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Add a package-specific GitHub Actions workflow for pull requests and main pushes touching `mcp-server/**` or its own workflow, plus manual dispatch. Follow the sibling workflow’s pinned actions and `contents: read`; set working directory to mcp-server and disable persisted checkout credentials. Start with the established Python 3.11 job. Enable the Python 3.13 container-interpreter job in the matrix after a clean 3.13 environment passes the same commands. Track that result independently. Install with `python -m pip install -e '.[dev]'`, run `python -m pip check`, `python -m ruff check .` and `python -m pytest -q --cov` so pyproject.toml owns the floor. Use a bounded job timeout. No live SIEM credentials are needed.

Use ubuntu-24.04 and the sibling workflow’s exact pins: `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` and `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`. Use `pull_request`, a main push and manual dispatch, with top-level `permissions: {contents: read}`. Paths are relative to repo root. Cancel superseded PR jobs only. A path-filtered workflow needs an unconditional gate before it can serve as a required check for every PR. If actionlint is absent, parse with PyYAML safe_load (quote YAML key `"on"`), assert triggers, paths, pins, permissions, matrix, working directory, editable install, lint and coverage steps. A parser checks structure only.

## Acceptance tests

Validate workflow YAML and event paths locally. Use actionlint when available. Run the job’s package commands from a clean package environment. The first authorized CI execution must show each enabled job green for an MCP change. Record 3.13 as pending until it qualifies. Until Actions has run, record local verification and mark hosted results pending. Keep unrelated ai-soc workflows and deployments outside the change.

1. Run `.venv/bin/python -m pytest -q tests --cov` against the current checkout. Confirm the baseline before adding the workflow.
2. Implement the contract, then rerun the focused command. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q --cov` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

This is the one work item whose implementation requires a root-level file. GitHub discovers workflows only under .github/workflows. Container publishing, dependency locks and hosted branch-protection settings are separate decisions.
