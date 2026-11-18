SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
UV ?= uv
NODE ?= build/tool-cache/node-v22.23.3/extracted/bin/node
NPM ?= npm
OFFLINE := scripts/run-offline.sh
PORT ?= 8000
LOCAL_PORT ?= 8123
LOCAL_DIR ?= build/local-ai-soc
LOCAL_UV = UV_PROJECT_ENVIRONMENT="$(CURDIR)/build/local-python" $(UV) run --locked --no-dev

.PHONY: dev-setup ci-check agent-check test test-web bootstrap web-build image-cache image-inputs-offline image-reproducibility infra-check check-session-teardown check-session-teardown-preflight check-session-teardown-drained local-init local local-down staging-golden lint ws-db-up ws-db-down ws-migrate ws-provision-role ws-backfill ws-poll ws-worker ws-correlate ws-partitions ws-audit-relay ws-model-prepare ws-model-drain ws-model-watch ws-model-status ws-model-provision

dev-setup:
	$(UV) sync --locked --all-groups
	$(NPM) --prefix web ci --no-audit --no-fund

ci-check: lint test
	$(NPM) --prefix web run typecheck
	$(NPM) --prefix web run validators:check
	$(NPM) --prefix web run workspace-types:check
	$(NPM) --prefix web run workspace-validators:check
	$(NPM) --prefix web test
	$(NPM) --prefix web run build

agent-check:
	$(UV) run --locked --offline python internal/tools/agent_environment/scope.py check

bootstrap:
	$(UV) sync --locked --all-groups
	UV_CACHE_DIR=$(CURDIR)/build/private/home/.cache/uv $(UV) build --wheel --out-dir build/private/bootstrap-wheel
	scripts/prepare-platform.sh
	$(NODE) build/tool-cache/node-v22.23.3/extracted/bin/npm ci --prefix web --ignore-scripts --no-audit --no-fund
	$(UV) run --locked --offline python scripts/prepare_containers.py
	$(OFFLINE) $(UV) run --locked --offline python scripts/bootstrap.py
	$(UV) run --locked --offline python scripts/reproducible_image.py prepare-cache --uv $(UV)

web-build:
	$(OFFLINE) build/tool-cache/node-v22.23.3/extracted/bin/npm --prefix web run build

image-cache:
	$(UV) run --locked --offline python scripts/reproducible_image.py prepare-cache --uv $(UV)

image-inputs-offline:
	$(OFFLINE) $(UV) run --locked --offline python scripts/prepare_containers.py --offline-only

image-reproducibility: image-inputs-offline web-build
	$(UV) run --locked --offline python scripts/reproducible_image.py build --scratch-root /dev/shm

infra-check:
	$(OFFLINE) $(UV) run --locked --offline python scripts/bootstrap.py
	$(OFFLINE) build/tool-cache/terraform/terraform -chdir=infra fmt -check -recursive
	$(OFFLINE) build/tool-cache/terraform/terraform -chdir=infra init -backend=false -lockfile=readonly
	$(OFFLINE) build/tool-cache/terraform/terraform -chdir=infra validate
	$(OFFLINE) build/tool-cache/tflint/tflint --chdir=infra

check-session-teardown:
	scripts/infra/check-session-teardown.sh

check-session-teardown-preflight:
	scripts/infra/check-session-teardown.sh preflight

check-session-teardown-drained:
	scripts/infra/check-session-teardown.sh drained

local-init:
	$(LOCAL_UV) python -m ai_soc.local.launcher init --state-dir "$(LOCAL_DIR)" --port $(LOCAL_PORT)

local:
	$(NPM) --prefix web ci --include=dev --no-audit --no-fund
	$(NPM) --prefix web run build
	$(LOCAL_UV) python -m ai_soc.local.launcher up --state-dir "$(LOCAL_DIR)" --port $(LOCAL_PORT)

local-down:
	$(LOCAL_UV) python -m ai_soc.local.launcher down --state-dir "$(LOCAL_DIR)" --port $(LOCAL_PORT)

staging-golden:
	$(UV) run --locked python scripts/staging_golden.py --manifest config/staging-validation.json $(STAGING_ARGS)

test:
	$(UV) run --locked python -m pytest -q

test-web:
	$(NPM) --prefix web run test:unit

lint:
	@if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		$(UV) run --locked python scripts/check-production-tree.py; \
	else \
		echo "Skipping production index check: no Git worktree"; \
	fi
	$(UV) run --locked ruff check src scripts verification
	$(UV) run --locked ruff format --check src scripts verification
	$(UV) run --locked pyright

ws-db-up:
	$(UV) run --locked --no-dev python scripts/workspace/db.py up

ws-db-down:
	$(UV) run --locked --no-dev python scripts/workspace/db.py down

ws-migrate:
	$(UV) run --locked --no-dev python scripts/workspace/db.py migrate

ws-provision-role:
	$(UV) run --locked --no-dev python scripts/workspace/provision_role.py

ws-backfill:
	$(UV) run --locked --no-dev python -m ai_soc.workspace.backfill $(WS_ARGS)

ws-poll:
	$(UV) run --locked --no-dev python -m ai_soc.workspace.poll $(WS_ARGS)

ws-worker:
	$(UV) run --locked --no-dev python -m ai_soc.workspace.worker $(WS_ARGS)

ws-correlate:
	$(UV) run --locked --no-dev --offline python -m ai_soc.workspace.correlate.runner $(WS_ARGS)

ws-partitions:
	$(UV) run --locked --no-dev python -m ai_soc.workspace.partitions $(WS_ARGS)

ws-audit-relay:
	$(UV) run --locked --no-dev python -m ai_soc.workspace.audit_delivery $(WS_ARGS)

ws-model-prepare:
	$(UV) run --locked --no-dev --offline python -m ai_soc.workspace.model.worker prepare $(WS_ARGS)

ws-model-drain:
	$(UV) run --locked --no-dev --offline python -m ai_soc.workspace.model.worker drain $(WS_ARGS)

ws-model-status:
	$(UV) run --locked --no-dev --offline python -m ai_soc.workspace.model.worker status $(WS_ARGS)

ws-model-provision:
	$(UV) run --locked --no-dev --offline python -m ai_soc.workspace.model.worker provision $(WS_ARGS)

ws-model-watch:
	$(UV) run --locked --no-dev --offline python -m ai_soc.workspace.model.worker watch $(WS_ARGS)
