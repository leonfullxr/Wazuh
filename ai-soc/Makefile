SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
UV ?= uv
NODE ?= build/tool-cache/node-v22.23.3/extracted/bin/node
NPM ?= build/tool-cache/node-v22.23.3/extracted/bin/npm
OFFLINE := scripts/run-offline.sh
PORT ?= 8000

.PHONY: bootstrap web-build image-cache image-inputs-offline image-reproducibility infra-check check-session-teardown check-session-teardown-preflight check-session-teardown-drained fixture dev staging-golden lint ws-db-up ws-db-down ws-migrate ws-provision-role ws-backfill ws-poll ws-worker ws-correlate ws-partitions ws-audit-relay ws-model-prepare ws-model-drain ws-model-watch ws-model-status ws-model-provision

bootstrap:
	$(UV) sync --locked --all-groups
	UV_CACHE_DIR=$(CURDIR)/build/private/home/.cache/uv $(UV) build --wheel --out-dir build/private/bootstrap-wheel
	scripts/prepare-platform.sh
	$(NODE) $(NPM) ci --prefix web --ignore-scripts --no-audit --no-fund
	$(UV) run --locked --offline python scripts/prepare_containers.py
	$(OFFLINE) $(UV) run --locked --offline python scripts/bootstrap.py
	$(UV) run --locked --offline python scripts/reproducible_image.py prepare-cache --uv $(UV)

web-build:
	$(OFFLINE) $(NPM) --prefix web run build

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

fixture:
	rm -rf build/dev-fixture
	$(OFFLINE) $(UV) run --locked --offline python examples/content-seed/run_fixture_demo.py --work-dir build/dev-fixture

dev:
	$(UV) run --locked --offline python -m ai_soc.devserver --pack build/dev-fixture/build-a --credentials build/dev-fixture/credentials.json --port $(PORT)

staging-golden:
	$(UV) run --locked python scripts/staging_golden.py --manifest config/staging-validation.json $(STAGING_ARGS)

lint:
	$(UV) run --locked --offline python scripts/check-production-tree.py
	$(OFFLINE) $(UV) run --locked --offline ruff check .
	$(OFFLINE) $(UV) run --locked --offline ruff format --check .
	$(OFFLINE) $(UV) run --locked --offline pyright

ws-db-up:
	$(UV) run --locked python scripts/workspace/db.py up

ws-db-down:
	$(UV) run --locked python scripts/workspace/db.py down

ws-migrate:
	$(UV) run --locked python scripts/workspace/db.py migrate

ws-provision-role:
	$(UV) run --locked python scripts/workspace/provision_role.py

ws-backfill:
	$(UV) run --locked python -m ai_soc.workspace.backfill $(WS_ARGS)

ws-poll:
	$(UV) run --locked python -m ai_soc.workspace.poll $(WS_ARGS)

ws-worker:
	$(UV) run --locked python -m ai_soc.workspace.worker $(WS_ARGS)

ws-correlate:
	$(UV) run --locked --offline python -m ai_soc.workspace.correlate.runner $(WS_ARGS)

ws-partitions:
	$(UV) run --locked python -m ai_soc.workspace.partitions $(WS_ARGS)

ws-audit-relay:
	$(UV) run --locked python -m ai_soc.workspace.audit_delivery $(WS_ARGS)

ws-model-prepare:
	$(UV) run --locked --offline python -m ai_soc.workspace.model.worker prepare $(WS_ARGS)

ws-model-drain:
	$(UV) run --locked --offline python -m ai_soc.workspace.model.worker drain $(WS_ARGS)

ws-model-status:
	$(UV) run --locked --offline python -m ai_soc.workspace.model.worker status $(WS_ARGS)

ws-model-provision:
	$(UV) run --locked --offline python -m ai_soc.workspace.model.worker provision $(WS_ARGS)

ws-model-watch:
	$(UV) run --locked --offline python -m ai_soc.workspace.model.worker watch $(WS_ARGS)
