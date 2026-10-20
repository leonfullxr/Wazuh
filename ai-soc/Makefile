SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
UV ?= uv
NODE ?= build/tool-cache/node-v22.23.3/extracted/bin/node
NPM ?= build/tool-cache/node-v22.23.3/extracted/bin/npm
OFFLINE := scripts/run-offline.sh
PORT ?= 8000

.PHONY: bootstrap ui-build image-cache image-inputs-offline image-reproducibility infra-check check-session-teardown check-session-teardown-preflight check-session-teardown-drained fixture dev staging-golden lint

bootstrap:
	$(UV) sync --locked --all-groups
	UV_CACHE_DIR=$(CURDIR)/build/private/home/.cache/uv $(UV) build --wheel --out-dir build/private/bootstrap-wheel
	scripts/prepare-platform.sh
	$(NODE) $(NPM) ci --prefix ui --ignore-scripts --no-audit --no-fund
	$(UV) run --locked --offline python scripts/prepare_containers.py
	$(OFFLINE) $(UV) run --locked --offline python scripts/bootstrap.py
	$(UV) run --locked --offline python scripts/reproducible_image.py prepare-cache --uv $(UV)

ui-build:
	$(OFFLINE) $(NPM) --prefix ui run build

image-cache:
	$(UV) run --locked --offline python scripts/reproducible_image.py prepare-cache --uv $(UV)

image-inputs-offline:
	$(OFFLINE) $(UV) run --locked --offline python scripts/prepare_containers.py --offline-only

image-reproducibility: image-inputs-offline ui-build
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
	$(OFFLINE) $(UV) run --locked --offline ruff check .
	$(OFFLINE) $(UV) run --locked --offline ruff format --check .
	$(OFFLINE) $(UV) run --locked --offline pyright
