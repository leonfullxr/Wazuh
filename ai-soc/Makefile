SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
UV ?= uv
NODE ?= build/tool-cache/node-v22.23.3/extracted/bin/node
NPM ?= build/tool-cache/node-v22.23.3/extracted/bin/npm
DOCKER_COMPOSE ?= build/tool-cache/docker-compose-v5.5.1/docker-compose
PYTEST := $(UV) run --locked --offline python -m pytest
OFFLINE := scripts/run-offline.sh
PORT ?= 8000
EVIDENCE := build/evidence

.PHONY: bootstrap image-cache image-inputs-offline image-reproducibility test-contract test-unit test-security test-golden state-runtime-check test-e2e infra-check check-session-teardown check-session-teardown-preflight check-session-teardown-drained compose-check container-check fixture dev reproducibility staging-golden qualification-wheel-check ci-check

bootstrap:
	$(UV) sync --locked --all-groups
	UV_CACHE_DIR=$(CURDIR)/build/private/home/.cache/uv $(UV) build --wheel --out-dir build/private/bootstrap-wheel
	scripts/prepare-platform.sh
	$(NODE) $(NPM) ci --prefix ui --ignore-scripts --no-audit --no-fund
	$(NODE) $(NPM) ci --prefix contracts/v1/tooling --ignore-scripts --no-audit --no-fund
	$(UV) run --locked --offline python scripts/prepare_containers.py
	$(OFFLINE) $(UV) run --locked --offline python scripts/bootstrap.py
	$(OFFLINE) $(UV) run --locked --offline python -m ai_soc.contracts.freeze --check
	$(UV) run --locked --offline python scripts/reproducible_image.py prepare-cache --uv $(UV)

image-cache:
	$(UV) run --locked --offline python scripts/reproducible_image.py prepare-cache --uv $(UV)

image-inputs-offline:
	$(OFFLINE) $(UV) run --locked --offline python scripts/prepare_containers.py --offline-only

image-reproducibility: image-inputs-offline
	$(UV) run --locked --offline python scripts/reproducible_image.py build --scratch-root /dev/shm

test-contract:
	mkdir -p $(EVIDENCE)
	$(OFFLINE) $(PYTEST) --confcutdir=tests/contract tests/contract -q --strict-markers --junitxml=$(EVIDENCE)/contract.xml

test-unit:
	mkdir -p $(EVIDENCE)
	$(OFFLINE) $(PYTEST) tests/unit -q --strict-markers -m 'not live' --junitxml=$(EVIDENCE)/unit.xml

test-security:
	mkdir -p $(EVIDENCE)
	$(OFFLINE) $(PYTEST) tests/security -q --strict-markers -m 'not live' --junitxml=$(EVIDENCE)/security.xml

test-golden:
	mkdir -p $(EVIDENCE)
	rm -f $(EVIDENCE)/golden.xml $(EVIDENCE)/admission-runtime.xml
	$(OFFLINE) $(PYTEST) tests/golden tests/integration --ignore=tests/integration/admission_runtime -q --strict-markers -m 'not live' --junitxml=$(EVIDENCE)/golden.xml
	$(OFFLINE) $(UV) run --locked --offline python tests/integration/admission_runtime/run.py --junitxml=/dev/stdout > $(EVIDENCE)/admission-runtime.capture.log 2>&1
	$(OFFLINE) $(UV) run --locked --offline python scripts/junit_capture.py --input $(EVIDENCE)/admission-runtime.capture.log --output $(EVIDENCE)/admission-runtime.xml

state-runtime-check:
	mkdir -p $(EVIDENCE)
	rm -f $(EVIDENCE)/dynamodb-state-runtime.xml
	$(OFFLINE) $(UV) run --locked --offline python tests/integration/admission_runtime/run.py -k dynamodb_state --junitxml=/dev/stdout > $(EVIDENCE)/dynamodb-state-runtime.capture.log 2>&1
	$(OFFLINE) $(UV) run --locked --offline python scripts/junit_capture.py --input $(EVIDENCE)/dynamodb-state-runtime.capture.log --output $(EVIDENCE)/dynamodb-state-runtime.xml

test-e2e:
	$(OFFLINE) $(NPM) --prefix ui run typecheck
	$(OFFLINE) $(NPM) --prefix ui run build
	mkdir -p $(EVIDENCE)
	rm -f $(EVIDENCE)/ui.xml
	PLAYWRIGHT_BROWSERS_PATH=$(CURDIR)/build/tool-cache/playwright PLAYWRIGHT_JUNIT_OUTPUT_NAME=../$(EVIDENCE)/ui.xml $(OFFLINE) $(NPM) --prefix ui run test:e2e -- --reporter=junit
	rm -f $(EVIDENCE)/routes.xml
	PLAYWRIGHT_BROWSERS_PATH=$(CURDIR)/build/tool-cache/playwright PLAYWRIGHT_JUNIT_OUTPUT_NAME=../../$(EVIDENCE)/routes.xml $(OFFLINE) $(NPM) --prefix ui run test:e2e -- --config ../tests/e2e/playwright.config.mts
	mkdir -p $(EVIDENCE)
	$(OFFLINE) $(PYTEST) tests/e2e -q --strict-markers -m 'not live' --junitxml=$(EVIDENCE)/e2e.xml

infra-check:
	$(OFFLINE) $(UV) run --locked --offline python scripts/bootstrap.py
	$(OFFLINE) build/tool-cache/terraform/terraform -chdir=infra fmt -check -recursive
	$(OFFLINE) build/tool-cache/terraform/terraform -chdir=infra init -backend=false -lockfile=readonly
	$(OFFLINE) build/tool-cache/terraform/terraform -chdir=infra validate
	$(OFFLINE) build/tool-cache/tflint/tflint --chdir=infra
	$(OFFLINE) $(PYTEST) tests/security/infra -q --strict-markers

check-session-teardown:
	scripts/infra/check-session-teardown.sh

check-session-teardown-preflight:
	scripts/infra/check-session-teardown.sh preflight

check-session-teardown-drained:
	scripts/infra/check-session-teardown.sh drained

compose-check:
	$(UV) run --locked --offline python scripts/local_protocol_check.py
	$(OFFLINE) $(PYTEST) tests/integration/harness -q --strict-markers

container-check:
	$(UV) run --locked --offline python scripts/prepare_containers.py
	$(UV) run --locked --offline python scripts/local_protocol_check.py

live-boot-check:
	$(UV) run --locked --offline python scripts/live_boot_check.py

fixture:
	rm -rf build/dev-fixture
	$(OFFLINE) $(UV) run --locked --offline python examples/content-seed/run_fixture_demo.py --work-dir build/dev-fixture

dev:
	$(UV) run --locked --offline python -m ai_soc.devserver --pack build/dev-fixture/build-a --credentials build/dev-fixture/credentials.json --port $(PORT)

reproducibility:
	mkdir -p $(EVIDENCE)
	$(PYTEST) tests/reproducibility -q --strict-markers -m 'not live' --junitxml=$(EVIDENCE)/reproducibility.xml

staging-golden:
	$(UV) run --locked python scripts/staging_golden.py --manifest config/staging-validation.json $(STAGING_ARGS)

qualification-wheel-check:
	$(OFFLINE) $(UV) run --locked --offline python scripts/qualification_wheel_check.py

ci-check: test-contract test-unit test-security test-golden test-e2e image-reproducibility infra-check compose-check reproducibility
	$(OFFLINE) $(UV) run --locked --offline ruff check .
	$(OFFLINE) $(UV) run --locked --offline ruff format --check .
	$(OFFLINE) $(UV) run --locked --offline pyright
	$(OFFLINE) $(UV) run --locked --offline python scripts/qualification_wheel_check.py
	$(OFFLINE) $(UV) run --locked --offline python scripts/coverage.py --require-all --results $(EVIDENCE)
	$(OFFLINE) build/tool-cache/trivy/trivy fs --skip-db-update --scanners secret,license --format json --output $(EVIDENCE)/trivy-fs.json .
