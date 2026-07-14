# wazuh-ai local PoC harness - see README.md for the walkthrough
SHELL := /bin/bash
-include .env
export

WAZUH_VERSION ?= 4.14.5
WAZUH_DIR := .wazuh-docker/single-node
OLLAMA_MODEL ?= gpt-oss:20b
EMBED_MODEL ?= bge-m3

.PHONY: keys wazuh securityconfig poc ollama ollama-gpu-verify embed airllm seed evals evals-fresh evals-qwen3 bakeoff demo-storyline test logs down clean

keys:
	./keys/gen-keys.sh

wazuh:
	@if [ ! -d .wazuh-docker ]; then \
	  git clone --depth 1 --branch v$(WAZUH_VERSION) https://github.com/wazuh/wazuh-docker.git .wazuh-docker ; \
	fi
	cd $(WAZUH_DIR) && docker compose -f generate-indexer-certs.yml run --rm generator
	cd $(WAZUH_DIR) && docker compose up -d
	@echo "Wazuh single-node starting. Dashboard: https://localhost:443 (admin / $(INDEXER_ADMIN_PASSWORD))"

securityconfig:
	./securityconfig/apply.sh

poc:
	docker compose -f docker-compose.poc.yml up -d --build
	@echo "keycloak: http://localhost:8085  n8n: http://localhost:5678  tool-service: http://localhost:8080"

ollama:
	docker compose -f docker-compose.poc.yml --profile ollama up -d ollama
	docker compose -f docker-compose.poc.yml exec ollama ollama pull $(OLLAMA_MODEL)
	@echo "ollama serving $(OLLAMA_MODEL). Set WAI_LLM_PROVIDER=openai and the"
	@echo "WAI_MODEL_* ids in .env (option B), then: make poc"
	@echo "Sparse MoE upgrades (README s3.4): make ollama OLLAMA_MODEL=gpt-oss:20b"
	@echo "(16 GB systems) or OLLAMA_MODEL=qwen3:30b-a3b (32 GB / 24 GB VRAM)"
	@echo "Verify GPU: make ollama-gpu-verify"

ollama-gpu-verify:
	@echo "=== ollama ps (expect GPU/ROCm, not 100% CPU) ==="
	@docker compose -f docker-compose.poc.yml exec ollama ollama ps 2>/dev/null || \
	  echo "ollama not running - start with: make ollama"
	@echo "=== rocm-smi (host, if installed) ==="
	@rocm-smi --showuse 2>/dev/null || echo "rocm-smi not on PATH (optional host check)"

embed:
	docker compose -f docker-compose.poc.yml --profile ollama up -d ollama
	docker compose -f docker-compose.poc.yml exec ollama ollama pull $(EMBED_MODEL)
	@echo "$(EMBED_MODEL) ready. Enable lane 0 with WAI_LANE0_ENABLED=true in .env"
	@echo "(README s3.5), then recreate the tool service."

airllm:
	docker compose -f docker-compose.poc.yml --profile airllm up -d --build airllm-shim
	@echo "airllm-shim on :8090 (EXPERIMENTAL batch depth lane, README s3.4)."
	@echo "Bind the analysis tier to it with .env option D2. First request"
	@echo "downloads and layer-splits AIRLLM_MODEL_ID - expect minutes per answer."

seed:
	python3 seed/seed_alerts.py

evals:
	python3 golden/run_evals.py

evals-fresh: seed evals

demo-storyline:
	python3 scripts/demo_storyline.py

# Three-model bake-off (section 7). Recreates tool-service per model so the
# container actually answers with each candidate. Artifacts: golden/last_run.<model>.json
BAKEOFF_MODELS ?= gpt-oss:20b qwen2.5:14b qwen3:30b-a3b
bakeoff:
	@set -e; \
	for m in $(BAKEOFF_MODELS); do \
	  echo "=== bake-off: $$m ==="; \
	  docker compose -f docker-compose.poc.yml --profile ollama exec -T ollama ollama pull $$m; \
	  WAI_LLM_PROVIDER=openai WAI_MODEL_ROUTER=$$m WAI_MODEL_ANALYSIS=$$m \
	    docker compose -f docker-compose.poc.yml up -d --force-recreate tool-service; \
	  until curl -sf http://localhost:8080/healthz >/dev/null 2>&1; do sleep 2; done; \
	  WAI_LLM_PROVIDER=openai WAI_MODEL_ROUTER=$$m WAI_MODEL_ANALYSIS=$$m \
	    python3 golden/run_evals.py || true; \
	  cp golden/last_run.json "golden/last_run.$$(echo $$m | tr ':/' '--').json"; \
	done; \
	echo "artifacts: golden/last_run.*.json"

# ---- Qwen3 instruct retry (lane 0 off — model-only golden run) ---------------
# Official non-thinking instruct build; raise output cap for tool-heavy turns.
# make evals-qwen3
QWEN3_INSTRUCT_MODEL ?= qwen3:30b-a3b-instruct-2507-q4_K_M

evals-qwen3:
	python3 seed/seed_alerts.py
	docker compose -f docker-compose.poc.yml --profile ollama exec -T ollama ollama pull $(QWEN3_INSTRUCT_MODEL)
	WAI_LLM_PROVIDER=openai \
	WAI_MODEL_ROUTER=$(QWEN3_INSTRUCT_MODEL) WAI_MODEL_ANALYSIS=$(QWEN3_INSTRUCT_MODEL) \
	WAI_LANE0_ENABLED=false WAI_MAX_OUTPUT_TOKENS=4096 \
		docker compose -f docker-compose.poc.yml up -d --build --force-recreate tool-service
	@until curl -sf http://localhost:8080/healthz >/dev/null 2>&1; do sleep 2; done
	WAI_LLM_PROVIDER=openai \
	WAI_MODEL_ROUTER=$(QWEN3_INSTRUCT_MODEL) WAI_MODEL_ANALYSIS=$(QWEN3_INSTRUCT_MODEL) \
	WAI_EVAL_TIMEOUT_S=600 python3 golden/run_evals.py; \
	cp golden/last_run.json "golden/last_run.$$(echo $(QWEN3_INSTRUCT_MODEL) | tr ':/' '--').json"

test:
	docker compose -f docker-compose.poc.yml run --rm --no-deps \
	  -v ./tool-service/tests:/app/tests:ro --entrypoint sh tool-service \
	  -c "pip install -q pytest && python -m pytest -q tests"

logs:
	docker compose -f docker-compose.poc.yml logs -f tool-service auth-shim

down:
	docker compose -f docker-compose.poc.yml down
	cd $(WAZUH_DIR) && docker compose down

clean: down
	rm -rf .wazuh-docker securityconfig/tmp golden/ground_truth.json
