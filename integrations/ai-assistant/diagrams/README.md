# Diagrams

Editable `.drawio` sources live here; PNG exports are in [`png/`](png/) (regenerate with `make diagrams-png`). The current architecture is the v3 set; the rest are kept for lineage.

## Current architecture (v3.8)

### `wazuh-ai-v3-icons.drawio` - icon-forward overview
The whole system at a glance and one turn end to end, glyph-driven.

![v3.8 topology](png/wazuh-ai-v3-icons--v38-topology-icons.png)
![v3.8 turn flow](png/wazuh-ai-v3-icons--v38-turn-flow-icons.png)

### `wazuh-ai-v3-gateway.drawio` - topology, labelled
The target multi-environment shape (one gateway, N environments) and its single-environment realization on the harness.

![Target: one gateway, N environments](png/wazuh-ai-v3-gateway--1-v3-target-one-gateway-n-environments.png)
![PoC: single environment on the harness](png/wazuh-ai-v3-gateway--2-v3-poc-single-environment-on-the-harness.png)

### `wazuh-ai-v3-workflow.drawio` - one turn, labelled
The full turn with every branch: both edges, admission, conversational/API confirm, language and scope, the read lane cascade, the write-actions lane, the veracity pipeline, and answer assembly.

![v3.8 turn workflow](png/wazuh-ai-v3-workflow.png)

### `wazuh-ai-selfhosted.drawio` - self-hosted deployment
The PoC as it runs on one machine, and how the same codebase scales to many environments.

![Self-hosted PoC on one machine](png/wazuh-ai-selfhosted--self-hosted-poc-icons.png)
![Self-hosted vs multi-environment](png/wazuh-ai-selfhosted--self-hosted-vs-cloud-icons.png)

## Enhancement pass (as built)

`wazuh-ai-enhancements.drawio` - the scope classifier, near-miss few-shot, knowledge tool, caching, and the local AMD test harness, with measured golden-set results.

![Enhanced turn workflow](png/wazuh-ai-enhancements--1-enhanced-turn-workflow.png)
![Caches and knowledge placement](png/wazuh-ai-enhancements--2-caches-and-knowledge-placement.png)
![Local test harness (AMD)](png/wazuh-ai-enhancements--3-local-test-harness-amd.png)

## Original self-hosted PoC (historical, v1/v2)

`wazuh-ai-poc-architecture.drawio` - the original eight-diagram deck. The veracity core it describes (lanes, the four checks, the local harness) is unchanged; the topology and identity have since moved to the v3 set above.

![Local PoC harness](png/wazuh-ai-poc-architecture--1-local-poc-harness.png)
![One question, end to end](png/wazuh-ai-poc-architecture--2-one-question-end-to-end.png)
![One port, three postures](png/wazuh-ai-poc-architecture--3-one-port-three-postures.png)
![Query cascade](png/wazuh-ai-poc-architecture--4-query-cascade.png)
![Veracity lanes](png/wazuh-ai-poc-architecture--5-veracity-lanes.png)
![Injection defense](png/wazuh-ai-poc-architecture--6-injection-defense.png)
![Eval harness](png/wazuh-ai-poc-architecture--7-eval-harness.png)
![Production topology](png/wazuh-ai-poc-architecture--8-production-topology.png)
