"""Deployment configuration. The tenant id comes from here and only here -
never from anything the user or the model says (D6)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WAI_")

    tenant: str = "lab"

    # Identity (verify-only: the mint key never exists in this process, D30)
    jwt_public_key_path: str = "/keys/jwt-public.pem"
    jwt_issuer: str = "wazuh-ai-shim.lab"
    jwt_audience: str = "wazuh-ai-backend.lab"
    access_role: str = "wazuh_ai_analyst"

    # Datastore
    indexer_url: str = "https://wazuh.indexer:9200"
    indexer_verify_ssl: bool = False  # lab only - prod pins the tenant CA
    alerts_index: str = "wazuh-alerts-*"
    vulnerabilities_index: str = "wazuh-states-vulnerabilities-*"

    # Inference backend (README s3): "bedrock" (default) or "openai" for any
    # OpenAI-compatible chat-completions endpoint (Ollama, Groq, LiteLLM, ...)
    llm_provider: str = "bedrock"
    llm_base_url: str = "http://ollama:11434/v1"
    llm_api_key: str = ""

    # Two model tiers (D37). Ids depend on the provider: Bedrock inference
    # profiles (verify with `aws bedrock list-inference-profiles`)
    # or whatever the OpenAI-compatible endpoint serves (qwen2.5:14b, ...).
    model_router: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    model_analysis: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

    # Per-tier overrides (D39, 13 s3.4): each tier may bind to its OWN
    # provider and endpoint, so a small resident local model can route while
    # analysis runs on Bedrock, a bigger local endpoint, or a layer-streamed
    # batch backend. Empty string = inherit the globals above.
    router_provider: str = ""
    router_base_url: str = ""
    router_api_key: str = ""
    analysis_provider: str = ""
    analysis_base_url: str = ""
    analysis_api_key: str = ""

    # Guardrails attach on the bedrock provider only (D38)
    guardrail_id: str = ""
    guardrail_version: str = "DRAFT"

    # Lane 0 - the semantic fast path (D40, README s3.5). Embedding-matched
    # question -> curated typed template, executed with NO model in the loop.
    # Needs an embeddings endpoint (any OpenAI-compatible /v1/embeddings;
    # bge-m3 on the ollama service works and is bilingual). Off by default.
    lane0_enabled: bool = False
    lane0_threshold: float = 0.80  # cosine floor; verify per embedding model
    lane0_near_miss_floor: float = 0.65  # below threshold but above -> few-shot hint
    embed_provider: str = "openai"  # openai | mlcommons (C3)
    embed_base_url: str = "http://ollama:11434/v1"
    embed_model: str = "bge-m3"
    embed_api_key: str = ""
    embed_ml_model_id: str = ""  # ML Commons deployed model id when provider=mlcommons

    # Saved-objects index for list_dashboards (C1); verify on your Wazuh fork.
    saved_objects_index: str = ".kibana"

    # Scope classifier (P1.2): active only when lane 0 is enabled (same embed endpoint).
    scope_classifier_enabled: bool = True
    scope_margin: float = 0.05  # refuse when out_score - in_score >= this

    # IR-keyed evidence cache (D41, README s3.5). 0 disables. When on, identical
    # query plans within the TTL are served from memory and labeled as such.
    evidence_cache_ttl: int = 0

    # Ops knobs (README s8)
    streaming: bool = True          # token-by-token SSE from the providers
    queue_wait_s: float = 30.0      # D14: queue for capacity, then honest reject
    service_enabled: bool = True    # kill switch: false -> 503 on all surfaces
    conversation_ttl: int = 3600    # in-memory multi-turn window (prod: indexer)
    conversation_max_turns: int = 8 # question/answer pairs kept per conversation
    indexer_ca_path: str = ""       # pin the tenant root CA instead of verify=off
    prompt_cache: bool = False      # Bedrock cachePoint on the prelude (verify, Q4)

    # Actions v1.5 (D20/D35) — write operations
    actions_enabled: bool = False
    actions_direct: bool = False  # propose/confirm default; dashboard-only when True
    action_proposal_ttl_s: int = 900
    operator_role: str = "wazuh_ai_operator"
    responder_role: str = "wazuh_ai_responder"
    # Browser confirm UI (V3.5c) — host-facing URLs for dashboard + auth-shim
    ui_public_base_url: str = "http://localhost:8080"
    actions_shim_public_url: str = "http://localhost:8081"
    actions_env_id: str = "lab"
    actions_cors_origins: str = (
        "https://localhost,http://localhost:5601,https://localhost:5601"
    )

    # Lanes and loop caps (D23/D32)
    lane2_enabled: bool = True
    max_tool_calls: int = 6
    evidence_budget_chars: int = 8000
    max_output_tokens: int = 2048
    connector_timeout_s: float = 110.0
    envs_file: str = ""
    env_card_ttl: int = 900  # 15 min; 0 disables the env context card (V3.7c)

    # Admission (a deliberately tiny D14: per-user single stream + per-tenant gate)
    tenant_concurrent: int = 2
    user_turns_per_minute: int = 6


CFG = Settings()
