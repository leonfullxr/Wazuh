"""Environment-backed configuration for the MCP-LLM gateway."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    gateway_host: str
    gateway_port: int
    gateway_api_key: str
    gateway_public_host: str
    mcp_sse_url: str
    llm_provider: str
    openai_api_key: str
    openai_model: str
    gemini_api_key: str
    gemini_model: str
    aws_region: str
    bedrock_model_id: str
    aws_access_key_id: str
    aws_secret_access_key: str
    openai_compatible_base_url: str
    openai_compatible_model: str
    openai_compatible_api_key: str
    wazuh_manager_ip: str
    wazuh_manager_port: int
    wazuh_manager_user: str
    wazuh_manager_pass: str
    wazuh_dashboard_ip: str
    wazuh_dashboard_user: str
    wazuh_dashboard_pass: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_pass: str
    smtp_from: str


def load_config() -> Config:
    return Config(
        gateway_host=os.getenv("GATEWAY_HOST", "0.0.0.0"),
        gateway_port=int(os.getenv("GATEWAY_PORT", "9912")),
        gateway_api_key=os.getenv("GATEWAY_API_KEY", ""),
        gateway_public_host=os.getenv("GATEWAY_PUBLIC_HOST", "127.0.0.1"),
        mcp_sse_url=os.getenv(
            "MCP_SSE_URL", "http://127.0.0.1:9900/mcp"
        ),
        llm_provider=os.getenv("LLM_PROVIDER", "openai").lower(),
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
        aws_region=os.getenv("AWS_REGION", "us-east-1"),
        bedrock_model_id=os.getenv("BEDROCK_MODEL_ID", ""),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", ""),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", ""),
        openai_compatible_base_url=os.getenv("OPENAI_COMPATIBLE_BASE_URL", ""),
        openai_compatible_model=os.getenv("OPENAI_COMPATIBLE_MODEL", ""),
        openai_compatible_api_key=os.getenv("OPENAI_COMPATIBLE_API_KEY", ""),
        wazuh_manager_ip=os.getenv("WAZUH_MANAGER_IP", "127.0.0.1"),
        wazuh_manager_port=int(os.getenv("WAZUH_MANAGER_PORT", "55000")),
        wazuh_manager_user=os.getenv("WAZUH_MANAGER_USER", "wazuh-wui"),
        wazuh_manager_pass=os.getenv("WAZUH_MANAGER_PASS", ""),
        wazuh_dashboard_ip=os.getenv("WAZUH_DASHBOARD_IP", "127.0.0.1"),
        wazuh_dashboard_user=os.getenv("WAZUH_DASHBOARD_USER", "admin"),
        wazuh_dashboard_pass=os.getenv("WAZUH_DASHBOARD_PASS", ""),
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_user=os.getenv("SMTP_USER", ""),
        smtp_pass=os.getenv("SMTP_PASS", ""),
        smtp_from=os.getenv("SMTP_FROM", ""),
    )


CFG = load_config()
