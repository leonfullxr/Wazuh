"""Direct action executors (manager, dashboard, SMTP)."""
from __future__ import annotations

import base64
import smtplib
from email.message import EmailMessage
from typing import Callable

import httpx

from .config import CFG
from .confirm import PendingAction
from .routing import ACTION_DASHBOARD, ACTION_REPORT, ACTION_RESTART


def _manager_base_url() -> str:
    return f"https://{CFG.wazuh_manager_ip}:{CFG.wazuh_manager_port}"


def _manager_token(client: httpx.Client) -> str:
    """Authenticate against the Wazuh manager API and return a JWT."""
    resp = client.post(
        f"{_manager_base_url()}/security/user/authenticate",
        auth=(CFG.wazuh_manager_user, CFG.wazuh_manager_pass),
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("data", {}).get("token")
    if not token:
        raise RuntimeError("Manager authenticate response did not include data.token")
    return token


def restart_agent(agent_id: str) -> str:
    """Restart a Wazuh agent through the manager API (port 55000, JWT)."""
    with httpx.Client(verify=False, timeout=60.0) as client:
        token = _manager_token(client)
        resp = client.put(
            f"{_manager_base_url()}/agents/{agent_id}/restart",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
    return f"Restart requested for agent {agent_id}."


def create_dashboard(name: str) -> str:
    """Create a saved-object dashboard stub via the Wazuh dashboard API."""
    url = f"https://{CFG.wazuh_dashboard_ip}/api/saved_objects/dashboard"
    payload = {
        "attributes": {
            "title": name,
            "description": "Created by AI assistant",
            "hits": 0,
            "optionsJSON": "{}",
            "panelsJSON": "[]",
            "version": 1,
        }
    }
    auth = (CFG.wazuh_dashboard_user, CFG.wazuh_dashboard_pass)
    headers = {"osd-xsrf": "true", "Content-Type": "application/json"}
    with httpx.Client(verify=False, timeout=60.0) as client:
        resp = client.post(url, json=payload, auth=auth, headers=headers)
        resp.raise_for_status()
    return f"Dashboard '{name}' created."


def send_pdf_report(email: str, pdf_bytes: bytes | None = None) -> str:
    """Email a PDF report through SMTP."""
    if not CFG.smtp_host:
        raise RuntimeError("SMTP_HOST is not configured")
    body = pdf_bytes or b"%PDF-1.4\n% AI assistant sample report\n"
    msg = EmailMessage()
    msg["Subject"] = "Wazuh AI assistant report"
    msg["From"] = CFG.smtp_from or CFG.smtp_user
    msg["To"] = email
    msg.set_content("Attached PDF report from the Wazuh dashboard assistant.")
    msg.add_attachment(
        body,
        maintype="application",
        subtype="pdf",
        filename="wazuh-report.pdf",
    )
    with smtplib.SMTP(CFG.smtp_host, CFG.smtp_port, timeout=60) as smtp:
        if CFG.smtp_user:
            smtp.starttls()
            smtp.login(CFG.smtp_user, CFG.smtp_pass)
        smtp.send_message(msg)
    return f"Report emailed to {email}."


def execute_pending_action(action: PendingAction) -> str:
    if action.intent == ACTION_RESTART:
        agent_id = action.params.get("agent_id", "unknown")
        return restart_agent(agent_id)
    if action.intent == ACTION_DASHBOARD:
        name = action.params.get("dashboard_name", "AI Assistant Dashboard")
        return create_dashboard(name)
    if action.intent == ACTION_REPORT:
        email = action.params.get("email", "")
        pdf = action.params.get("pdf_bytes")
        if isinstance(pdf, str):
            pdf = base64.b64decode(pdf)
        return send_pdf_report(email, pdf)
    return f"Unknown action: {action.intent}"


# Injectable hook for tests.
action_executor: Callable[[PendingAction], str] = execute_pending_action
