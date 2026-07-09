"""EXPERIMENTAL - AirLLM depth-lane shim (README s3.4, D39).

Wraps AirLLM's layer-streamed generation in the OpenAI chat-completions
dialect, so the tool service's existing `openai` provider can point at it
with zero changes: WAI_ANALYSIS_BASE_URL=http://airllm-shim:8090/v1.

What AirLLM buys: models far larger than the hardware (70B-class on a 4-8 GB
GPU) by keeping one transformer layer resident at a time and streaming the
rest from disk. What it costs: measured 0.07-0.7 tokens/second, so this is a
BATCH lane for rare depth jobs, never the interactive path. AirLLM ships no
server, no chat template handling and no tool calling (verified against the
repo, 2026-06), so this shim adds all three:

  - chat templating via the model tokenizer's apply_chat_template, with a
    plain-text fallback
  - a prompt-rendered tool convention: schemas are injected into the system
    prompt and a fenced ```tool_call``` JSON block in the output is parsed
    back into an OpenAI tool_calls response. Big models usually manage this;
    it is a convention, not a guarantee - hence experimental
  - single-flight serving: layer streaming saturates the disk, so one
    request at a time, everything else queues on the lock
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid

from fastapi import FastAPI

MODEL_ID = os.environ.get("AIRLLM_MODEL_ID", "Qwen/Qwen2.5-7B-Instruct")
COMPRESSION = os.environ.get("AIRLLM_COMPRESSION", "4bit")  # '4bit' | '8bit' | ''
MAX_NEW_TOKENS = int(os.environ.get("AIRLLM_MAX_NEW_TOKENS", "512"))
MAX_INPUT_TOKENS = int(os.environ.get("AIRLLM_MAX_INPUT_TOKENS", "3072"))

app = FastAPI(title="airllm depth-lane shim")
_model = None
_lock = asyncio.Lock()

TOOL_CALL_RE = re.compile(r"```tool_call\s*(\{.*?\})\s*```", re.DOTALL)


def _load() -> None:
    """Deferred heavy import; the first request pays the model download and
    the per-layer split (which AirLLM caches on disk)."""
    global _model
    from airllm import AutoModel  # verify: API of airllm v3.x

    kwargs = {"compression": COMPRESSION} if COMPRESSION else {}
    _model = AutoModel.from_pretrained(MODEL_ID, **kwargs)


def _render_prompt(messages: list[dict], tools: list[dict] | None) -> str:
    msgs: list[dict] = []
    for m in messages:
        role, content = m.get("role", "user"), m.get("content") or ""
        if role == "tool":
            msgs.append(
                {
                    "role": "user",
                    "content": f"[tool result for {m.get('tool_call_id', '?')}]\n{content}",
                }
            )
        elif role == "assistant" and m.get("tool_calls"):
            rendered = [
                {
                    "name": c["function"]["name"],
                    "arguments": c["function"]["arguments"],
                }
                for c in m["tool_calls"]
            ]
            msgs.append(
                {
                    "role": "assistant",
                    "content": f"{content}\n```tool_call\n{json.dumps(rendered)}\n```",
                }
            )
        else:
            msgs.append({"role": role, "content": content})

    if tools:
        schemas = json.dumps([t["function"] for t in tools])
        instr = (
            "\n\nYou can call tools. Available tools as JSON Schemas: "
            f"{schemas}\nTo call exactly one tool, respond with ONLY a fenced"
            " block:\n```tool_call\n{\"name\": \"<tool_name>\","
            " \"arguments\": { ... }}\n```\nOtherwise answer normally."
        )
        if msgs and msgs[0]["role"] == "system":
            msgs[0]["content"] += instr
        else:
            msgs.insert(0, {"role": "system", "content": instr.strip()})

    tokenizer = _model.tokenizer
    try:
        return tokenizer.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True
        )
    except Exception:
        joined = "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in msgs)
        return joined + "\n\nASSISTANT:"


def _generate(prompt: str, max_new: int) -> tuple[str, int, int]:
    import torch

    tokenizer = _model.tokenizer
    enc = tokenizer(
        prompt,
        return_tensors="pt",
        return_attention_mask=False,
        truncation=True,
        max_length=MAX_INPUT_TOKENS,
    )
    ids = enc["input_ids"]
    if torch.cuda.is_available():
        ids = ids.cuda()
    out = _model.generate(
        ids,
        max_new_tokens=max_new,
        use_cache=True,
        return_dict_in_generate=True,
    )
    seq = out.sequences[0]
    new_tokens = seq[ids.shape[1] :]
    text = tokenizer.decode(new_tokens, skip_special_tokens=True)
    return text, int(ids.shape[1]), int(len(new_tokens))


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "model": MODEL_ID, "loaded": _model is not None}


@app.post("/v1/chat/completions")
async def chat_completions(req: dict) -> dict:
    async with _lock:  # single-flight by design
        if _model is None:
            await asyncio.to_thread(_load)
        prompt = _render_prompt(req.get("messages", []), req.get("tools"))
        max_new = min(int(req.get("max_tokens") or MAX_NEW_TOKENS), MAX_NEW_TOKENS)
        text, n_in, n_out = await asyncio.to_thread(_generate, prompt, max_new)

    match = TOOL_CALL_RE.search(text)
    message: dict
    finish = "stop"
    if match:
        try:
            call = json.loads(match.group(1))
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_{uuid.uuid4().hex[:8]}",
                        "type": "function",
                        "function": {
                            "name": call.get("name", ""),
                            "arguments": json.dumps(call.get("arguments", {})),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        except json.JSONDecodeError:
            message = {"role": "assistant", "content": text.strip()}
    else:
        message = {"role": "assistant", "content": text.strip()}

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": MODEL_ID,
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": n_in,
            "completion_tokens": n_out,
            "total_tokens": n_in + n_out,
        },
    }
