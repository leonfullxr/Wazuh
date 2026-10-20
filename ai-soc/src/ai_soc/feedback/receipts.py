"""Stateless, replica portable encrypted feedback receipts."""

from __future__ import annotations

import base64
import re
import secrets
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import AnswerStatus, ErrorCode, FeedbackReceiptPayload


class FeedbackReceiptCodec:
    """AES-GCM codec with domain-separated associated data and key rotation."""

    def __init__(self, keys: dict[str, bytes], current_key_id: str) -> None:
        if current_key_id not in keys or not keys:
            raise ValueError("current receipt key must be present")
        if any(len(key) != 32 for key in keys.values()):
            raise ValueError("feedback receipt keys must be 256-bit AES keys")
        self._keys = dict(keys)
        self._current = current_key_id

    def issue(
        self,
        *,
        question_id: UUID,
        owner_key: str,
        environment_id: str,
        content_sha: str,
        cue_ids: list[str],
        topic_ids: list[str],
        outcome_code: AnswerStatus,
        now: datetime,
        lifetime_seconds: int = 1800,
    ) -> str:
        if lifetime_seconds < 1 or lifetime_seconds > 1800:
            raise ValueError("receipt lifetime must be within 30 minutes")
        payload = FeedbackReceiptPayload(
            receipt_id=uuid4(),
            question_id=question_id,
            owner_key=owner_key,
            environment_id=environment_id,
            content_sha=content_sha,
            cue_ids=cue_ids,
            topic_ids=topic_ids,
            outcome_code=outcome_code,
            issued_at=now,
            expires_at=now.replace(microsecond=0) + timedelta(seconds=lifetime_seconds),
            key_id=self._current,
        )
        nonce = secrets.token_bytes(12)
        aad = b"soc.feedback.v1"
        encrypted = AESGCM(self._keys[self._current]).encrypt(
            nonce, payload.model_dump_json().encode("utf-8"), aad
        )
        return ".".join(
            (
                self._current,
                base64.urlsafe_b64encode(nonce).rstrip(b"=").decode("ascii"),
                base64.urlsafe_b64encode(encrypted).rstrip(b"=").decode("ascii"),
            )
        )

    def open(
        self,
        token: str,
        *,
        question_id: UUID,
        owner_key: str,
        environment_id: str,
        now: datetime,
    ) -> FeedbackReceiptPayload:
        try:
            key_id, encoded_nonce, encoded_ciphertext = token.split(".", 2)
            key = self._keys[key_id]
            nonce = self._decode(encoded_nonce)
            ciphertext = self._decode(encoded_ciphertext)
            if len(nonce) != 12 or len(ciphertext) > 8192:
                raise ValueError("invalid receipt envelope")
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, b"soc.feedback.v1")
            payload = FeedbackReceiptPayload.model_validate_json(plaintext)
            if payload.key_id != key_id:
                raise ValueError("key identifier mismatch")
            if payload.expires_at <= now or payload.issued_at > now:
                raise ValueError("receipt expired or issued in the future")
            if (
                payload.question_id != question_id
                or payload.owner_key != owner_key
                or payload.environment_id != environment_id
            ):
                raise ValueError("receipt binding mismatch")
            return payload
        except (ValueError, KeyError, InvalidTag, UnicodeError):
            raise ServiceFailure(
                public_error(
                    ErrorCode.FEEDBACK_INVALID,
                    "Feedback receipt is invalid or expired.",
                    trace_id=str(uuid4()),
                )
            ) from None

    @staticmethod
    def _decode(value: str) -> bytes:
        if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
            raise ValueError("invalid base64url value")
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4), altchars=b"-_", validate=True
        )
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
            raise ValueError("noncanonical base64url value")
        return decoded
