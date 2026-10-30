"""Digest-pinned content pack acquisition for live boot."""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import tempfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Protocol, cast
from urllib.parse import urlparse

from ai_soc.content.builder import preflight_ustar, verify_content_pack
from ai_soc.content.catalog import ContentCatalog, load_content_catalog
from ai_soc.contracts.models import BuildProvenance, ConfigBounds, PackManifest
from ai_soc.live.env import optional_endpoint, require_region
from ai_soc.live.sealed import ContentPackLocation


class _StreamingBody(Protocol):
    def read(self, amount: int = -1) -> bytes: ...


class _S3GetObject(Protocol):
    def __call__(self, *, Bucket: str, Key: str) -> Mapping[str, object]: ...


class _S3Client(Protocol):
    def get_object(self, *, Bucket: str, Key: str) -> Mapping[str, object]: ...


def _read_archive(body: _StreamingBody, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        request = min(64 * 1024, limit - total)
        chunk = body.read(request)
        if not chunk:
            break
        if len(chunk) > request:
            raise ValueError("content pack stream exceeded its bounded read")
        total += len(chunk)
        chunks.append(chunk)
    if total >= limit:
        raise ValueError("content pack archive exceeds its byte limit")
    return b"".join(chunks)


def acquire_content_pack(
    location: ContentPackLocation,
    provenance: BuildProvenance,
    *,
    s3_get_object: _S3GetObject | None = None,
    target_root: Path | None = None,
) -> tuple[Path, ContentCatalog]:
    """Materialize a verified pack directory and return it with a loaded catalog."""
    root = target_root or Path(tempfile.mkdtemp(prefix="soc-pack-", dir="/tmp"))
    if location.uri.startswith("file://"):
        pack_dir = Path(urlparse(location.uri).path)
        if not pack_dir.is_dir():
            raise ValueError("file content pack path must be a directory")
        _verify_directory_digest(pack_dir, location.pack_sha256)
        verify_content_pack(pack_dir)
        catalog = load_content_catalog(pack_dir, provenance=provenance)
        return pack_dir, catalog

    if not location.uri.startswith("s3://"):
        raise ValueError("unsupported content pack URI")

    parsed = urlparse(location.uri)
    bucket = parsed.netloc
    key = PurePosixPath(parsed.path).as_posix().lstrip("/")
    if s3_get_object is None:
        import boto3

        s3_kwargs: dict[str, object] = {"region_name": require_region()}
        endpoint = optional_endpoint("SOC_S3_ENDPOINT_URL")
        if endpoint is not None:
            s3_kwargs["endpoint_url"] = endpoint
            s3_kwargs["aws_access_key_id"] = os.environ.get("AWS_ACCESS_KEY_ID", "soclocal")
            s3_kwargs["aws_secret_access_key"] = os.environ.get(
                "AWS_SECRET_ACCESS_KEY", "soclocalsecret"
            )
        client = cast(_S3Client, boto3.client("s3", **s3_kwargs))  # type: ignore[reportUnknownMemberType]
        s3_get_object = client.get_object
    response = s3_get_object(Bucket=bucket, Key=key)
    body = cast(_StreamingBody, response["Body"])
    archive_bytes = _read_archive(body, ConfigBounds().pack_bytes)
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    if archive_digest != location.pack_sha256:
        raise ValueError("content pack archive digest mismatch")

    pack_dir = root / "pack"
    pack_dir.mkdir()
    archive_path = pack_dir / "content.tar"
    archive_path.write_bytes(archive_bytes)
    (pack_dir / "archive.sha256").write_text(f"{archive_digest}\n", encoding="ascii")
    bounds = ConfigBounds()
    preflight_ustar(archive_bytes, bounds)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) > bounds.content_files + 4:
            raise ValueError("content archive has too many members")
        if len({member.name for member in members}) != len(members):
            raise ValueError("content archive has duplicate members")
        total = len(archive_bytes)
        for member in members:
            member_name = member.name.rstrip("/") if member.isdir() else member.name
            path = PurePosixPath(member_name)
            if (
                not (member.isfile() or member.isdir())
                or path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
                or path.as_posix() != member_name
                or member.size < 0
                or member.size > bounds.content_file_bytes
            ):
                raise ValueError("content archive member path, type, or size is invalid")
            total += member.size
        if total > bounds.pack_bytes:
            raise ValueError("content archive extraction exceeds its cumulative byte limit")
        for member in members:
            if member.isdir():
                pack_dir.joinpath(*PurePosixPath(member.name.rstrip("/")).parts).mkdir(
                    parents=True, exist_ok=True
                )
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("content archive member cannot be read")
            payload = extracted.read(bounds.content_file_bytes)
            if len(payload) != member.size or len(payload) > bounds.content_file_bytes:
                raise ValueError("content archive member exceeded its bounded read")
            destination = pack_dir.joinpath(*PurePosixPath(member.name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
    verify_content_pack(pack_dir)
    catalog = load_content_catalog(pack_dir, provenance=provenance)
    return pack_dir, catalog


def _verify_directory_digest(pack_dir: Path, expected: str) -> None:
    path = pack_dir / "manifest.json"
    if path.stat().st_size > ConfigBounds().content_file_bytes:
        raise ValueError("content pack manifest exceeds its read limit")
    with path.open("rb") as stream:
        raw = stream.read(ConfigBounds().content_file_bytes)
    if len(raw) > ConfigBounds().content_file_bytes:
        raise ValueError("content pack manifest exceeded its bounded read")
    manifest = PackManifest.model_validate_json(raw)
    if manifest.pack_sha256 != expected:
        raise ValueError("content pack manifest digest mismatch")
