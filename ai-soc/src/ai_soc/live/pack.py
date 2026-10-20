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

from ai_soc.content.builder import verify_content_pack
from ai_soc.content.catalog import ContentCatalog, load_content_catalog
from ai_soc.contracts.models import BuildProvenance, PackManifest
from ai_soc.live.env import optional_endpoint, require_region
from ai_soc.live.sealed import ContentPackLocation


class _StreamingBody(Protocol):
    def read(self) -> bytes: ...


class _S3GetObject(Protocol):
    def __call__(self, *, Bucket: str, Key: str) -> Mapping[str, object]: ...


class _S3Client(Protocol):
    def get_object(self, *, Bucket: str, Key: str) -> Mapping[str, object]: ...


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
    archive_bytes = body.read()
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    if archive_digest != location.pack_sha256:
        raise ValueError("content pack archive digest mismatch")

    pack_dir = root / "pack"
    pack_dir.mkdir()
    archive_path = pack_dir / "content.tar"
    archive_path.write_bytes(archive_bytes)
    (pack_dir / "archive.sha256").write_text(f"{archive_digest}\n", encoding="ascii")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        archive.extractall(pack_dir, filter="data")
    verify_content_pack(pack_dir)
    catalog = load_content_catalog(pack_dir, provenance=provenance)
    return pack_dir, catalog


def _verify_directory_digest(pack_dir: Path, expected: str) -> None:
    manifest = PackManifest.model_validate_json((pack_dir / "manifest.json").read_bytes())
    if manifest.pack_sha256 != expected:
        raise ValueError("content pack manifest digest mismatch")
