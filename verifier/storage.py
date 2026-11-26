"""Bucket storage abstraction supporting Cloudflare R2 (S3 API) and local filesystem.

Includes server-side `copy()` so moving verified `proof.bin` inside R2 incurs
zero GCP internet egress, and `total_bytes()` for the 8 GiB free-tier storage cap.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import Protocol


class BucketStorage(Protocol):
    def list_prefix(self, prefix: str) -> list[str]: ...
    def total_bytes(self, prefix: str = "") -> int: ...
    def exists(self, key: str) -> bool: ...
    def get_bytes(self, key: str) -> bytes: ...
    def put_bytes(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        cache_control: str | None = None,
    ) -> None: ...
    def copy(
        self,
        src_key: str,
        dst_key: str,
        content_type: str = "application/octet-stream",
        cache_control: str | None = None,
    ) -> None: ...
    def delete(self, key: str) -> None: ...


class LocalDirStorage:
    """Filesystem-backed bucket for zero-cloud local development and integration tests."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        rel = key.lstrip("/")
        p = (self.root / rel).resolve()
        if not str(p).startswith(str(self.root)):
            raise ValueError(f"unsafe storage key: {key}")
        return p

    def list_prefix(self, prefix: str) -> list[str]:
        norm = prefix.lstrip("/")
        results: list[str] = []
        for path in self.root.rglob("*"):
            if path.is_file():
                rel = path.relative_to(self.root).as_posix()
                if rel.startswith(norm):
                    results.append(rel)
        results.sort()
        return results

    def total_bytes(self, prefix: str = "") -> int:
        norm = prefix.lstrip("/")
        total = 0
        for path in self.root.rglob("*"):
            if path.is_file():
                rel = path.relative_to(self.root).as_posix()
                if rel.startswith(norm):
                    total += path.stat().st_size
        return total

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def get_bytes(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def put_bytes(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        cache_control: str | None = None,
    ) -> None:
        del content_type, cache_control
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)

    def copy(
        self,
        src_key: str,
        dst_key: str,
        content_type: str = "application/octet-stream",
        cache_control: str | None = None,
    ) -> None:
        del content_type, cache_control
        src = self._path(src_key)
        dst = self._path(dst_key)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    def delete(self, key: str) -> None:
        p = self._path(key)
        if p.exists():
            p.unlink()


class R2S3Storage:
    """Cloudflare R2 storage via S3-compatible boto3 client."""

    def __init__(self, bucket: str, endpoint_url: str, access_key_id: str, secret_access_key: str) -> None:
        import boto3
        from botocore.config import Config

        self.bucket = bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="auto",
            config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
        )

    def list_prefix(self, prefix: str) -> list[str]:
        keys: list[str] = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for item in page.get("Contents", []):
                keys.append(item["Key"])
        keys.sort()
        return keys

    def total_bytes(self, prefix: str = "") -> int:
        total = 0
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for item in page.get("Contents", []):
                total += int(item.get("Size", 0))
        return total

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
                return False
            raise

    def get_bytes(self, key: str) -> bytes:
        resp = self.client.get_object(Bucket=self.bucket, Key=key)
        return resp["Body"].read()

    def put_bytes(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        cache_control: str | None = None,
    ) -> None:
        kwargs = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": data,
            "ContentType": content_type,
        }
        if cache_control:
            kwargs["CacheControl"] = cache_control
        self.client.put_object(**kwargs)

    def copy(
        self,
        src_key: str,
        dst_key: str,
        content_type: str = "application/octet-stream",
        cache_control: str | None = None,
    ) -> None:
        kwargs = {
            "Bucket": self.bucket,
            "CopySource": {"Bucket": self.bucket, "Key": src_key},
            "Key": dst_key,
            "ContentType": content_type,
            "MetadataDirective": "REPLACE",
        }
        if cache_control:
            kwargs["CacheControl"] = cache_control
        self.client.copy_object(**kwargs)

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)


def storage_from_env() -> BucketStorage:
    local_dir = os.environ.get("LOCAL_BUCKET_DIR")
    if local_dir:
        return LocalDirStorage(local_dir)
    return R2S3Storage(
        bucket=os.environ["R2_BUCKET"],
        endpoint_url=os.environ["R2_ENDPOINT"],
        access_key_id=os.environ["R2_ACCESS_KEY_ID"],
        secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
    )
