"""Shared protocol parsing, schedule validation, Ed25519 & Hashcash PoW checks.

Matches worker/src/protocol.js and sparse-solver-challenge's beacon.c / protocol.c
byte-for-byte.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import time
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STNPRF03_MAGIC = b"STNPRF03"
STNREG01_MAGIC = b"STNREG01"
REG_BYTES = 144
SIG_BYTES = 48
START_BYTES = REG_BYTES + SIG_BYTES  # 192
DIGEST_BYTES = 32
PREFIX_FIXED_BYTES = 8 + START_BYTES + DIGEST_BYTES + SIG_BYTES + 4  # 284
MAX_TSA_RESPONSE = 1048576

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
POW_NONCE_RE = re.compile(r"^[0-9A-Za-z._-]{1,64}$")


class ValidationError(ValueError):
    """Raised when a submission violates protocol, cryptographic, or schema rules."""


def default_protocol_path() -> Path:
    return Path(__file__).resolve().parent.parent / "config" / "protocol.json"


def load_protocol_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or Path(os.environ.get("PROTOCOL_CONFIG", default_protocol_path()))
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    # Optional env overrides for local testing or emergency tuning
    if "ALLOWED_ROWS" in os.environ:
        cfg["allowed_rows"] = [int(x) for x in os.environ["ALLOWED_ROWS"].split(",") if x.strip()]
    if "POW_BITS" in os.environ:
        cfg["submission"]["pow_bits"] = int(os.environ["POW_BITS"])
    if "LAUNCH_ROUND" in os.environ:
        cfg["drand"]["launch_round"] = int(os.environ["LAUNCH_ROUND"])
    if "SKIP_SCHEDULE_CHECK" in os.environ:
        cfg["drand"]["skip_schedule_check"] = os.environ["SKIP_SCHEDULE_CHECK"].lower() in ("1", "true", "yes")
    return cfg


def drand_round_utc(round_num: int, cfg: dict[str, Any]) -> int:
    genesis = int(cfg["drand"]["genesis_utc"])
    period = int(cfg["drand"]["period_s"])
    return genesis + period * (round_num - 1)


def utc_to_next_official_rounds(now_utc: int, count: int, cfg: dict[str, Any]) -> list[dict[str, int]]:
    interval = int(cfg["drand"]["round_interval_s"])
    genesis = int(cfg["drand"]["genesis_utc"])
    period = int(cfg["drand"]["period_s"])
    launch_round = int(cfg["drand"]["launch_round"])
    first_slot = ((now_utc // interval) + (1 if now_utc % interval else 0)) * interval
    out: list[dict[str, int]] = []
    slot = first_slot
    while len(out) < count:
        rnd = (slot - genesis) // period + 1
        if rnd >= launch_round and drand_round_utc(rnd, cfg) == slot:
            out.append({"start_round": rnd, "scheduled_utc": slot})
        slot += interval
    return out


def is_official_start_round(round_num: int, cfg: dict[str, Any]) -> bool:
    if cfg["drand"].get("skip_schedule_check"):
        return round_num >= 1
    if round_num < int(cfg["drand"]["launch_round"]):
        return False
    scheduled = drand_round_utc(round_num, cfg)
    return scheduled % int(cfg["drand"]["round_interval_s"]) == 0


def entry_hash_for_pubkey(pubkey_hex: str, cfg: dict[str, Any]) -> bytes:
    label = f"{cfg['domains']['entry_prefix']}{pubkey_hex}".encode("ascii")
    return hashlib.sha256(cfg["domains"]["stencil_entry"].encode("ascii") + label).digest()


def attempt_id_for_start(start_bytes: bytes, cfg: dict[str, Any]) -> str:
    return hashlib.sha256(cfg["domains"]["stencil_attempt"].encode("ascii") + start_bytes).hexdigest()


@dataclass(frozen=True)
class ParsedProofHeader:
    profile_id: str
    rows: int
    start_round: int
    proof_round: int
    clock_error_ns: int
    entry_hash: bytes
    nonce32: bytes
    reg_bytes: bytes
    start_bytes: bytes
    start_sig: bytes
    digest: bytes
    proof_sig: bytes
    tsa_der: bytes
    attempt_id: str
    proof_sha256: str


def parse_proof_header(proof_bytes: bytes, cfg: dict[str, Any]) -> ParsedProofHeader:
    if len(proof_bytes) < PREFIX_FIXED_BYTES + 1:
        raise ValidationError("proof.bin too short for STNPRF03 header")
    if proof_bytes[:8] != STNPRF03_MAGIC:
        raise ValidationError("proof.bin missing STNPRF03 magic")

    start_bytes = proof_bytes[8 : 8 + START_BYTES]
    reg_bytes = start_bytes[:REG_BYTES]
    start_sig = start_bytes[REG_BYTES:]
    digest = proof_bytes[200:232]
    proof_sig = proof_bytes[232:280]
    (der_len,) = struct.unpack("<I", proof_bytes[280:284])

    if der_len < 1 or der_len > MAX_TSA_RESPONSE:
        raise ValidationError(f"invalid embedded TSA response length: {der_len}")
    if PREFIX_FIXED_BYTES + der_len >= len(proof_bytes):
        raise ValidationError("proof.bin truncated inside TSA response or missing algebraic body")
    tsa_der = proof_bytes[284 : 284 + der_len]

    if reg_bytes[:8] != STNREG01_MAGIC:
        raise ValidationError("registration missing STNREG01 magic")

    raw_profile = reg_bytes[8:48]
    profile_id = raw_profile.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    # Ensure trailing padding is strictly zero bytes
    if raw_profile != profile_id.encode("ascii").ljust(40, b"\x00"):
        raise ValidationError("non-zero padding in profile field")

    rows, reserved_zero = struct.unpack("<II", reg_bytes[48:56])
    if reserved_zero != 0:
        raise ValidationError("reserved registration field must be zero")

    start_round, proof_round, clock_error_ns = struct.unpack("<QQQ", reg_bytes[56:80])
    entry_hash = reg_bytes[80:112]
    nonce32 = reg_bytes[112:144]

    return ParsedProofHeader(
        profile_id=profile_id,
        rows=rows,
        start_round=start_round,
        proof_round=proof_round,
        clock_error_ns=clock_error_ns,
        entry_hash=entry_hash,
        nonce32=nonce32,
        reg_bytes=reg_bytes,
        start_bytes=start_bytes,
        start_sig=start_sig,
        digest=digest,
        proof_sig=proof_sig,
        tsa_der=tsa_der,
        attempt_id=attempt_id_for_start(start_bytes, cfg),
        proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
    )


def validate_proof_policy(header: ParsedProofHeader, proof_len: int, cfg: dict[str, Any], now_utc: int | None = None) -> None:
    now = int(time.time()) if now_utc is None else now_utc
    if header.profile_id != cfg["profile_id"]:
        raise ValidationError(f"unsupported profile: {header.profile_id!r}")
    if header.rows not in cfg["allowed_rows"]:
        raise ValidationError(f"unsupported row count: {header.rows}")
    max_bytes_map = cfg.get("max_proof_bytes_by_rows", {})
    max_bytes = int(max_bytes_map.get(str(header.rows), 1048576))
    if proof_len > max_bytes:
        raise ValidationError(f"proof.bin exceeds size limit ({proof_len} > {max_bytes})")

    if not is_official_start_round(header.start_round, cfg):
        raise ValidationError(f"start_round {header.start_round} is not an official scheduled round")
    if header.proof_round <= header.start_round:
        raise ValidationError("proof_round must be greater than start_round")

    start_utc = drand_round_utc(header.start_round, cfg)
    proof_utc = drand_round_utc(header.proof_round, cfg)
    if start_utc > now:
        raise ValidationError("start_round is in the future")
    if proof_utc > now:
        raise ValidationError("proof_round is in the future")

    min_err = int(cfg["tsa"]["min_clock_error_ns"])
    if header.clock_error_ns < min_err:
        raise ValidationError(f"clock_error_ns must be >= {min_err}")
    window_ns = (proof_utc - start_utc) * 1_000_000_000
    if header.clock_error_ns > (window_ns - 1) // 2:
        raise ValidationError("clock_error_ns exceeds half of round window")


def validate_metadata(metadata_bytes: bytes, cfg: dict[str, Any]) -> dict[str, Any]:
    sub_cfg = cfg["submission"]
    if len(metadata_bytes) > int(sub_cfg["max_metadata_bytes"]):
        raise ValidationError("metadata.json exceeds maximum byte size")
    try:
        meta = json.loads(metadata_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValidationError(f"invalid metadata.json: {exc}") from exc
    if not isinstance(meta, dict):
        raise ValidationError("metadata.json must be a JSON object")

    pubkey = meta.get("pubkey")
    if not isinstance(pubkey, str) or not HEX64_RE.match(pubkey):
        raise ValidationError("metadata.pubkey must be a 64-character lowercase hex Ed25519 public key")

    max_short = int(sub_cfg["max_short_field_chars"])
    max_url = int(sub_cfg["max_url_chars"])
    max_desc = int(sub_cfg["max_description_bytes"])

    for field in ("display_name", "solver_name"):
        val = meta.get(field)
        if val is not None:
            if not isinstance(val, str) or len(val) > max_short:
                raise ValidationError(f"metadata.{field} must be a string <= {max_short} chars")

    repo_url = meta.get("repo_url")
    if repo_url is not None and repo_url != "":
        if not isinstance(repo_url, str) or len(repo_url) > max_url:
            raise ValidationError(f"metadata.repo_url must be a string <= {max_url} chars")
        parsed = urlparse(repo_url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise ValidationError("metadata.repo_url must be an http(s) URL")

    for field in ("compute_description", "algorithm_description"):
        val = meta.get(field)
        if val is not None:
            if not isinstance(val, str) or len(val.encode("utf-8")) > max_desc:
                raise ValidationError(f"metadata.{field} must be UTF-8 string <= {max_desc} bytes")

    self_rep = meta.get("self_reported")
    if self_rep is not None:
        if not isinstance(self_rep, dict):
            raise ValidationError("metadata.self_reported must be an object")
        for num_field in ("solve_wall_s", "peak_rss_mib"):
            v = self_rep.get(num_field)
            if v is not None and (not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0):
                raise ValidationError(f"metadata.self_reported.{num_field} must be a non-negative number")

    hw = meta.get("hardware")
    if hw is not None:
        if not isinstance(hw, dict):
            raise ValidationError("metadata.hardware must be an object")
        max_model = int(sub_cfg.get("max_hardware_model_chars", 96))
        for str_field in ("cpu_model", "gpu_model"):
            v = hw.get(str_field)
            if v is not None:
                if not isinstance(v, str) or len(v) > max_model:
                    raise ValidationError(f"metadata.hardware.{str_field} must be a string <= {max_model} chars")
        for int_field, lo, hi in (("cpu_cores", 1, 1_000_000), ("gpu_count", 0, 100_000), ("node_count", 1, 100_000)):
            v = hw.get(int_field)
            if v is not None:
                if not isinstance(v, int) or isinstance(v, bool) or v < lo or v > hi:
                    raise ValidationError(f"metadata.hardware.{int_field} must be an integer in [{lo}, {hi}]")
        ram = hw.get("ram_gib")
        if ram is not None:
            if not isinstance(ram, (int, float)) or isinstance(ram, bool) or ram <= 0 or ram > 10_000_000:
                raise ValidationError("metadata.hardware.ram_gib must be a number in (0, 10000000]")

    return meta


def build_signature_message(proof_sha256: str, metadata_sha256: str, cfg: dict[str, Any]) -> bytes:
    prefix = cfg["domains"]["submit_sig"]
    return f"{prefix}{proof_sha256}\n{metadata_sha256}\n".encode("ascii")


def verify_ed25519_binding(
    header: ParsedProofHeader,
    metadata_bytes: bytes,
    pubkey_hex: str,
    sig_hex: str,
    cfg: dict[str, Any],
) -> None:
    if not HEX64_RE.match(pubkey_hex):
        raise ValidationError("invalid pubkey hex")
    if not HEX128_RE.match(sig_hex):
        raise ValidationError("submission.sig must be 128 lowercase hex chars (64 bytes)")

    expected_entry = entry_hash_for_pubkey(pubkey_hex, cfg)
    if header.entry_hash != expected_entry:
        raise ValidationError(
            "registration ENTRY hash does not match ed25519:<pubkey> (use `ed25519:<pubkey>` as entrant label)"
        )

    metadata_sha256 = hashlib.sha256(metadata_bytes).hexdigest()
    msg = build_signature_message(header.proof_sha256, metadata_sha256, cfg)
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(sig_hex), msg)
    except (ValueError, InvalidSignature) as exc:
        raise ValidationError("invalid Ed25519 submission signature") from exc


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for b in digest:
        if b == 0:
            bits += 8
        else:
            bits += 8 - b.bit_length()
            break
    return bits


def build_pow_message(
    proof_sha256: str,
    metadata_sha256: str,
    pubkey_hex: str,
    pow_bucket: int,
    pow_nonce: str,
    cfg: dict[str, Any],
) -> bytes:
    prefix = cfg["domains"]["submit_pow"]
    return f"{prefix}{proof_sha256}\n{metadata_sha256}\n{pubkey_hex}\n{pow_bucket}\n{pow_nonce}".encode("ascii")


def verify_pow(
    proof_sha256: str,
    metadata_sha256: str,
    pubkey_hex: str,
    pow_bucket: int,
    pow_nonce: str,
    cfg: dict[str, Any],
    now_utc: int | None = None,
    check_freshness: bool = True,
) -> None:
    bits_req = int(cfg["submission"]["pow_bits"])
    if bits_req <= 0:
        return
    if not isinstance(pow_nonce, str) or not POW_NONCE_RE.match(pow_nonce):
        raise ValidationError("invalid pow_nonce format")
    if check_freshness:
        now = int(time.time()) if now_utc is None else now_utc
        bucket_s = int(cfg["submission"]["pow_bucket_s"])
        skew = int(cfg["submission"]["pow_max_bucket_skew"])
        cur_bucket = now // bucket_s
        if pow_bucket < cur_bucket - skew or pow_bucket > cur_bucket + 1:
            raise ValidationError("pow_bucket expired or out of range")
    h = hashlib.sha256(
        build_pow_message(proof_sha256, metadata_sha256, pubkey_hex, pow_bucket, pow_nonce, cfg)
    ).digest()
    if leading_zero_bits(h) < bits_req:
        raise ValidationError(f"insufficient PoW difficulty (need {bits_req} leading zero bits)")
