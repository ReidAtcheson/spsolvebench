"""Batch verifier for spsolvebench (runs 5x/day via Cloud Run Jobs or manually).

Pipeline:
  1. List `pending/` in bucket. Exit immediately if empty (unless --force-rebuild).
  2. Pass 1 (cheap, ~5 ms/item): validate STNPRF03 header, 5/day schedule, metadata
     schema, Ed25519 signature + ENTRY binding, and `stencil beacon-verify-stamp`.
  3. Pass 2 (full verification): run unmodified C `stencil verify-beacon` against
     pinned Sigstore root CA & policy OID.
  4. Pass 3 (moderation, passing proofs only): call Cloudflare Workers AI to check
     safety and on-topic relevance; redact flagged text while preserving the
     certified numerical score.
  5. Rebuild `public/index.json` and `public/dataset.jsonl.gz` if any entries changed.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

from moderation import ModerationResult, moderate_metadata
from protocol import (
    ParsedProofHeader,
    ValidationError,
    drand_round_utc,
    load_protocol_config,
    parse_proof_header,
    validate_metadata,
    validate_proof_policy,
    verify_ed25519_binding,
    verify_pow,
)
from storage import BucketStorage, storage_from_env

KV_RE = re.compile(r"([a-zA-Z0-9_]+)=([^\s]+)")


def default_stencil_bin() -> Path:
    env = os.environ.get("STENCIL_BIN")
    if env:
        return Path(env)
    return Path("/usr/local/bin/stencil")


def default_sigstore_ca() -> Path:
    env = os.environ.get("SIGSTORE_CA")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "config" / "sigstore-root.crt"


def verify_pinned_ca_fingerprint(ca_path: Path, expected_sha256: str) -> None:
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(ca_path), "-outform", "DER"],
        capture_output=True,
        check=True,
    )
    actual = hashlib.sha256(proc.stdout).hexdigest()
    if actual != expected_sha256.lower():
        raise RuntimeError(f"Sigstore root CA fingerprint mismatch: got {actual}, expected {expected_sha256}")


def parse_stencil_kv(stdout: str) -> dict[str, str]:
    return dict(KV_RE.findall(stdout))


def run_stencil_stamp_check(
    stencil_bin: Path,
    ca_path: Path,
    policy_oid: str,
    header: ParsedProofHeader,
) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="spsolve-stamp-") as tmp:
        td = Path(tmp)
        reg_p = td / "reg"
        start_p = td / "start"
        dig_p = td / "digest"
        tsr_p = td / "stamp.tsr"
        reg_p.write_bytes(header.reg_bytes)
        start_p.write_bytes(header.start_bytes)
        dig_p.write_bytes(header.digest)
        tsr_p.write_bytes(header.tsa_der)

        proc = subprocess.run(
            [
                str(stencil_bin),
                "beacon-verify-stamp",
                str(reg_p),
                str(ca_path),
                policy_oid,
                str(start_p),
                str(dig_p),
                str(tsr_p),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
            raise ValidationError(f"beacon-verify-stamp failed: {msg}")
        return parse_stencil_kv(proc.stdout)


def run_stencil_verify_beacon(
    stencil_bin: Path,
    ca_path: Path,
    policy_oid: str,
    header: ParsedProofHeader,
    proof_bytes: bytes,
    timeout_s: int = 900,
) -> tuple[int, dict[str, str], str]:
    with tempfile.TemporaryDirectory(prefix="spsolve-verify-") as tmp:
        td = Path(tmp)
        reg_p = td / "reg"
        dig_p = td / "digest"
        proof_p = td / "proof.bin"
        reg_p.write_bytes(header.reg_bytes)
        dig_p.write_bytes(header.digest)
        proof_p.write_bytes(proof_bytes)

        proc = subprocess.run(
            [
                str(stencil_bin),
                "verify-beacon",
                str(reg_p),
                str(ca_path),
                policy_oid,
                str(dig_p),
                str(proof_p),
            ],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        fields = parse_stencil_kv(proc.stdout)
        combined = (proc.stdout + "\n" + proc.stderr).strip()
        return proc.returncode, fields, combined


def _cleanup_pending(storage: BucketStorage, attempt_id: str) -> None:
    for name in ("proof.bin", "envelope.json", "metadata.json", "submission.sig", "pow.json"):
        storage.delete(f"pending/{attempt_id}/{name}")


def _record_rejection(storage: BucketStorage, attempt_id: str, reason: str, stage: str) -> None:
    payload = {
        "id": attempt_id,
        "status": "rejected",
        "stage": stage,
        "reason": reason,
        "rejected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    storage.put_bytes(
        f"rejected/{attempt_id}/reason.json",
        json.dumps(payload, indent=2).encode("utf-8"),
        content_type="application/json",
    )
    _cleanup_pending(storage, attempt_id)


def list_pending_ids(storage: BucketStorage) -> list[str]:
    keys = storage.list_prefix("pending/")
    ids: set[str] = set()
    for key in keys:
        parts = key.split("/")
        if len(parts) >= 3 and parts[0] == "pending" and parts[1]:
            ids.add(parts[1])
    return sorted(ids)


def pass1_check(
    storage: BucketStorage,
    attempt_id: str,
    cfg: dict[str, Any],
    stencil_bin: Path,
    ca_path: Path,
) -> tuple[ParsedProofHeader, bytes, bytes, dict[str, Any], str]:
    proof_bytes = storage.get_bytes(f"pending/{attempt_id}/proof.bin")
    pow_obj: dict[str, Any] | None = None
    if storage.exists(f"pending/{attempt_id}/envelope.json"):
        env_obj = json.loads(storage.get_bytes(f"pending/{attempt_id}/envelope.json").decode("utf-8"))
        metadata_bytes = str(env_obj["metadata_raw"]).encode("utf-8")
        sig_hex = str(env_obj["sig"]).strip().lower()
        if "pow_bucket" in env_obj and "pow_nonce" in env_obj:
            pow_obj = env_obj
    else:
        metadata_bytes = storage.get_bytes(f"pending/{attempt_id}/metadata.json")
        sig_hex = storage.get_bytes(f"pending/{attempt_id}/submission.sig").decode("ascii").strip().lower()
        if storage.exists(f"pending/{attempt_id}/pow.json"):
            pow_obj = json.loads(storage.get_bytes(f"pending/{attempt_id}/pow.json").decode("utf-8"))

    header = parse_proof_header(proof_bytes, cfg)
    if header.attempt_id != attempt_id:
        raise ValidationError("pending object ID does not match STNPRF03 attempt ID")

    validate_proof_policy(header, len(proof_bytes), cfg)
    meta = validate_metadata(metadata_bytes, cfg)
    verify_ed25519_binding(header, metadata_bytes, meta["pubkey"], sig_hex, cfg)

    # Re-verify PoW difficulty if attached (skip freshness since batch runs later)
    if pow_obj is not None:
        verify_pow(
            header.proof_sha256,
            hashlib.sha256(metadata_bytes).hexdigest(),
            meta["pubkey"],
            int(pow_obj["pow_bucket"]),
            str(pow_obj["pow_nonce"]),
            cfg,
            check_freshness=False,
        )

    # Fast ~5 ms cryptographic check of Quicknet start sig + Sigstore RFC 3161 stamp & window
    run_stencil_stamp_check(stencil_bin, ca_path, cfg["tsa"]["policy_oid"], header)
    return header, proof_bytes, metadata_bytes, meta, sig_hex


def build_entry_record(
    header: ParsedProofHeader,
    proof_len: int,
    metadata_bytes: bytes,
    meta: dict[str, Any],
    sig_hex: str,
    verify_fields: dict[str, str],
    verify_wall_s: float,
    mod: ModerationResult,
    cfg: dict[str, Any],
) -> dict[str, Any]:
    pubkey = meta["pubkey"]
    redacted = mod.status in ("redacted", "error_redacted")
    elapsed_ns = int(verify_fields["elapsed_ns"])
    backward_str = verify_fields.get("backward_2_upper") or verify_fields.get("backward_2") or ""

    public_meta: dict[str, Any] = {
        "pubkey": pubkey,
        "pubkey_short": f"ed25519:{pubkey[:8]}...{pubkey[-6:]}",
        "description_hidden": redacted,
    }
    hw_raw = meta.get("hardware")
    if not redacted:
        for k in ("display_name", "solver_name", "repo_url", "compute_description", "algorithm_description", "self_reported"):
            if meta.get(k) not in (None, ""):
                public_meta[k] = meta[k]
        if isinstance(hw_raw, dict):
            clean_hw = {
                k: hw_raw[k]
                for k in ("cpu_model", "cpu_cores", "ram_gib", "gpu_model", "gpu_count", "node_count")
                if hw_raw.get(k) not in (None, "")
            }
            if clean_hw:
                public_meta["hardware"] = clean_hw
    else:
        if meta.get("self_reported") is not None:
            public_meta["self_reported"] = meta["self_reported"]
        if isinstance(hw_raw, dict):
            # Keep strictly validated numeric hardware specs even if string fields were redacted
            numeric_hw = {
                k: hw_raw[k]
                for k in ("cpu_cores", "ram_gib", "gpu_count", "node_count")
                if hw_raw.get(k) is not None
            }
            if numeric_hw:
                public_meta["hardware"] = numeric_hw

    return {
        "schema_version": 1,
        "id": header.attempt_id,
        "status": "verified",
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profile": verify_fields.get("profile", header.profile_id),
        "rows": int(verify_fields["rows"]),
        "start_round": header.start_round,
        "proof_round": header.proof_round,
        "start_scheduled_utc": drand_round_utc(header.start_round, cfg),
        "proof_scheduled_utc": drand_round_utc(header.proof_round, cfg),
        "clock_error_ns": header.clock_error_ns,
        "certified": {
            "target": verify_fields["target"],
            "elapsed_ns": elapsed_ns,
            "elapsed_s": round(elapsed_ns / 1e9, 6),
            "start_scheduled_ns": int(verify_fields["start_scheduled_ns"]),
            "commitment_utc_ns": int(verify_fields["commitment_utc_ns"]),
            "clock_uncertainty_ns": int(verify_fields["clock_uncertainty_ns"]),
            "backward_2_upper": backward_str,
            "backward_2_upper_num": float(backward_str) if backward_str else None,
            "relative_rhs": verify_fields.get("relative_rhs"),
            "exponent": int(verify_fields["exponent"]) if "exponent" in verify_fields else None,
            "rho": verify_fields.get("rho"),
            "x_squared": verify_fields.get("x_squared"),
            "attempt": verify_fields.get("attempt", header.attempt_id),
        },
        "artifacts": {
            "proof_path": f"verified/{header.attempt_id}/proof.bin",
            "entry_path": f"verified/{header.attempt_id}/entry.json",
            "metadata_path": None if redacted else f"verified/{header.attempt_id}/metadata.json",
            "sig_path": f"verified/{header.attempt_id}/submission.sig",
            "proof_bytes": proof_len,
            "proof_sha256": header.proof_sha256,
            "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
            "winner_digest_hex": header.digest.hex(),
            "reg_hex": header.reg_bytes.hex(),
            "submission_sig": sig_hex,
        },
        "entrant": public_meta,
        "moderation": mod.to_dict(),
        "verifier": {
            "verify_wall_s": round(verify_wall_s, 3),
            "tsa_policy_oid": cfg["tsa"]["policy_oid"],
            "tsa_root_der_sha256": cfg["tsa"]["root_der_sha256"],
        },
    }


def make_index_row(entry: dict[str, Any]) -> dict[str, Any]:
    ent = entry["entrant"]
    cert = entry["certified"]
    sr = ent.get("self_reported") or {}
    hw = ent.get("hardware")
    return {
        "id": entry["id"],
        "rows": entry["rows"],
        "start_round": entry["start_round"],
        "proof_round": entry["proof_round"],
        "start_scheduled_utc": entry["start_scheduled_utc"],
        "elapsed_ns": cert["elapsed_ns"],
        "elapsed_s": cert["elapsed_s"],
        "clock_uncertainty_ns": cert["clock_uncertainty_ns"],
        "backward_2_upper": cert["backward_2_upper"],
        "backward_2_upper_num": cert["backward_2_upper_num"],
        "pubkey": ent["pubkey"],
        "pubkey_short": ent["pubkey_short"],
        "display_name": ent.get("display_name"),
        "solver_name": ent.get("solver_name"),
        "repo_url": ent.get("repo_url"),
        "hardware": hw if isinstance(hw, dict) and hw else None,
        "solve_wall_s": sr.get("solve_wall_s"),
        "peak_rss_mib": sr.get("peak_rss_mib"),
        "has_writeup": bool(ent.get("compute_description") or ent.get("algorithm_description")),
        "description_hidden": bool(ent.get("description_hidden")),
        "proof_bytes": entry["artifacts"]["proof_bytes"],
        "verified_at": entry["verified_at"],
    }


def rebuild_public_indices(storage: BucketStorage, cfg: dict[str, Any]) -> int:
    keys = [k for k in storage.list_prefix("verified/") if k.endswith("/entry.json")]
    entries: list[dict[str, Any]] = []
    for k in keys:
        try:
            entries.append(json.loads(storage.get_bytes(k).decode("utf-8")))
        except Exception as exc:
            print(f"[warn] skipping corrupt {k}: {exc}", file=sys.stderr)

    entries.sort(
        key=lambda e: (
            e["rows"],
            e["certified"]["elapsed_ns"],
            e["certified"]["backward_2_upper_num"] if e["certified"]["backward_2_upper_num"] is not None else 1.0,
            e["id"],
        )
    )

    rows_summary = [make_index_row(e) for e in entries]
    tier_counts: dict[str, int] = {}
    for r in rows_summary:
        tier_counts[str(r["rows"])] = tier_counts.get(str(r["rows"]), 0) + 1

    index_payload = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "site_name": cfg["site_name"],
        "profile_id": cfg["profile_id"],
        "allowed_rows": cfg["allowed_rows"],
        "drand": {
            "chain_hash": cfg["drand"]["chain_hash"],
            "genesis_utc": cfg["drand"]["genesis_utc"],
            "period_s": cfg["drand"]["period_s"],
            "round_interval_s": cfg["drand"]["round_interval_s"],
            "launch_round": cfg["drand"]["launch_round"],
        },
        "tsa": {
            "provider": cfg["tsa"]["provider"],
            "policy_oid": cfg["tsa"]["policy_oid"],
            "root_der_sha256": cfg["tsa"]["root_der_sha256"],
        },
        "total_entries": len(rows_summary),
        "tier_counts": tier_counts,
        "entries": rows_summary,
    }

    storage.put_bytes(
        "public/index.json",
        json.dumps(index_payload, separators=(",", ":")).encode("utf-8"),
        content_type="application/json",
        cache_control="public, max-age=60",
    )

    jsonl_lines = "\n".join(json.dumps(e, separators=(",", ":")) for e in entries)
    if jsonl_lines:
        jsonl_lines += "\n"
    gz_bytes = gzip.compress(jsonl_lines.encode("utf-8"), compresslevel=6)
    storage.put_bytes(
        "public/dataset.jsonl.gz",
        gz_bytes,
        content_type="application/gzip",
        cache_control="public, max-age=300",
    )
    return len(entries)


def run_batch(
    storage: BucketStorage,
    cfg: dict[str, Any],
    stencil_bin: Path,
    ca_path: Path,
    max_items: int = 50,
    max_workers: int = 1,
    force_rebuild: bool = False,
    verify_timeout_s: int = 900,
    moderator=moderate_metadata,
) -> dict[str, int]:
    verify_pinned_ca_fingerprint(ca_path, cfg["tsa"]["root_der_sha256"])

    pending_ids = list_pending_ids(storage)
    stats = {"pending_seen": len(pending_ids), "verified": 0, "rejected": 0, "skipped_duplicate": 0}
    if not pending_ids and not force_rebuild:
        print("[batch] pending/ is empty; exiting cleanly.")
        return stats

    if len(pending_ids) > max_items:
        print(f"[batch] capping run to {max_items} of {len(pending_ids)} pending items.")
        pending_ids = pending_ids[:max_items]

    # Pass 1: fast checks (~5 ms/item) so junk never starves valid proofs
    ready: list[tuple[str, ParsedProofHeader, bytes, bytes, dict[str, Any], str]] = []
    for aid in pending_ids:
        if storage.exists(f"verified/{aid}/entry.json"):
            print(f"[batch] {aid[:12]} already verified; cleaning duplicate pending/")
            _cleanup_pending(storage, aid)
            stats["skipped_duplicate"] += 1
            continue
        try:
            parsed = pass1_check(storage, aid, cfg, stencil_bin, ca_path)
            ready.append((aid, *parsed))
        except Exception as exc:
            print(f"[batch] {aid[:12]} REJECTED in pass1: {exc}")
            _record_rejection(storage, aid, str(exc), stage="pass1")
            stats["rejected"] += 1

    # Pass 2: full `stencil verify-beacon`
    def _verify_one(item):
        aid, header, proof_bytes, metadata_bytes, meta, sig_hex = item
        t0 = time.monotonic()
        rc, fields, combined = run_stencil_verify_beacon(
            stencil_bin, ca_path, cfg["tsa"]["policy_oid"], header, proof_bytes, timeout_s=verify_timeout_s
        )
        dt_s = time.monotonic() - t0
        return aid, header, proof_bytes, metadata_bytes, meta, sig_hex, rc, fields, combined, dt_s

    if ready:
        workers = max(1, min(max_workers, len(ready)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_verify_one, item) for item in ready]
            for fut in as_completed(futs):
                aid, header, proof_bytes, metadata_bytes, meta, sig_hex, rc, fields, combined, dt_s = fut.result()
                if rc != 0:
                    if rc == 3:
                        reason = f"Certified miss: backward_2_upper={fields.get('backward_2_upper', 'unknown')} exceeded 2^-53"
                    else:
                        reason = f"verify-beacon failed (rc={rc}): {combined[:300]}"
                    print(f"[batch] {aid[:12]} REJECTED in pass2 ({dt_s:.2f}s): {reason}")
                    _record_rejection(storage, aid, reason, stage="verify-beacon")
                    stats["rejected"] += 1
                    continue

                if fields.get("target") != "pass" or fields.get("attempt") != aid:
                    reason = "verify-beacon output mismatch on target or attempt ID"
                    print(f"[batch] {aid[:12]} REJECTED in pass2: {reason}")
                    _record_rejection(storage, aid, reason, stage="verify-beacon")
                    stats["rejected"] += 1
                    continue

                # Pass 3: post-verification text moderation (only on real verified solves!)
                mod = moderator(meta)
                entry = build_entry_record(
                    header, len(proof_bytes), metadata_bytes, meta, sig_hex, fields, dt_s, mod, cfg
                )
                redacted = mod.status in ("redacted", "error_redacted")

                # Server-side copy inside R2 avoids re-uploading proof.bin over GCP egress!
                storage.copy(
                    f"pending/{aid}/proof.bin",
                    f"verified/{aid}/proof.bin",
                    content_type="application/octet-stream",
                    cache_control="public, max-age=31536000, immutable",
                )
                storage.put_bytes(
                    f"verified/{aid}/submission.sig",
                    (sig_hex + "\n").encode("ascii"),
                    content_type="text/plain",
                    cache_control="public, max-age=31536000, immutable",
                )
                if redacted:
                    storage.put_bytes(
                        f"quarantine/{aid}/metadata.json",
                        metadata_bytes,
                        content_type="application/json",
                    )
                else:
                    storage.put_bytes(
                        f"verified/{aid}/metadata.json",
                        metadata_bytes,
                        content_type="application/json",
                        cache_control="public, max-age=31536000, immutable",
                    )
                storage.put_bytes(
                    f"verified/{aid}/entry.json",
                    json.dumps(entry, indent=2).encode("utf-8"),
                    content_type="application/json",
                    cache_control="public, max-age=300",
                )
                _cleanup_pending(storage, aid)
                stats["verified"] += 1
                print(
                    f"[batch] {aid[:12]} VERIFIED PASS rows={entry['rows']} "
                    f"elapsed={entry['certified']['elapsed_s']:.3f}s "
                    f"berr={entry['certified']['backward_2_upper']} mod={mod.status} ({dt_s:.2f}s)"
                )

    if stats["verified"] > 0 or force_rebuild:
        total = rebuild_public_indices(storage, cfg)
        print(f"[batch] Published public/index.json and public/dataset.jsonl.gz ({total} total verified entries).")

        # Hard storage kill-switch: pause new intake before reaching R2's 10 GiB free-tier ceiling
        max_verified_bytes = int(os.environ.get("MAX_VERIFIED_BYTES", str(8 * 1024 * 1024 * 1024)))
        used_bytes = storage.total_bytes("verified/")
        paused = used_bytes >= max_verified_bytes
        budget_payload = {
            "submissions_paused": paused,
            "verified_bytes": used_bytes,
            "max_verified_bytes": max_verified_bytes,
            "reason": (
                f"R2 storage safety cap reached ({used_bytes} >= {max_verified_bytes} bytes)"
                if paused
                else ""
            ),
            "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        storage.put_bytes(
            "public/budget_status.json",
            json.dumps(budget_payload, indent=2).encode("utf-8"),
            content_type="application/json",
            cache_control="public, max-age=60",
        )
        if paused:
            print(f"[batch] WARNING: Storage safety cap triggered ({used_bytes} bytes); submissions paused.")

    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description="spsolvebench batch proof verifier")
    ap.add_argument("--config", type=Path, default=None, help="Path to protocol.json")
    ap.add_argument("--stencil", type=Path, default=None, help="Path to stencil binary with blst")
    ap.add_argument("--ca", type=Path, default=None, help="Path to pinned sigstore-root.crt")
    ap.add_argument("--max-items", type=int, default=int(os.environ.get("MAX_ITEMS_PER_RUN", "50")))
    ap.add_argument("--workers", type=int, default=int(os.environ.get("VERIFY_WORKERS", "1")))
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("VERIFY_TIMEOUT_S", "900")))
    ap.add_argument("--force-rebuild", action="store_true", help="Rebuild public/index.json even if pending/ is empty")
    args = ap.parse_args()

    cfg = load_protocol_config(args.config)
    storage = storage_from_env()
    stencil_bin = args.stencil or default_stencil_bin()
    ca_path = args.ca or default_sigstore_ca()

    stats = run_batch(
        storage=storage,
        cfg=cfg,
        stencil_bin=stencil_bin,
        ca_path=ca_path,
        max_items=args.max_items,
        max_workers=args.workers,
        force_rebuild=args.force_rebuild,
        verify_timeout_s=args.timeout,
    )
    print(f"[batch] Done: {json.dumps(stats)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
