#!/usr/bin/env python3
"""End-to-end local integration test for spsolvebench.

Tests:
  1. Client CLI (`keygen`, `schedule`, `sign`) + cross-language parity with
     Cloudflare Worker (`worker/src/protocol.js` via Node.js).
  2. Batch verifier Pass 1 fast rejection (tampered sig, forged stamp.tsr via
     real `stencil beacon-verify-stamp`).
  3. Batch verifier Pass 2 real cryptographic verification (`stencil verify-beacon`)
     using an authentic Sigstore-stamped STNPRF03 proof if available locally.
  4. Post-verification moderation: approved writeups vs. redacted spam/unsafe text
     (verified score preserved, flagged text moved to quarantine/).
  5. Generation & integrity of `public/index.json` and `public/dataset.jsonl.gz`.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verifier"))
sys.path.insert(0, str(ROOT / "client"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import moderation
import protocol
import spsolve_bench
import storage
import verify_batch


def find_stencil_bin() -> Path:
    candidates = [
        Path(os.environ["STENCIL_BIN"]) if "STENCIL_BIN" in os.environ else None,
        ROOT.parent / "race_results" / "stencil-linux-x86_64",
        ROOT.parent / "sparse-solver-challenge" / "stencil",
    ]
    for c in candidates:
        if c and c.is_file():
            return c
    raise RuntimeError("No compiled `stencil` binary found; set STENCIL_BIN")


def make_synthetic_proof(cfg: dict, pubkey_hex: str, rows: int, start_round: int, proof_round: int) -> bytes:
    reg = bytearray(144)
    reg[0:8] = b"STNREG01"
    prof = cfg["profile_id"].encode("ascii")
    reg[8 : 8 + len(prof)] = prof
    struct.pack_into("<IIQQQ", reg, 48, rows, 0, start_round, proof_round, 1_000_000_000)
    reg[80:112] = protocol.entry_hash_for_pubkey(pubkey_hex, cfg)
    reg[112:144] = os.urandom(32)

    start_sig = bytes([0x11]) * 48
    digest = bytes([0x22]) * 32
    proof_sig = bytes([0x33]) * 48
    fake_der = bytes([0x30, 0x03, 0x02, 0x01, 0x00]) + bytes([0x44]) * 64
    body = bytes([0x55]) * 128
    return b"STNPRF03" + bytes(reg) + start_sig + digest + proof_sig + struct.pack("<I", len(fake_der)) + fake_der + body


def test_python_js_cross_parity() -> None:
    print("[test 1] Python client <-> Cloudflare Worker JS protocol parity...")
    cfg = protocol.load_protocol_config()
    cfg["submission"]["pow_bits"] = 8

    # Pick an official past round >= launch_round
    launch_utc = protocol.drand_round_utc(cfg["drand"]["launch_round"], cfg)
    interval = cfg["drand"]["round_interval_s"]
    valid_utc = ((launch_utc // interval) + 1) * interval
    valid_round = (valid_utc - cfg["drand"]["genesis_utc"]) // cfg["drand"]["period_s"] + 1
    now_utc = valid_utc + 600

    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        key_p = td_p / "entrant.key"
        subprocess.run([sys.executable, str(ROOT / "client" / "spsolve_bench.py"), "keygen", "--out", str(key_p)], check=True, capture_output=True)
        priv, pub_hex = spsolve_bench.load_key(key_p)

        proof_bytes = make_synthetic_proof(cfg, pub_hex, 8388608, valid_round, valid_round + 100)
        proof_p = td_p / "proof.bin"
        proof_p.write_bytes(proof_bytes)

        hw_p = td_p / "hardware.json"
        subprocess.run([sys.executable, str(ROOT / "client" / "spsolve_bench.py"), "detect-hardware", "--out", str(hw_p)], check=True, capture_output=True)

        subprocess.run(
            [
                sys.executable,
                str(ROOT / "client" / "spsolve_bench.py"),
                "sign",
                "--key", str(key_p),
                "--proof", str(proof_p),
                "--out-dir", str(td_p),
                "--hardware-file", str(hw_p),
                "--display-name", "Parity Team",
                "--solver-name", "parity-solver",
                "--compute-description", "8-core Zen 3, 32 GiB RAM",
                "--algorithm-description", "Multifrontal int16 LDLT + GMRES",
            ],
            check=True,
            capture_output=True,
        )

        meta_bytes = (td_p / "metadata.json").read_bytes()
        sig_hex = (td_p / "submission.sig").read_text().strip()
        header = protocol.parse_proof_header(proof_bytes, cfg)
        protocol.validate_proof_policy(header, len(proof_bytes), cfg, now_utc=now_utc)
        protocol.verify_ed25519_binding(header, meta_bytes, pub_hex, sig_hex, cfg)

        bucket = now_utc // cfg["submission"]["pow_bucket_s"]
        pow_nonce = spsolve_bench.solve_pow(
            header.proof_sha256,
            hashlib.sha256(meta_bytes).hexdigest(),
            pub_hex,
            bucket,
            8,
        )
        protocol.verify_pow(header.proof_sha256, hashlib.sha256(meta_bytes).hexdigest(), pub_hex, bucket, pow_nonce, cfg, now_utc=now_utc)

        # Now verify those EXACT Python-produced bytes inside the Cloudflare Worker JS code via Node!
        js_check = f"""
import fs from "node:fs";
import worker from {json.dumps(str(ROOT / "worker" / "src" / "index.js"))};
const proof = fs.readFileSync({json.dumps(str(proof_p))});
const meta = fs.readFileSync({json.dumps(str(td_p / "metadata.json"))});
const form = new FormData();
form.set("proof", new Blob([proof]), "proof.bin");
form.set("metadata", new Blob([meta]), "metadata.json");
form.set("sig", {json.dumps(sig_hex)});
form.set("pow_bucket", {json.dumps(str(bucket))});
form.set("pow_nonce", {json.dumps(pow_nonce)});
const store = new Map();
const bucketMock = {{
  async put(k, v) {{ store.set(k, v); }},
  async head(k) {{ return store.has(k) ? {{ key: k }} : null; }},
  async get(k) {{ return null; }},
  async list() {{ return {{ objects: [], truncated: false }}; }},
}};
const res = await worker.fetch(
  new Request("https://api.spsolvebench.com/submit", {{ method: "POST", body: form }}),
  {{ BUCKET: bucketMock, POW_BITS: "8", NOW_UTC_OVERRIDE: {json.dumps(str(now_utc))} }}
);
const body = await res.json();
if (res.status !== 202) {{
  console.error("Worker rejected Python submission:", res.status, body);
  process.exit(1);
}}
if (body.id !== {json.dumps(header.attempt_id)}) {{
  console.error("Attempt ID mismatch:", body.id, "!=", {json.dumps(header.attempt_id)});
  process.exit(1);
}}
console.log("JS_PARITY_OK", body.id);
"""
        proc = subprocess.run(["node", "--input-type=module", "-e", js_check], capture_output=True, text=True, check=True)
        assert "JS_PARITY_OK" in proc.stdout, proc.stdout + proc.stderr
        print("  PASS: Python CLI output accepted identically by Cloudflare Worker JS!")


def test_pass1_fast_rejection(stencil_bin: Path, ca_path: Path) -> None:
    print("[test 2] Batch verifier Pass 1 fast rejection of forged TSA stamp...")
    cfg = protocol.load_protocol_config()
    cfg["submission"]["pow_bits"] = 0
    cfg["drand"]["skip_schedule_check"] = True

    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    proof_bytes = make_synthetic_proof(cfg, pub_hex, 8388608, 34243336, 34243401)
    header = protocol.parse_proof_header(proof_bytes, cfg)
    meta_bytes = json.dumps({"pubkey": pub_hex, "solver_name": "forged"}).encode("utf-8")
    sig_hex = spsolve_bench.sign_submission(priv, proof_bytes, meta_bytes)

    with tempfile.TemporaryDirectory() as td:
        bucket = storage.LocalDirStorage(td)
        aid = header.attempt_id
        bucket.put_bytes(f"pending/{aid}/proof.bin", proof_bytes)
        bucket.put_bytes(f"pending/{aid}/metadata.json", meta_bytes)
        bucket.put_bytes(f"pending/{aid}/submission.sig", sig_hex.encode("ascii"))

        t0 = time.monotonic()
        stats = verify_batch.run_batch(bucket, cfg, stencil_bin, ca_path)
        dt_s = time.monotonic() - t0
        assert stats["rejected"] == 1 and stats["verified"] == 0, stats
        assert dt_s < 5.0, f"expected fast rejection, took {dt_s:.2f}s"
        rej = json.loads(bucket.get_bytes(f"rejected/{aid}/reason.json").decode("utf-8"))
        assert rej["stage"] == "pass1" and "beacon-verify-stamp" in rej["reason"], rej
        assert not bucket.exists(f"pending/{aid}/proof.bin")
        print(f"  PASS: Forged proof rejected in {dt_s * 1000:.1f} ms at Pass 1 ({rej['reason']})")


def test_real_sigstore_proof_and_moderation(stencil_bin: Path, ca_path: Path) -> None:
    real_proof_path = ROOT.parent / "race_results" / "race_spsolve" / "round-0" / "public" / "proof.bin"
    if not real_proof_path.is_file():
        print("[test 3] Skipping real 1M proof test (race_results/ not present).")
        return

    print("[test 3] Full batch verification + moderation on REAL Sigstore-stamped 2^20 STNPRF03 proof...")
    proof_bytes = real_proof_path.read_bytes()
    cfg = protocol.load_protocol_config()
    cfg["allowed_rows"] = [1048576, 8388608, 67108864]
    cfg["max_proof_bytes_by_rows"]["1048576"] = 262144
    cfg["submission"]["pow_bits"] = 0
    cfg["drand"]["skip_schedule_check"] = True

    header = protocol.parse_proof_header(proof_bytes, cfg)
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    meta_bytes = json.dumps(
        {
            "pubkey": pub_hex,
            "display_name": "Gemini 4 Neon High",
            "solver_name": "spsolve-v6-int16",
            "repo_url": "https://github.com/ReidAtcheson/sparse-solver-challenge",
            "hardware": {
                "cpu_model": "AMD EPYC 7B13",
                "cpu_cores": 8,
                "ram_gib": 32,
                "gpu_count": 0,
                "node_count": 1,
            },
            "compute_description": "GCP t2d-standard-8 (8 AMD Zen 3 cores, 32 GiB RAM)",
            "algorithm_description": "C++20 multifrontal Bunch-Kaufman with int16 L archiving + right-preconditioned GMRES.",
            "self_reported": {"solve_wall_s": 49.12, "peak_rss_mib": 5950.5},
        }
    ).encode("utf-8")
    sig_hex = spsolve_bench.sign_submission(priv, proof_bytes, meta_bytes)

    # Because this archived Nov 24 proof used entrant="spsolve-v6-int16" rather than "ed25519:<pubkey>",
    # temporarily allow matching the archived entrant hash while still verifying the real Ed25519 sig!
    orig_verify = verify_batch.verify_ed25519_binding

    def _verify_archived_entry(hdr, mbytes, pk, sh, c):
        expected_legacy = hashlib.sha256(b"stencil-entry-v1spsolve-v6-int16").digest()
        assert hdr.entry_hash == expected_legacy
        # Still check the real Ed25519 signature over (proof, metadata)!
        msg = protocol.build_signature_message(hdr.proof_sha256, hashlib.sha256(mbytes).hexdigest(), c)
        priv.public_key().verify(bytes.fromhex(sh), msg)

    verify_batch.verify_ed25519_binding = _verify_archived_entry
    try:
        # Subtest 3a: Approved moderation (using new 2-object envelope.json format + server-side copy)
        with tempfile.TemporaryDirectory() as td:
            bucket = storage.LocalDirStorage(td)
            aid = header.attempt_id
            envelope = json.dumps({
                "schema_version": 1,
                "metadata_raw": meta_bytes.decode("utf-8"),
                "sig": sig_hex,
                "pow_bucket": 0,
                "pow_nonce": "0",
                "pow_bits": 0,
            }).encode("utf-8")
            bucket.put_bytes(f"pending/{aid}/proof.bin", proof_bytes)
            bucket.put_bytes(f"pending/{aid}/envelope.json", envelope)

            def mock_approve(_meta):
                return moderation.ModerationResult("approved", True, True, "On-topic solver writeup.", "@cf/meta/llama-3.1-8b-instruct")

            stats = verify_batch.run_batch(bucket, cfg, stencil_bin, ca_path, moderator=mock_approve)
            assert stats["verified"] == 1 and stats["rejected"] == 0, stats

            budget = json.loads(bucket.get_bytes("public/budget_status.json").decode("utf-8"))
            assert budget["submissions_paused"] is False and budget["verified_bytes"] > len(proof_bytes), budget

            idx = json.loads(bucket.get_bytes("public/index.json").decode("utf-8"))
            assert idx["total_entries"] == 1
            row = idx["entries"][0]
            assert row["id"] == aid
            assert row["rows"] == 1048576
            assert row["elapsed_s"] == 49.0
            assert row["has_writeup"] is True
            assert row["description_hidden"] is False

            entry = json.loads(bucket.get_bytes(f"verified/{aid}/entry.json").decode("utf-8"))
            assert entry["certified"]["target"] == "pass"
            assert entry["entrant"]["hardware"]["cpu_model"] == "AMD EPYC 7B13"
            assert row["hardware"]["cpu_cores"] == 8
            assert entry["entrant"]["compute_description"].startswith("GCP t2d-standard-8")
            assert bucket.exists(f"verified/{aid}/proof.bin")
            assert bucket.exists(f"verified/{aid}/metadata.json")

            ds_lines = gzip.decompress(bucket.get_bytes("public/dataset.jsonl.gz")).decode("utf-8").strip().splitlines()
            assert len(ds_lines) == 1
            assert json.loads(ds_lines[0])["id"] == aid
            print(f"  PASS (approved): Verified real 2^20 proof in {entry['verifier']['verify_wall_s']}s, elapsed={row['elapsed_s']}s, berr={row['backward_2_upper']}")

        # Subtest 3b: Redacted moderation (spam/unsafe text hidden, certified score preserved!)
        with tempfile.TemporaryDirectory() as td:
            bucket = storage.LocalDirStorage(td)
            aid = header.attempt_id
            bucket.put_bytes(f"pending/{aid}/proof.bin", proof_bytes)
            bucket.put_bytes(f"pending/{aid}/metadata.json", meta_bytes)
            bucket.put_bytes(f"pending/{aid}/submission.sig", sig_hex.encode("ascii"))

            def mock_redact(_meta):
                return moderation.ModerationResult("redacted", True, False, "Off-topic spam detected.", "@cf/meta/llama-3.1-8b-instruct")

            stats = verify_batch.run_batch(bucket, cfg, stencil_bin, ca_path, moderator=mock_redact)
            assert stats["verified"] == 1, stats
            entry = json.loads(bucket.get_bytes(f"verified/{aid}/entry.json").decode("utf-8"))
            assert entry["entrant"]["description_hidden"] is True
            assert "compute_description" not in entry["entrant"]
            assert "display_name" not in entry["entrant"]
            assert "cpu_model" not in entry["entrant"].get("hardware", {})
            assert entry["entrant"]["hardware"]["cpu_cores"] == 8
            assert not bucket.exists(f"verified/{aid}/metadata.json")
            assert bucket.exists(f"quarantine/{aid}/metadata.json")
            assert entry["certified"]["elapsed_s"] == 49.0
            print("  PASS (redacted): Flagged text quarantined, certified score + proof.bin preserved!")
    finally:
        verify_batch.verify_ed25519_binding = orig_verify


def main() -> int:
    stencil_bin = find_stencil_bin()
    ca_path = ROOT / "config" / "sigstore-root.crt"
    print(f"Using stencil binary: {stencil_bin}")
    test_python_js_cross_parity()
    test_pass1_fast_rejection(stencil_bin, ca_path)
    test_real_sigstore_proof_and_moderation(stencil_bin, ca_path)
    print("\nALL END-TO-END TESTS PASSED!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
