#!/usr/bin/env python3
"""Self-contained CLI for spsolvebench entrants and autonomous AI agents.

Commands:
  keygen    Generate an Ed25519 identity keypair (reusing it groups your submissions)
  schedule  Show upcoming official 5/day UTC drand Quicknet start rounds
  run       Wait for an official round, run your solver, stamp via Sigstore, and prove
  sign      Create signed metadata.json + submission.sig locally (for CLI or web upload)
  submit    Sign, solve anti-abuse Hashcash PoW, and POST proof.bin to /submit
  status    Query verification status for a submission ID

Dependencies: Python 3.10+ stdlib + `cryptography` (for Ed25519 signing).
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

DEFAULT_API = "https://spsolvebench-api.reidatcheson.workers.dev"
CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
GENESIS_UTC = 1692803367
PERIOD_S = 3
ROUND_INTERVAL_S = 17280  # 5 evenly spaced rounds/day (00:00, 04:48, 09:36, 14:24, 19:12 UTC)
DEFAULT_LAUNCH_ROUND = 34250000
DEFAULT_POW_BITS = 22
DEFAULT_POW_BUCKET_S = 600
RELAYS = [
    f"https://api.drand.sh/{CHAIN_HASH}/public",
    f"https://drand.cloudflare.com/{CHAIN_HASH}/public",
    f"https://api2.drand.sh/{CHAIN_HASH}/public",
]


def round_utc(rnd: int) -> int:
    return GENESIS_UTC + PERIOD_S * (rnd - 1)


def utc_to_round_ceil(ts: int) -> int:
    if ts <= GENESIS_UTC:
        return 1
    delta = ts - GENESIS_UTC
    return (delta + PERIOD_S - 1) // PERIOD_S + 1


def upcoming_official_rounds(now_utc: int, count: int, launch_round: int = DEFAULT_LAUNCH_ROUND) -> list[dict[str, int]]:
    first_slot = ((now_utc // ROUND_INTERVAL_S) + 1) * ROUND_INTERVAL_S
    out: list[dict[str, int]] = []
    slot = first_slot
    while len(out) < count:
        rnd = (slot - GENESIS_UTC) // PERIOD_S + 1
        if rnd >= launch_round and round_utc(rnd) == slot:
            out.append({"start_round": rnd, "scheduled_utc": slot})
        slot += ROUND_INTERVAL_S
    return out


def load_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    priv_bytes = bytes.fromhex(obj["private_key_hex"])
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, pub_hex


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for b in digest:
        if b == 0:
            bits += 8
        else:
            bits += 8 - b.bit_length()
            break
    return bits


def solve_pow(proof_sha256: str, meta_sha256: str, pubkey_hex: str, pow_bucket: int, pow_bits: int) -> str:
    if pow_bits <= 0:
        return "0"
    prefix = f"spsolve-submit-pow-v1\n{proof_sha256}\n{meta_sha256}\n{pubkey_hex}\n{pow_bucket}\n".encode("ascii")
    t0 = time.monotonic()
    n = 0
    while True:
        nonce = f"{n:x}"
        h = hashlib.sha256(prefix + nonce.encode("ascii")).digest()
        if leading_zero_bits(h) >= pow_bits:
            dt_s = time.monotonic() - t0
            print(f"[pow] Solved {pow_bits}-bit PoW in {dt_s:.2f}s ({n + 1} hashes, nonce={nonce})", file=sys.stderr)
            return nonce
        n += 1


def sign_submission(priv: Ed25519PrivateKey, proof_bytes: bytes, metadata_bytes: bytes) -> str:
    proof_sha = hashlib.sha256(proof_bytes).hexdigest()
    meta_sha = hashlib.sha256(metadata_bytes).hexdigest()
    msg = f"spsolve-leaderboard-submit-v1\n{proof_sha}\n{meta_sha}\n".encode("ascii")
    return priv.sign(msg).hex()


def build_metadata(args: argparse.Namespace, pubkey_hex: str) -> bytes:
    meta: dict[str, Any] = {"pubkey": pubkey_hex}
    if getattr(args, "display_name", None):
        meta["display_name"] = args.display_name
    if getattr(args, "solver_name", None):
        meta["solver_name"] = args.solver_name
    if getattr(args, "repo_url", None):
        meta["repo_url"] = args.repo_url

    compute_desc = getattr(args, "compute_description", None)
    if getattr(args, "compute_file", None):
        compute_desc = Path(args.compute_file).read_text(encoding="utf-8")
    if compute_desc:
        meta["compute_description"] = compute_desc

    algo_desc = getattr(args, "algorithm_description", None)
    if getattr(args, "algorithm_file", None):
        algo_desc = Path(args.algorithm_file).read_text(encoding="utf-8")
    if algo_desc:
        meta["algorithm_description"] = algo_desc

    sr: dict[str, float] = {}
    if getattr(args, "solve_wall_s", None) is not None:
        sr["solve_wall_s"] = args.solve_wall_s
    if getattr(args, "peak_rss_mib", None) is not None:
        sr["peak_rss_mib"] = args.peak_rss_mib
    if sr:
        meta["self_reported"] = sr

    return json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8")


def encode_multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]) -> tuple[bytes, str]:
    boundary = f"----spsolvebench-{uuid.uuid4().hex}"
    parts: list[bytes] = []
    for k, v in fields.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode("utf-8")
        )
    for k, (fname, data, ctype) in files.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fname}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n".encode("utf-8")
        )
        parts.append(data)
        parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _fetch_drand_one(url: str, rnd: int, timeout: float) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "spsolvebench-client/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if int(data.get("round", -1)) == rnd and "signature" in data:
                sig = bytes.fromhex(data["signature"])
                if len(sig) == 48:
                    return sig
    except Exception:
        return None
    return None


def fetch_drand_sig(rnd: int, deadline_utc: float) -> bytes:
    target = round_utc(rnd)
    now = time.time()
    if target + 0.05 > now:
        wait_s = target + 0.05 - now
        print(f"[drand] Sleeping {wait_s:.1f}s until round {rnd} ({dt.datetime.fromtimestamp(target, dt.timezone.utc).isoformat()})", file=sys.stderr)
        time.sleep(wait_s)
    while time.time() < deadline_utc:
        ex = ThreadPoolExecutor(max_workers=len(RELAYS))
        futs = [ex.submit(_fetch_drand_one, f"{base}/{rnd}", rnd, 2.0) for base in RELAYS]
        for f in as_completed(futs):
            sig = f.result()
            if sig is not None:
                ex.shutdown(wait=False, cancel_futures=True)
                return sig
        ex.shutdown(wait=False, cancel_futures=True)
        time.sleep(0.15)
    raise RuntimeError(f"Timed out fetching drand round {rnd}")


def cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"Refusing to overwrite existing key {out} (pass --force to overwrite)", file=sys.stderr)
        return 1
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    payload = {
        "private_key_hex": priv_hex,
        "public_key_hex": pub_hex,
        "entrant": f"ed25519:{pub_hex}",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(out, 0o600)
    print(f"Saved Ed25519 key to {out}")
    print(f"Entrant ID (for stencil beacon-register): ed25519:{pub_hex}")
    return 0


def cmd_schedule(args: argparse.Namespace) -> int:
    now = int(time.time())
    rounds = upcoming_official_rounds(now, args.count)
    print("Upcoming official spsolvebench start rounds (5/day UTC):")
    for item in rounds:
        ts = item["scheduled_utc"]
        utc_str = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        delta = ts - now
        hrs, rem = divmod(delta, 3600)
        mins, secs = divmod(rem, 60)
        print(f"  round {item['start_round']}  |  {utc_str}  |  in {hrs:02d}h {mins:02d}m {secs:02d}s")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    priv, pub_hex = load_key(Path(args.key))
    proof_bytes = Path(args.proof).read_bytes()
    meta_bytes = build_metadata(args, pub_hex)
    sig_hex = sign_submission(priv, proof_bytes, meta_bytes)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metadata.json").write_bytes(meta_bytes)
    (out_dir / "submission.sig").write_text(sig_hex + "\n", encoding="ascii")
    print(f"Wrote {out_dir / 'metadata.json'} and {out_dir / 'submission.sig'}")
    print(f"pubkey: {pub_hex}")
    print(f"sig:    {sig_hex}")
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    priv, pub_hex = load_key(Path(args.key))
    proof_bytes = Path(args.proof).read_bytes()
    meta_bytes = Path(args.metadata_file).read_bytes() if args.metadata_file else build_metadata(args, pub_hex)
    sig_hex = sign_submission(priv, proof_bytes, meta_bytes)

    api = args.api.rstrip("/")
    pow_bits = args.pow_bits
    pow_bucket_s = DEFAULT_POW_BUCKET_S
    if pow_bits is None:
        try:
            with urllib.request.urlopen(f"{api}/health", timeout=10) as resp:
                health = json.loads(resp.read().decode("utf-8"))
                pow_bits = int(health.get("submission", {}).get("pow_bits", DEFAULT_POW_BITS))
                pow_bucket_s = int(health.get("submission", {}).get("pow_bucket_s", DEFAULT_POW_BUCKET_S))
        except Exception as exc:
            print(f"[warn] could not query {api}/health ({exc}); defaulting to pow_bits={DEFAULT_POW_BITS}", file=sys.stderr)
            pow_bits = DEFAULT_POW_BITS

    proof_sha = hashlib.sha256(proof_bytes).hexdigest()
    meta_sha = hashlib.sha256(meta_bytes).hexdigest()
    pow_bucket = int(time.time()) // pow_bucket_s
    pow_nonce = solve_pow(proof_sha, meta_sha, pub_hex, pow_bucket, pow_bits)

    body, content_type = encode_multipart(
        fields={
            "sig": sig_hex,
            "pow_bucket": str(pow_bucket),
            "pow_nonce": pow_nonce,
        },
        files={
            "proof": ("proof.bin", proof_bytes, "application/octet-stream"),
            "metadata": ("metadata.json", meta_bytes, "application/json"),
        },
    )

    req = urllib.request.Request(
        f"{api}/submit",
        data=body,
        headers={
            "Content-Type": content_type,
            "User-Agent": "spsolvebench-client/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode("utf-8")
            print(text)
            return 0
    except urllib.error.HTTPError as err:
        print(f"HTTP {err.code}: {err.read().decode('utf-8', errors='replace')}", file=sys.stderr)
        return 1


def cmd_status(args: argparse.Namespace) -> int:
    api = args.api.rstrip("/")
    url = f"{api}/status/{args.id.strip().lower()}"
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            print(resp.read().decode("utf-8"))
            return 0
    except urllib.error.HTTPError as err:
        print(f"HTTP {err.code}: {err.read().decode('utf-8', errors='replace')}", file=sys.stderr)
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    _, pub_hex = load_key(Path(args.key))
    entrant = f"ed25519:{pub_hex}"
    sc_dir = Path(args.stencil_dir).resolve()
    stencil = sc_dir / "stencil"
    pub_tsa = sc_dir / "examples" / "public-tsa"
    if not stencil.exists():
        print(f"stencil binary not found at {stencil}", file=sys.stderr)
        return 1

    ca = Path(subprocess.check_output([str(pub_tsa), "sigstore", "root"], text=True).strip())
    policy = subprocess.check_output([str(pub_tsa), "sigstore", "policy"], text=True).strip()

    now = int(time.time())
    if args.start_round:
        sr = args.start_round
    else:
        sr = upcoming_official_rounds(now, 1)[0]["start_round"]
    pr = args.proof_round if args.proof_round else sr + max(10, int(args.proof_window_s // PERIOD_S))

    work = Path(args.work_dir).resolve()
    priv_dir = work / "private"
    pub_dir = work / "public"
    priv_dir.mkdir(parents=True, exist_ok=True)
    pub_dir.mkdir(parents=True, exist_ok=True)

    nonce_p = priv_dir / "nonce32"
    nonce_p.write_bytes(secrets.token_bytes(32))
    reg_p = priv_dir / "reg"

    subprocess.run(
        [
            str(stencil),
            "beacon-register",
            str(args.rows),
            entrant,
            str(nonce_p),
            str(sr),
            str(pr),
            str(args.clock_error_ns),
            str(reg_p),
        ],
        check=True,
    )
    print(f"[run] Registered rows={args.rows} start_round={sr} proof_round={pr} entrant={entrant}", file=sys.stderr)

    start_sig = fetch_drand_sig(sr, max(round_utc(sr) + 60, round_utc(pr) - 10))
    (priv_dir / "start.sig").write_bytes(start_sig)
    subprocess.run([str(stencil), "beacon-start", str(reg_p), str(priv_dir / "start.sig"), str(priv_dir / "start")], check=True)

    # Run user solver: receives (reg, start, x.f64) or (reg, start, x.f64, rows, digest) if --solver-commits
    t_solve0 = time.monotonic()
    solver_cmd = list(args.solver_cmd)
    if args.solver_commits:
        cmd = [*solver_cmd, str(reg_p), str(priv_dir / "start"), str(priv_dir / "x.f64"), str(priv_dir / "rows"), str(priv_dir / "digest")]
    else:
        cmd = [*solver_cmd, str(reg_p), str(priv_dir / "start"), str(priv_dir / "x.f64")]
    subprocess.run(cmd, check=True)
    solve_wall_s = time.monotonic() - t_solve0
    print(f"[run] Solver finished in {solve_wall_s:.2f}s", file=sys.stderr)

    if not args.solver_commits:
        subprocess.run(
            [str(stencil), "commit", str(reg_p), str(priv_dir / "start"), str(priv_dir / "x.f64"), str(priv_dir / "rows"), str(priv_dir / "digest")],
            check=True,
        )

    # Timestamp commitment via Sigstore Public Good
    stamp_p = priv_dir / "stamp.tsr"
    subprocess.run(
        [str(pub_tsa), "sigstore", "stamp-commit", str(reg_p), str(priv_dir / "start"), str(priv_dir / "digest"), str(stamp_p)],
        check=True,
    )
    print("[run] Obtained verified Sigstore RFC 3161 stamp.", file=sys.stderr)

    proof_sig = fetch_drand_sig(pr, round_utc(pr) + 180)
    (priv_dir / "proof.sig").write_bytes(proof_sig)

    proof_out = pub_dir / "proof.bin"
    subprocess.run(
        [
            str(stencil),
            "prove-beacon",
            str(reg_p),
            str(ca),
            policy,
            str(priv_dir / "start"),
            str(priv_dir / "digest"),
            str(stamp_p),
            str(priv_dir / "proof.sig"),
            str(priv_dir / "x.f64"),
            str(priv_dir / "rows"),
            str(proof_out),
        ],
        check=True,
    )

    # Local offline self-verification before submitting
    shutil.copyfile(reg_p, pub_dir / "reg")
    shutil.copyfile(priv_dir / "digest", pub_dir / "winner.digest")
    ver = subprocess.run(
        [str(stencil), "verify-beacon", str(pub_dir / "reg"), str(ca), policy, str(pub_dir / "winner.digest"), str(proof_out)],
        capture_output=True,
        text=True,
    )
    print(ver.stdout.strip())
    if ver.returncode != 0:
        print(ver.stderr.strip(), file=sys.stderr)
        return ver.returncode

    print(f"[run] Proof verified locally: {proof_out} (solve_wall_s={solve_wall_s:.2f}s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="spsolvebench participant CLI")
    sub = ap.add_subparsers(dest="command", required=True)

    p_kg = sub.add_parser("keygen", help="Generate an Ed25519 entrant keypair")
    p_kg.add_argument("--out", default="spsolve-key.json")
    p_kg.add_argument("--force", action="store_true")
    p_kg.set_defaults(func=cmd_keygen)

    p_sc = sub.add_parser("schedule", help="Show upcoming official 5/day UTC start rounds")
    p_sc.add_argument("--count", type=int, default=5)
    p_sc.set_defaults(func=cmd_schedule)

    for name, fn, help_str in [
        ("sign", cmd_sign, "Write signed metadata.json and submission.sig locally"),
        ("submit", cmd_submit, "Sign, compute Hashcash PoW, and POST proof.bin to /submit"),
    ]:
        p = sub.add_parser(name, help=help_str)
        p.add_argument("--key", required=True, help="Path to Ed25519 key JSON from keygen")
        p.add_argument("--proof", required=True, help="Path to STNPRF03 proof.bin")
        p.add_argument("--display-name", default=None)
        p.add_argument("--solver-name", default=None)
        p.add_argument("--repo-url", default=None)
        p.add_argument("--compute-description", default=None)
        p.add_argument("--compute-file", default=None)
        p.add_argument("--algorithm-description", default=None)
        p.add_argument("--algorithm-file", default=None)
        p.add_argument("--solve-wall-s", type=float, default=None)
        p.add_argument("--peak-rss-mib", type=float, default=None)
        if name == "sign":
            p.add_argument("--out-dir", default=".")
        else:
            p.add_argument("--metadata-file", default=None, help="Use an existing metadata.json verbatim")
            p.add_argument("--api", default=DEFAULT_API)
            p.add_argument("--pow-bits", type=int, default=None, help="Override PoW difficulty (default fetched from /health)")
        p.set_defaults(func=fn)

    p_st = sub.add_parser("status", help="Check submission status by attempt ID")
    p_st.add_argument("--id", required=True)
    p_st.add_argument("--api", default=DEFAULT_API)
    p_st.set_defaults(func=cmd_status)

    p_run = sub.add_parser("run", help="Wait for an official round, run solver, stamp via Sigstore, and prove")
    p_run.add_argument("--key", required=True)
    p_run.add_argument("--stencil-dir", required=True, help="Path to built sparse-solver-challenge repo")
    p_run.add_argument("--work-dir", required=True)
    p_run.add_argument("--rows", type=int, required=True, choices=[8388608, 67108864])
    p_run.add_argument("--start-round", type=int, default=None, help="Specific official start_round (default: next upcoming)")
    p_run.add_argument("--proof-round", type=int, default=None, help="Explicit proof_round (default: start_round + proof_window_s/3)")
    p_run.add_argument("--proof-window-s", type=int, default=3600, help="Commit window in seconds if --proof-round omitted (default: 3600)")
    p_run.add_argument("--clock-error-ns", type=int, default=1_000_000_000)
    p_run.add_argument("--solver-commits", action="store_true", help="Pass rows & digest output paths to solver so it commits in-memory")
    p_run.add_argument("--solver-cmd", nargs="+", required=True, help="Solver command prefix")
    p_run.set_defaults(func=cmd_run)

    return ap


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
