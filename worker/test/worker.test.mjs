import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import worker from "../src/index.js";
import {
  buildPowMessage,
  buildSignatureMessage,
  concatBytes,
  entryHashForPubkey,
  leadingZeroBits,
  sha256Bytes,
  sha256Hex,
  toHex,
} from "../src/protocol.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cfg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../config/protocol.json"), "utf-8"));

class MockR2Bucket {
  constructor() {
    this.store = new Map();
  }
  async put(key, value, opts = {}) {
    let bytes;
    if (typeof value === "string") {
      bytes = new TextEncoder().encode(value);
    } else if (value instanceof Uint8Array) {
      bytes = new Uint8Array(value);
    } else {
      bytes = new Uint8Array(await new Response(value).arrayBuffer());
    }
    this.store.set(key, { bytes, httpMetadata: opts.httpMetadata || {} });
  }
  async head(key) {
    return this.store.has(key) ? { key, size: this.store.get(key).bytes.length } : null;
  }
  async get(key) {
    const rec = this.store.get(key);
    if (!rec) return null;
    return {
      body: rec.bytes,
      httpMetadata: rec.httpMetadata,
      async text() {
        return new TextDecoder().decode(rec.bytes);
      },
      async arrayBuffer() {
        return rec.bytes.buffer.slice(rec.bytes.byteOffset, rec.bytes.byteOffset + rec.bytes.byteLength);
      },
    };
  }
  async list({ prefix = "" } = {}) {
    const objects = [];
    for (const [key, rec] of this.store.entries()) {
      if (key.startsWith(prefix)) objects.push({ key, size: rec.bytes.length });
    }
    return { objects, truncated: false };
  }
}

async function makeSyntheticProof({ rows = 8388608, startRound = 34250545n, proofRound = 34250600n, clockErrorNs = 1_000_000_000n, pubkeyHex }) {
  const reg = new Uint8Array(144);
  reg.set(new TextEncoder().encode("STNREG01"), 0);
  reg.set(new TextEncoder().encode("signed-three-band-backward80-v2"), 8);
  const view = new DataView(reg.buffer);
  view.setUint32(48, rows, true);
  view.setUint32(52, 0, true);
  view.setBigUint64(56, startRound, true);
  view.setBigUint64(64, proofRound, true);
  view.setBigUint64(72, clockErrorNs, true);
  reg.set(await entryHashForPubkey(pubkeyHex, cfg), 80);
  crypto.getRandomValues(reg.subarray(112, 144));

  const startSig = new Uint8Array(48).fill(0x11);
  const digest = new Uint8Array(32).fill(0x22);
  const proofSig = new Uint8Array(48).fill(0x33);
  const der = new Uint8Array(64).fill(0x44);
  const derLenBuf = new Uint8Array(4);
  new DataView(derLenBuf.buffer).setUint32(0, der.length, true);
  const body = new Uint8Array(128).fill(0x55);

  return concatBytes(
    new TextEncoder().encode("STNPRF03"),
    reg,
    startSig,
    digest,
    proofSig,
    derLenBuf,
    der,
    body
  );
}

async function solvePow(proofSha256, metaSha256, pubkeyHex, bucket, bits) {
  for (let n = 0; n < 200000; n++) {
    const nonce = n.toString(16);
    const h = await sha256Bytes(buildPowMessage(proofSha256, metaSha256, pubkeyHex, bucket, nonce, cfg));
    if (leadingZeroBits(h) >= bits) return nonce;
  }
  throw new Error("PoW not found");
}

async function makeSignedRequest({
  rows = 8388608,
  startRound = 34250545n, // 1692803367 + 3*(34250545-1) = 1795554999? Wait: let's compute exact slot!
  proofRound,
  powBits = 8,
  nowUtc,
  tamperSig = false,
  tamperPow = false,
  metaOverrides = {},
}) {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubBytes = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pubkeyHex = toHex(pubBytes);

  const proofBytes = await makeSyntheticProof({
    rows,
    startRound,
    proofRound: proofRound ?? startRound + 100n,
    pubkeyHex,
  });

  const metadata = {
    pubkey: pubkeyHex,
    display_name: "Test Solver Team",
    solver_name: "mf-int16",
    repo_url: "https://github.com/example/solver",
    hardware: {
      cpu_model: "AMD EPYC 7B13",
      cpu_cores: 8,
      ram_gib: 32,
      gpu_count: 0,
      node_count: 1,
    },
    compute_description: "AMD EPYC 8-core, 32 GiB RAM",
    algorithm_description: "Multifrontal int16 LDLT + GMRES refinement",
    self_reported: { solve_wall_s: 42.1, peak_rss_mib: 5900 },
    ...metaOverrides,
  };
  const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));

  const proofSha = await sha256Hex(proofBytes);
  const metaSha = await sha256Hex(metadataBytes);
  const sigMsg = buildSignatureMessage(proofSha, metaSha, cfg);
  const sigBytes = new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, sigMsg));
  if (tamperSig) sigBytes[0] ^= 0xff;
  const sigHex = toHex(sigBytes);

  const bucket = Math.floor(nowUtc / cfg.submission.pow_bucket_s);
  const nonce = tamperPow ? "bad" : await solvePow(proofSha, metaSha, pubkeyHex, bucket, powBits);

  const form = new FormData();
  form.set("proof", new Blob([proofBytes], { type: "application/octet-stream" }), "proof.bin");
  form.set("metadata", new Blob([metadataBytes], { type: "application/json" }), "metadata.json");
  form.set("sig", sigHex);
  form.set("pow_bucket", String(bucket));
  form.set("pow_nonce", nonce);

  return new Request("https://api.spsolvebench.com/submit", { method: "POST", body: form });
}

// Compute an exact valid 5/day UTC round >= launch_round (34250000)
const launchUtc = BigInt(cfg.drand.genesis_utc) + BigInt(cfg.drand.period_s) * (BigInt(cfg.drand.launch_round) - 1n);
const interval = BigInt(cfg.drand.round_interval_s);
const validUtc = ((launchUtc / interval) + 1n) * interval;
const VALID_START_ROUND = (validUtc - BigInt(cfg.drand.genesis_utc)) / BigInt(cfg.drand.period_s) + 1n;
const NOW_UTC = Number(validUtc + 600n);

test("GET /health returns protocol parameters", async () => {
  const env = { BUCKET: new MockR2Bucket() };
  const res = await worker.fetch(new Request("https://api.spsolvebench.com/health"), env);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.allowed_rows, [8388608, 67108864]);
  assert.equal(body.tsa.policy_oid, "1.3.6.1.4.1.57264.2");
});

test("POST /submit accepts valid signed proof, stores in pending/, serves status, blocks pending/ via /data/", async () => {
  const bucket = new MockR2Bucket();
  const env = { BUCKET: bucket, POW_BITS: "8", NOW_UTC_OVERRIDE: String(NOW_UTC) };

  const req = await makeSignedRequest({ startRound: VALID_START_ROUND, nowUtc: NOW_UTC });
  const res = await worker.fetch(req, env);
  assert.equal(res.status, 202);
  const body = await res.json();
  assert.equal(body.status, "pending");
  assert.equal(body.rows, 8388608);
  assert.match(body.id, /^[0-9a-f]{64}$/);

  // Status endpoint reports pending
  const stRes = await worker.fetch(new Request(`https://api.spsolvebench.com/status/${body.id}`), env);
  assert.equal(stRes.status, 200);
  assert.equal((await stRes.json()).status, "pending");

  // /data/pending/* MUST be forbidden
  const forbidden = await worker.fetch(
    new Request(`https://api.spsolvebench.com/data/pending/${body.id}/proof.bin`),
    env
  );
  assert.equal(forbidden.status, 403);

  // /data/quarantine/* MUST be forbidden
  const forbiddenQ = await worker.fetch(
    new Request(`https://api.spsolvebench.com/data/quarantine/${body.id}/metadata.json`),
    env
  );
  assert.equal(forbiddenQ.status, 403);
});

test("POST /submit rejects bad Ed25519 signature, bad PoW, non-scheduled round, and disallowed rows", async () => {
  const env = { BUCKET: new MockR2Bucket(), POW_BITS: "8", NOW_UTC_OVERRIDE: String(NOW_UTC) };

  const badSig = await worker.fetch(
    await makeSignedRequest({ startRound: VALID_START_ROUND, nowUtc: NOW_UTC, tamperSig: true }),
    env
  );
  assert.equal(badSig.status, 400);
  assert.match((await badSig.json()).error, /Ed25519/i);

  const badPow = await worker.fetch(
    await makeSignedRequest({ startRound: VALID_START_ROUND, nowUtc: NOW_UTC, tamperPow: true }),
    env
  );
  assert.equal(badPow.status, 400);
  assert.match((await badPow.json()).error, /PoW/i);

  const badRound = await worker.fetch(
    await makeSignedRequest({ startRound: VALID_START_ROUND + 1n, nowUtc: NOW_UTC }),
    env
  );
  assert.equal(badRound.status, 400);
  assert.match((await badRound.json()).error, /official scheduled round/i);

  const badRows = await worker.fetch(
    await makeSignedRequest({ rows: 1048576, startRound: VALID_START_ROUND, nowUtc: NOW_UTC }),
    env
  );
  assert.equal(badRows.status, 400);
  assert.match((await badRows.json()).error, /unsupported row count/i);

  const badHw = await worker.fetch(
    await makeSignedRequest({
      startRound: VALID_START_ROUND,
      nowUtc: NOW_UTC,
      metaOverrides: { hardware: { cpu_cores: 0 } },
    }),
    env
  );
  assert.equal(badHw.status, 400);
  assert.match((await badHw.json()).error, /hardware\.cpu_cores/i);
});

test("POST /submit enforces hard pending queue cap and storage budget kill-switch", async () => {
  const bucket = new MockR2Bucket();
  const env = {
    BUCKET: bucket,
    POW_BITS: "6",
    MAX_PENDING_QUEUE: "1",
    DISABLE_ISOLATE_CACHE: "1",
    NOW_UTC_OVERRIDE: String(NOW_UTC),
  };

  const r1 = await worker.fetch(await makeSignedRequest({ startRound: VALID_START_ROUND, nowUtc: NOW_UTC }), env);
  assert.equal(r1.status, 202);

  const r2 = await worker.fetch(await makeSignedRequest({ startRound: VALID_START_ROUND, nowUtc: NOW_UTC }), env);
  assert.equal(r2.status, 429);

  // Trigger storage budget kill-switch -> 503 Service Unavailable
  await bucket.put(
    "public/budget_status.json",
    JSON.stringify({ submissions_paused: true, reason: "R2 8 GiB safety cap reached" })
  );
  const r3 = await worker.fetch(await makeSignedRequest({ startRound: VALID_START_ROUND, nowUtc: NOW_UTC }), env);
  assert.equal(r3.status, 503);
  assert.match((await r3.json()).error, /paused/i);
});
