/**
 * Cloudflare Worker: edge intake, status lookup, and cached public R2 data serving.
 *
 * Billing-hardened for the $0/mo Free tier:
 *   - R2 bucket stays PRIVATE (no public r2.dev); Workers Free hard-stops at 100k req/day.
 *   - Uses Cloudflare Edge Cache (`caches.default`) on GET /data/* to minimize R2 Class B reads.
 *   - Writes only 2 objects per pending submission (`proof.bin` + `envelope.json`) so the
 *     GCP verifier can server-side `copy_object` proof.bin inside R2 with zero GCP egress.
 *   - Enforces hard `max_pending_queue` cap (cached in-isolate) + `public/budget_status.json`
 *     8 GiB storage kill-switch written by the batch verifier.
 */
import defaultProtocol from "../../config/protocol.json" with { type: "json" };
import {
  ValidationError,
  parseProofHeader,
  validateMetadata,
  validateProofPolicy,
  verifyEd25519Binding,
  verifyPow,
} from "./protocol.js";

const HEX64_RE = /^[0-9a-f]{64}$/;

// In-isolate caches (reset cleanly on cold start; bypassable in tests via env)
let cachedPendingCount = { value: 0, expiresAt: 0 };
let cachedBudgetPaused = { paused: false, reason: "", expiresAt: 0 };

function buildConfig(env) {
  const cfg = structuredClone(defaultProtocol);
  if (env?.ALLOWED_ROWS) {
    cfg.allowed_rows = String(env.ALLOWED_ROWS)
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isFinite(n));
  }
  if (env?.POW_BITS !== undefined && env.POW_BITS !== "") {
    cfg.submission.pow_bits = Number(env.POW_BITS);
  }
  if (env?.LAUNCH_ROUND !== undefined && env.LAUNCH_ROUND !== "") {
    cfg.drand.launch_round = Number(env.LAUNCH_ROUND);
  }
  if (env?.MAX_PENDING_QUEUE !== undefined && env.MAX_PENDING_QUEUE !== "") {
    cfg.submission.max_pending_queue = Number(env.MAX_PENDING_QUEUE);
  }
  if (env?.SKIP_SCHEDULE_CHECK === "1" || env?.SKIP_SCHEDULE_CHECK === "true") {
    cfg.drand.skip_schedule_check = true;
  }
  return cfg;
}

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env?.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(data, status = 200, env = {}, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(env),
      ...extraHeaders,
    },
  });
}

async function isBudgetPaused(bucket, env) {
  if (env?.SUBMISSIONS_PAUSED === "1" || env?.SUBMISSIONS_PAUSED === "true") {
    return { paused: true, reason: "Submissions paused by operator kill-switch." };
  }
  const nowMs = Date.now();
  const useCache = !env?.DISABLE_ISOLATE_CACHE;
  if (useCache && nowMs < cachedBudgetPaused.expiresAt) {
    return { paused: cachedBudgetPaused.paused, reason: cachedBudgetPaused.reason };
  }
  try {
    const obj = await bucket.get("public/budget_status.json");
    if (obj) {
      const data = JSON.parse(await obj.text());
      const paused = Boolean(data.submissions_paused);
      const reason = String(data.reason || "Storage safety cap reached.");
      if (useCache) cachedBudgetPaused = { paused, reason, expiresAt: nowMs + 60_000 };
      return { paused, reason };
    }
  } catch {
    // ignore absent/unreadable budget status
  }
  if (useCache) cachedBudgetPaused = { paused: false, reason: "", expiresAt: nowMs + 60_000 };
  return { paused: false, reason: "" };
}

async function countPendingAttempts(bucket, limit, env) {
  const nowMs = Date.now();
  const useCache = !env?.DISABLE_ISOLATE_CACHE;
  if (useCache && nowMs < cachedPendingCount.expiresAt && cachedPendingCount.value >= limit) {
    return cachedPendingCount.value;
  }
  let cursor;
  const ids = new Set();
  do {
    const page = await bucket.list({ prefix: "pending/", cursor, limit: 1000 });
    for (const obj of page.objects) {
      const parts = obj.key.split("/");
      if (parts.length >= 3 && parts[1]) ids.add(parts[1]);
      if (ids.size >= limit) break;
    }
    if (ids.size >= limit) break;
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  if (useCache) {
    cachedPendingCount = { value: ids.size, expiresAt: nowMs + 30_000 };
  }
  return ids.size;
}

async function handleSubmit(request, env, cfg) {
  if (!env?.BUCKET) {
    return jsonResponse({ error: "R2 bucket binding not configured" }, 500, env);
  }

  // 0. Storage / operator kill-switch check
  const pauseState = await isBudgetPaused(env.BUCKET, env);
  if (pauseState.paused) {
    return jsonResponse({ error: `Submissions temporarily paused: ${pauseState.reason}` }, 503, env);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("multipart/form-data")) {
    throw new ValidationError("Content-Type must be multipart/form-data");
  }

  let form;
  try {
    form = await request.formData();
  } catch {
    throw new ValidationError("failed to parse multipart/form-data body");
  }

  const proofField = form.get("proof");
  const metaField = form.get("metadata");
  const sigField = form.get("sig");
  const powBucketRaw = form.get("pow_bucket");
  const powNonceRaw = form.get("pow_nonce");

  if (!proofField || typeof proofField === "string") {
    throw new ValidationError("missing file field `proof`");
  }
  if (!metaField) {
    throw new ValidationError("missing field `metadata`");
  }
  if (typeof sigField !== "string") {
    throw new ValidationError("missing string field `sig`");
  }

  const proofBytes = new Uint8Array(await proofField.arrayBuffer());
  const metadataBytes =
    typeof metaField === "string"
      ? new TextEncoder().encode(metaField)
      : new Uint8Array(await metaField.arrayBuffer());
  const sigHex = sigField.trim().toLowerCase();
  const powBucket = powBucketRaw === null ? 0 : Number(String(powBucketRaw).trim());
  const powNonce = powNonceRaw === null ? "" : String(powNonceRaw).trim();

  // 1. Parse and check metadata + proof header + schedule
  const meta = validateMetadata(metadataBytes, cfg);
  const header = await parseProofHeader(proofBytes, cfg);
  const nowUtc = env?.NOW_UTC_OVERRIDE ? Number(env.NOW_UTC_OVERRIDE) : Math.floor(Date.now() / 1000);
  validateProofPolicy(header, proofBytes.length, cfg, nowUtc);

  // 2. Verify Ed25519 signature & reg ENTRY binding
  const metadataSha256 = await verifyEd25519Binding(header, metadataBytes, meta.pubkey, sigHex, cfg);

  // 3. Verify Hashcash PoW (anti-abuse)
  await verifyPow(header.proofSha256, metadataSha256, meta.pubkey, powBucket, powNonce, cfg, nowUtc);

  // 4. Deduplicate against already verified or pending submissions
  const aid = header.attemptId;
  const existingVerified = await env.BUCKET.head(`verified/${aid}/entry.json`);
  if (existingVerified) {
    return jsonResponse(
      {
        id: aid,
        status: "verified",
        message: "This attempt has already been verified.",
        status_url: `/status/${aid}`,
      },
      200,
      env
    );
  }

  const existingPending =
    (await env.BUCKET.head(`pending/${aid}/envelope.json`)) ||
    (await env.BUCKET.head(`pending/${aid}/metadata.json`));
  if (existingPending) {
    return jsonResponse(
      {
        id: aid,
        status: "pending",
        message: "This attempt is already queued for verification.",
        status_url: `/status/${aid}`,
      },
      202,
      env
    );
  }

  // 5. Hard cap pending queue to protect R2 free tier and verifier budget
  const maxQueue = Number(cfg.submission.max_pending_queue);
  const currentPending = await countPendingAttempts(env.BUCKET, maxQueue, env);
  if (currentPending >= maxQueue) {
    return jsonResponse(
      {
        error: "Verification queue is temporarily full for this round window. Please retry after the next batch run.",
      },
      429,
      env
    );
  }

  // 6. Store only 2 R2 objects: raw proof.bin (for zero-egress server-side copy_object)
  //    + envelope.json (preserves exact UTF-8 metadata text + sig + PoW metadata).
  const envelope = JSON.stringify({
    schema_version: 1,
    metadata_raw: new TextDecoder("utf-8", { fatal: true }).decode(metadataBytes),
    sig: sigHex,
    pow_bucket: powBucket,
    pow_nonce: powNonce,
    pow_bits: cfg.submission.pow_bits,
    received_at: new Date(nowUtc * 1000).toISOString(),
  });

  await Promise.all([
    env.BUCKET.put(`pending/${aid}/proof.bin`, proofBytes, {
      httpMetadata: { contentType: "application/octet-stream" },
    }),
    env.BUCKET.put(`pending/${aid}/envelope.json`, envelope, {
      httpMetadata: { contentType: "application/json" },
    }),
  ]);
  if (!env?.DISABLE_ISOLATE_CACHE) {
    cachedPendingCount = { value: currentPending + 1, expiresAt: Date.now() + 30_000 };
  }

  return jsonResponse(
    {
      id: aid,
      status: "pending",
      rows: header.rows,
      start_round: Number(header.startRound),
      proof_round: Number(header.proofRound),
      status_url: `/status/${aid}`,
    },
    202,
    env
  );
}

async function handleStatus(id, env) {
  if (!HEX64_RE.test(id)) {
    return jsonResponse({ error: "invalid submission ID" }, 400, env);
  }
  const ver = await env.BUCKET.get(`verified/${id}/entry.json`);
  if (ver) {
    const body = await ver.text();
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "public, max-age=60",
        ...corsHeaders(env),
      },
    });
  }
  const rej = await env.BUCKET.get(`rejected/${id}/reason.json`);
  if (rej) {
    const body = await rej.text();
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "public, max-age=60",
        ...corsHeaders(env),
      },
    });
  }
  const pend =
    (await env.BUCKET.head(`pending/${id}/envelope.json`)) ||
    (await env.BUCKET.head(`pending/${id}/metadata.json`));
  if (pend) {
    return jsonResponse(
      {
        id,
        status: "pending",
        message: "Queued for the next scheduled batch verification run.",
      },
      200,
      env
    );
  }
  return jsonResponse({ id, status: "not_found" }, 404, env);
}

async function handlePublicData(request, key, env, ctx) {
  // Strictly allow ONLY public/* and verified/* (never pending/* or quarantine/*)
  if (key.includes("..") || (!key.startsWith("public/") && !key.startsWith("verified/"))) {
    return jsonResponse({ error: "forbidden path" }, 403, env);
  }

  // Edge Cache API: serves repeated downloads without hitting R2 Class B ops
  const edgeCache = typeof caches !== "undefined" && caches?.default ? caches.default : null;
  const cacheKey = edgeCache ? new Request(request.url, { method: "GET" }) : null;
  if (edgeCache && cacheKey) {
    const cached = await edgeCache.match(cacheKey);
    if (cached) return cached;
  }

  const obj = await env.BUCKET.get(key);
  if (!obj) {
    if (key === "public/index.json") {
      return jsonResponse(
        {
          schema_version: 1,
          generated_at: null,
          total_entries: 0,
          tier_counts: {},
          entries: [],
        },
        200,
        env,
        { "Cache-Control": "public, max-age=30" }
      );
    }
    return jsonResponse({ error: "not found" }, 404, env);
  }
  const headers = new Headers(corsHeaders(env));
  if (obj.httpMetadata?.contentType) {
    headers.set("Content-Type", obj.httpMetadata.contentType);
  } else if (key.endsWith(".json")) {
    headers.set("Content-Type", "application/json; charset=utf-8");
  } else if (key.endsWith(".gz")) {
    headers.set("Content-Type", "application/gzip");
  } else {
    headers.set("Content-Type", "application/octet-stream");
  }
  const cacheControl =
    obj.httpMetadata?.cacheControl ||
    (key.startsWith("verified/") && key.endsWith(".bin")
      ? "public, max-age=31536000, immutable"
      : "public, max-age=60");
  headers.set("Cache-Control", cacheControl);

  const response = new Response(obj.body, { status: 200, headers });
  if (edgeCache && cacheKey) {
    const putPromise = edgeCache.put(cacheKey, response.clone());
    if (ctx?.waitUntil) ctx.waitUntil(putPromise);
    else await putPromise;
  }
  return response;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    const url = new URL(request.url);
    const cfg = buildConfig(env);

    try {
      if (request.method === "GET" && (url.pathname === "/health" || url.pathname === "/")) {
        const pauseState = env?.BUCKET ? await isBudgetPaused(env.BUCKET, env) : { paused: false, reason: "" };
        return jsonResponse(
          {
            service: cfg.site_name,
            profile_id: cfg.profile_id,
            allowed_rows: cfg.allowed_rows,
            submissions_paused: pauseState.paused,
            drand: cfg.drand,
            tsa: {
              provider: cfg.tsa.provider,
              policy_oid: cfg.tsa.policy_oid,
              root_der_sha256: cfg.tsa.root_der_sha256,
              min_clock_error_ns: cfg.tsa.min_clock_error_ns,
            },
            submission: {
              pow_bits: cfg.submission.pow_bits,
              pow_bucket_s: cfg.submission.pow_bucket_s,
              max_metadata_bytes: cfg.submission.max_metadata_bytes,
              max_description_bytes: cfg.submission.max_description_bytes,
              max_pending_queue: cfg.submission.max_pending_queue,
            },
          },
          200,
          env,
          { "Cache-Control": "public, max-age=60" }
        );
      }

      if (request.method === "POST" && url.pathname === "/submit") {
        return await handleSubmit(request, env, cfg);
      }

      if (request.method === "GET" && url.pathname.startsWith("/status/")) {
        const id = url.pathname.slice("/status/".length).trim().toLowerCase();
        return await handleStatus(id, env);
      }

      if (request.method === "GET" && url.pathname.startsWith("/data/")) {
        const key = decodeURIComponent(url.pathname.slice("/data/".length));
        return await handlePublicData(request, key, env, ctx);
      }

      return jsonResponse({ error: "not found" }, 404, env);
    } catch (err) {
      if (err instanceof ValidationError) {
        return jsonResponse({ error: err.message }, err.status, env);
      }
      return jsonResponse({ error: "internal server error" }, 500, env);
    }
  },
};
