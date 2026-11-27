/**
 * Pure WebCrypto protocol validator for Cloudflare Workers (and Node 20+/24+).
 * Matches verifier/protocol.py and sparse-solver-challenge's beacon.c / protocol.c byte-for-byte.
 */

const STNPRF03_MAGIC = new Uint8Array([0x53, 0x54, 0x4e, 0x50, 0x52, 0x46, 0x30, 0x33]); // "STNPRF03"
const STNREG01_MAGIC = new Uint8Array([0x53, 0x54, 0x4e, 0x52, 0x45, 0x47, 0x30, 0x31]); // "STNREG01"
const REG_BYTES = 144;
const SIG_BYTES = 48;
const START_BYTES = REG_BYTES + SIG_BYTES; // 192
const PREFIX_FIXED_BYTES = 284;
const MAX_TSA_RESPONSE = 1048576;

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;
const POW_NONCE_RE = /^[0-9A-Za-z._-]{1,64}$/;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export class ValidationError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = "ValidationError";
    this.status = status;
  }
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new ValidationError("invalid hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(...chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export async function sha256Bytes(data) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

export async function sha256Hex(data) {
  return toHex(await sha256Bytes(data));
}

function readU32LE(view, offset) {
  return view.getUint32(offset, true);
}

function readU64LE(view, offset) {
  return view.getBigUint64(offset, true);
}

export function drandRoundUtc(roundNum, cfg) {
  const genesis = BigInt(cfg.drand.genesis_utc);
  const period = BigInt(cfg.drand.period_s);
  return genesis + period * (BigInt(roundNum) - 1n);
}

export function isOfficialStartRound(roundNum, cfg) {
  if (cfg.drand.skip_schedule_check) return BigInt(roundNum) >= 1n;
  if (BigInt(roundNum) < BigInt(cfg.drand.launch_round)) return false;
  const scheduled = drandRoundUtc(roundNum, cfg);
  return scheduled % BigInt(cfg.drand.round_interval_s) === 0n;
}

export async function entryHashForPubkey(pubkeyHex, cfg) {
  const prefix = textEncoder.encode(cfg.domains.stencil_entry);
  const label = textEncoder.encode(`${cfg.domains.entry_prefix}${pubkeyHex}`);
  return sha256Bytes(concatBytes(prefix, label));
}

export async function parseProofHeader(proofBytes, cfg) {
  if (proofBytes.length < PREFIX_FIXED_BYTES + 1) {
    throw new ValidationError("proof.bin too short for STNPRF03 header");
  }
  if (!bytesEqual(proofBytes.subarray(0, 8), STNPRF03_MAGIC)) {
    throw new ValidationError("proof.bin missing STNPRF03 magic");
  }

  const view = new DataView(proofBytes.buffer, proofBytes.byteOffset, proofBytes.byteLength);
  const startBytes = proofBytes.subarray(8, 8 + START_BYTES);
  const regBytes = startBytes.subarray(0, REG_BYTES);
  const digest = proofBytes.subarray(200, 232);
  const derLen = readU32LE(view, 280);

  if (derLen < 1 || derLen > MAX_TSA_RESPONSE) {
    throw new ValidationError(`invalid embedded TSA response length: ${derLen}`);
  }
  if (PREFIX_FIXED_BYTES + derLen >= proofBytes.length) {
    throw new ValidationError("proof.bin truncated inside TSA response or missing algebraic body");
  }

  if (!bytesEqual(regBytes.subarray(0, 8), STNREG01_MAGIC)) {
    throw new ValidationError("registration missing STNREG01 magic");
  }

  const rawProfile = regBytes.subarray(8, 48);
  let nulIdx = rawProfile.indexOf(0);
  if (nulIdx === -1) nulIdx = 40;
  for (let i = nulIdx; i < 40; i++) {
    if (rawProfile[i] !== 0) {
      throw new ValidationError("non-zero padding in profile field");
    }
  }
  let profileId;
  try {
    profileId = textDecoder.decode(rawProfile.subarray(0, nulIdx));
  } catch {
    throw new ValidationError("invalid profile ID encoding");
  }

  const regView = new DataView(regBytes.buffer, regBytes.byteOffset, regBytes.byteLength);
  const rows = readU32LE(regView, 48);
  const reservedZero = readU32LE(regView, 52);
  if (reservedZero !== 0) {
    throw new ValidationError("reserved registration field must be zero");
  }

  const startRound = readU64LE(regView, 56);
  const proofRound = readU64LE(regView, 64);
  const clockErrorNs = readU64LE(regView, 72);
  const entryHash = regBytes.subarray(80, 112);

  const attemptPrefix = textEncoder.encode(cfg.domains.stencil_attempt);
  const attemptId = await sha256Hex(concatBytes(attemptPrefix, startBytes));
  const proofSha256 = await sha256Hex(proofBytes);

  return {
    profileId,
    rows,
    startRound,
    proofRound,
    clockErrorNs,
    entryHash,
    regBytes,
    startBytes,
    digest,
    derLen,
    attemptId,
    proofSha256,
  };
}

export function validateProofPolicy(header, proofLen, cfg, nowUtc = Math.floor(Date.now() / 1000)) {
  if (header.profileId !== cfg.profile_id) {
    throw new ValidationError(`unsupported profile: ${header.profileId}`);
  }
  if (!cfg.allowed_rows.includes(header.rows)) {
    throw new ValidationError(`unsupported row count: ${header.rows}`);
  }
  const maxBytes = Number(cfg.max_proof_bytes_by_rows?.[String(header.rows)] ?? 1048576);
  if (proofLen > maxBytes) {
    throw new ValidationError(`proof.bin exceeds size limit (${proofLen} > ${maxBytes})`, 413);
  }
  if (!isOfficialStartRound(header.startRound, cfg)) {
    throw new ValidationError(`start_round ${header.startRound} is not an official scheduled round`);
  }
  if (header.proofRound <= header.startRound) {
    throw new ValidationError("proof_round must be greater than start_round");
  }

  const nowBig = BigInt(nowUtc);
  const startUtc = drandRoundUtc(header.startRound, cfg);
  const proofUtc = drandRoundUtc(header.proofRound, cfg);
  if (startUtc > nowBig) {
    throw new ValidationError("start_round is in the future");
  }
  if (proofUtc > nowBig) {
    throw new ValidationError("proof_round is in the future");
  }

  const minErr = BigInt(cfg.tsa.min_clock_error_ns);
  if (header.clockErrorNs < minErr) {
    throw new ValidationError(`clock_error_ns must be >= ${minErr}`);
  }
  const windowNs = (proofUtc - startUtc) * 1_000_000_000n;
  if (header.clockErrorNs > (windowNs - 1n) / 2n) {
    throw new ValidationError("clock_error_ns exceeds half of round window");
  }
}

export function validateMetadata(metadataBytes, cfg) {
  const sub = cfg.submission;
  if (metadataBytes.length > sub.max_metadata_bytes) {
    throw new ValidationError("metadata.json exceeds maximum byte size", 413);
  }
  let meta;
  try {
    meta = JSON.parse(textDecoder.decode(metadataBytes));
  } catch {
    throw new ValidationError("invalid UTF-8 or JSON in metadata.json");
  }
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    throw new ValidationError("metadata.json must be a JSON object");
  }

  if (typeof meta.pubkey !== "string" || !HEX64_RE.test(meta.pubkey)) {
    throw new ValidationError("metadata.pubkey must be a 64-char lowercase hex Ed25519 public key");
  }

  for (const field of ["display_name", "solver_name"]) {
    const val = meta[field];
    if (val !== undefined && val !== null) {
      if (typeof val !== "string" || val.length > sub.max_short_field_chars) {
        throw new ValidationError(`metadata.${field} must be a string <= ${sub.max_short_field_chars} chars`);
      }
    }
  }

  if (meta.repo_url !== undefined && meta.repo_url !== null && meta.repo_url !== "") {
    if (typeof meta.repo_url !== "string" || meta.repo_url.length > sub.max_url_chars) {
      throw new ValidationError(`metadata.repo_url must be a string <= ${sub.max_url_chars} chars`);
    }
    let parsed;
    try {
      parsed = new URL(meta.repo_url);
    } catch {
      throw new ValidationError("metadata.repo_url must be a valid URL");
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new ValidationError("metadata.repo_url must use http(s)");
    }
  }

  for (const field of ["compute_description", "algorithm_description"]) {
    const val = meta[field];
    if (val !== undefined && val !== null) {
      if (typeof val !== "string" || textEncoder.encode(val).length > sub.max_description_bytes) {
        throw new ValidationError(`metadata.${field} must be UTF-8 <= ${sub.max_description_bytes} bytes`);
      }
    }
  }

  if (meta.self_reported !== undefined && meta.self_reported !== null) {
    if (typeof meta.self_reported !== "object" || Array.isArray(meta.self_reported)) {
      throw new ValidationError("metadata.self_reported must be an object");
    }
    for (const numField of ["solve_wall_s", "peak_rss_mib"]) {
      const v = meta.self_reported[numField];
      if (v !== undefined && v !== null) {
        if (typeof v !== "number" || !Number.isFinite(v) || v < 0) {
          throw new ValidationError(`metadata.self_reported.${numField} must be a non-negative number`);
        }
      }
    }
  }

  if (meta.hardware !== undefined && meta.hardware !== null) {
    if (typeof meta.hardware !== "object" || Array.isArray(meta.hardware)) {
      throw new ValidationError("metadata.hardware must be an object");
    }
    const hw = meta.hardware;
    const maxModel = Number(sub.max_hardware_model_chars ?? 96);
    for (const strField of ["cpu_model", "gpu_model"]) {
      const v = hw[strField];
      if (v !== undefined && v !== null) {
        if (typeof v !== "string" || v.length > maxModel) {
          throw new ValidationError(`metadata.hardware.${strField} must be a string <= ${maxModel} chars`);
        }
      }
    }
    const intBounds = [
      ["cpu_cores", 1, 1_000_000],
      ["gpu_count", 0, 100_000],
      ["node_count", 1, 100_000],
    ];
    for (const [field, lo, hi] of intBounds) {
      const v = hw[field];
      if (v !== undefined && v !== null) {
        if (!Number.isInteger(v) || v < lo || v > hi) {
          throw new ValidationError(`metadata.hardware.${field} must be an integer in [${lo}, ${hi}]`);
        }
      }
    }
    if (hw.ram_gib !== undefined && hw.ram_gib !== null) {
      if (typeof hw.ram_gib !== "number" || !Number.isFinite(hw.ram_gib) || hw.ram_gib <= 0 || hw.ram_gib > 10_000_000) {
        throw new ValidationError("metadata.hardware.ram_gib must be a number in (0, 10000000]");
      }
    }
  }

  return meta;
}

export function buildSignatureMessage(proofSha256, metadataSha256, cfg) {
  return textEncoder.encode(`${cfg.domains.submit_sig}${proofSha256}\n${metadataSha256}\n`);
}

export async function verifyEd25519Binding(header, metadataBytes, pubkeyHex, sigHex, cfg) {
  if (!HEX64_RE.test(pubkeyHex)) throw new ValidationError("invalid pubkey hex");
  if (!HEX128_RE.test(sigHex)) {
    throw new ValidationError("submission.sig must be 128 lowercase hex chars (64 bytes)");
  }

  const expectedEntry = await entryHashForPubkey(pubkeyHex, cfg);
  if (!bytesEqual(header.entryHash, expectedEntry)) {
    throw new ValidationError(
      "registration ENTRY hash does not match ed25519:<pubkey> (register with entrant `ed25519:<pubkey>`)"
    );
  }

  const metadataSha256 = await sha256Hex(metadataBytes);
  const msg = buildSignatureMessage(header.proofSha256, metadataSha256, cfg);

  let key;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      fromHex(pubkeyHex),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
  } catch {
    throw new ValidationError("invalid Ed25519 public key bytes");
  }

  const ok = await crypto.subtle.verify("Ed25519", key, fromHex(sigHex), msg);
  if (!ok) {
    throw new ValidationError("invalid Ed25519 submission signature");
  }
  return metadataSha256;
}

export function leadingZeroBits(bytes) {
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0) {
      bits += 8;
    } else {
      bits += Math.clz32(b) - 24;
      break;
    }
  }
  return bits;
}

export function buildPowMessage(proofSha256, metadataSha256, pubkeyHex, powBucket, powNonce, cfg) {
  return textEncoder.encode(
    `${cfg.domains.submit_pow}${proofSha256}\n${metadataSha256}\n${pubkeyHex}\n${powBucket}\n${powNonce}`
  );
}

export async function verifyPow(
  proofSha256,
  metadataSha256,
  pubkeyHex,
  powBucket,
  powNonce,
  cfg,
  nowUtc = Math.floor(Date.now() / 1000)
) {
  const bitsReq = Number(cfg.submission.pow_bits);
  if (bitsReq <= 0) return;

  if (!Number.isInteger(powBucket) || powBucket < 0) {
    throw new ValidationError("pow_bucket must be a non-negative integer");
  }
  if (typeof powNonce !== "string" || !POW_NONCE_RE.test(powNonce)) {
    throw new ValidationError("invalid pow_nonce format");
  }

  const bucketS = Number(cfg.submission.pow_bucket_s);
  const skew = Number(cfg.submission.pow_max_bucket_skew);
  const curBucket = Math.floor(nowUtc / bucketS);
  if (powBucket < curBucket - skew || powBucket > curBucket + 1) {
    throw new ValidationError("pow_bucket expired or out of range");
  }

  const digest = await sha256Bytes(
    buildPowMessage(proofSha256, metadataSha256, pubkeyHex, powBucket, powNonce, cfg)
  );
  if (leadingZeroBits(digest) < bitsReq) {
    throw new ValidationError(`insufficient PoW difficulty (need ${bitsReq} leading zero bits)`);
  }
}
