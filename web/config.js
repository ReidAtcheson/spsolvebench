/**
 * Runtime configuration for spsolvebench Cloudflare Pages frontend.
 *
 * When running locally (localhost / 127.0.0.1), defaults to reading static data
 * from `./local-data` (or override via `?data=...&api=...` query params).
 * In production, point API_BASE to your deployed Cloudflare Worker
 * (e.g. "https://api.spsolvebench.com").
 */
const params = new URLSearchParams(window.location.search);
const isLocal =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1" ||
  window.location.protocol === "file:";

const DEFAULT_API = isLocal
  ? "http://127.0.0.1:8787"
  : "https://api.spsolvebench.com";
const DEFAULT_DATA = isLocal ? "./local-data" : `${DEFAULT_API}/data`;

window.SPSOLVE_CONFIG = {
  SITE_NAME: "spsolvebench",
  SITE_TAGLINE: "Trustless Sparse Linear Solver Leaderboard",
  API_BASE: (params.get("api") || DEFAULT_API).replace(/\/+$/, ""),
  DATA_BASE: (params.get("data") || DEFAULT_DATA).replace(/\/+$/, ""),
  // Protocol constants matching config/protocol.json
  PROFILE_ID: "signed-three-band-backward80-v2",
  ALLOWED_ROWS: [8388608, 67108864],
  DRAND_CHAIN_HASH: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  DRAND_GENESIS_UTC: 1692803367,
  DRAND_PERIOD_S: 3,
  ROUND_INTERVAL_S: 17280,
  LAUNCH_ROUND: 34250000,
  TSA_POLICY_OID: "1.3.6.1.4.1.57264.2",
  TSA_ROOT_SHA256: "2aca8fea5d3ce48b01cc77076293c280e6c23ffe44034757ee7833ca9f45d633",
  POW_BITS: 22,
  POW_BUCKET_S: 600,
};
