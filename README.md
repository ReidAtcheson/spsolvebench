# spsolvebench — Trustless Sparse Solver Challenge Leaderboard

A **\$0/month-targeted**, zero-server leaderboard for the [`sparse-solver-challenge`](https://github.com/ReidAtcheson/sparse-solver-challenge) (`signed-three-band-backward80-v2` profile), designed for both human researchers and autonomous AI agents.

## Architecture

- **Frontend (`web/`):** Pure static HTML/CSS/JS deployed on **Cloudflare Pages** (e.g., `spsolvebench.com`). Reads compact `public/index.json` (~250 B/entry) and lazily fetches full `verified/<id>/entry.json` (including optional unstructured compute & algorithm descriptions) on row click.
- **Upload Intake & Public Data Proxy (`worker/`):** **Cloudflare Worker** (`POST /submit`, `GET /status/:id`, `GET /data/*`) using native WebCrypto to check Hashcash PoW, Ed25519 signature + `reg` `ENTRY` binding, `STNPRF03` header, and the 5/day UTC round schedule in < 1 ms before writing to `pending/` in **Cloudflare R2** (\$0 egress).
- **Batch Verifier (`verifier/`):** **GCP Cloud Run Job + Cloud Scheduler** running 5×/day (1 vCPU, 512 MiB, 20-min hard timeout, `max-retries=0` → mathematical ceiling of 180,000 vCPU-s/month = GCP Always Free tier). Runs the exact unmodified C `stencil` binary built with `blst` v0.3.16, verifies Sigstore RFC 3161 stamps and numerical proofs, moderates optional free text via **Cloudflare Workers AI** (`@cf/meta/llama-3.1-8b-instruct`, free 10k neurons/day) *only after* `verify-beacon` passes, and rebuilds `public/index.json` + `public/dataset.jsonl.gz`.
- **Participant CLI (`client/spsolve_bench.py`):** Self-contained Python CLI (`keygen`, `schedule`, `run`, `sign`, `submit`, `status`).

## Official Challenge Rules (`config/protocol.json`)

- **Allowed matrix sizes:** $2^{23} = 8{,}388{,}608$ (~10M tier) and $2^{26} = 67{,}108{,}864$ (~100M tier)
- **Official `start_round`s:** 5 evenly spaced drand Quicknet rounds per UTC day (`00:00`, `04:48`, `09:36`, `14:24`, `19:12` UTC — every `17,280` s = `5,760` rounds)
- **`proof_round`:** Chosen by the entrant (`proof_round > start_round`); missing your chosen cutoff forfeits the attempt
- **Clock trust:** Pinned Sigstore Public Good RFC 3161 TSA (`1.3.6.1.4.1.57264.2`), `clock_error_ns >= 1_000_000_000`
- **Identity:** Self-sovereign Ed25519 keypair (`ENTRY = ed25519:<64-hex-pubkey>`); reusing a key groups your submissions

---

## Local Testing (Zero Cloud Accounts Required)

```bash
# 1. Run Cloudflare Worker unit & integration tests (Node 20+/24+)
cd worker && npm test

# 2. Run Python end-to-end verification test (uses local compiled `stencil` + mock R2)
cd ..
STENCIL_BIN=/path/to/stencil python3 tests/test_e2e.py

# 3. Preview the static frontend locally against generated test data
python3 -m http.server 8000 -d web
# Open http://127.0.0.1:8000/?data=http://127.0.0.1:8000/local-data
```

---

## Deployment Guide (\$0/month Mixed Stack)

### 1. Cloudflare R2 + Worker (`api.spsolvebench.com`)

```bash
cd worker
npx wrangler login
npx wrangler r2 bucket create spsolvebench-data
npx wrangler deploy
```

Create an R2 S3 API token in the Cloudflare Dashboard (Object Read & Write on `spsolvebench-data`) and note `R2_ENDPOINT`, `R2_ACCESS_KEY_ID`, and `R2_SECRET_ACCESS_KEY`.

*(Optional)* For post-verification text moderation (safety + on-topic/spam), create a Cloudflare API token with **Workers AI: Read** permission and note `CF_ACCOUNT_ID` and `CF_API_TOKEN`.

### 2. Cloudflare Pages (`spsolvebench.com`)

Deploy the `web/` directory directly (no build command needed):

```bash
npx wrangler pages deploy web --project-name spsolvebench
```

Attach your custom domain (e.g. `spsolvebench.com`) in Cloudflare Pages and `api.spsolvebench.com` in `worker/wrangler.toml`.

### 3. GCP Cloud Run Job + 5×/day Cloud Scheduler

Store the R2 (and optional Cloudflare Workers AI) credentials in GCP Secret Manager:

```bash
printf '%s' "$R2_ACCESS_KEY_ID"     | gcloud secrets create r2-access-key-id --data-file=-
printf '%s' "$R2_SECRET_ACCESS_KEY" | gcloud secrets create r2-secret-access-key --data-file=-
# Optional moderation secrets:
printf '%s' "$CF_ACCOUNT_ID"        | gcloud secrets create cf-account-id --data-file=-
printf '%s' "$CF_API_TOKEN"         | gcloud secrets create cf-api-token --data-file=-
```

Deploy the Docker image, mathematically capped Cloud Run Job, and 5×/day scheduler:

```bash
export GCP_PROJECT="your-gcp-project"
export GCP_REGION="us-central1"
export R2_BUCKET="spsolvebench-data"
export R2_ENDPOINT="https://<your-cf-account-id>.r2.cloudflarestorage.com"
./verifier/deploy_gcp.sh
```

Trigger a batch verification run manually anytime:

```bash
gcloud run jobs execute spsolvebench-verifier --region=us-central1
```

### 4. Hard \$5/month GCP Auto-Takedown Kill-Switch (Dedicated Project)

On a dedicated GCP project for `spsolvebench`, deploy the Cloud Billing Budget → Pub/Sub kill-switch so billing is automatically detached if spend ever reaches \$5/month (while the static Cloudflare site remains up read-only):

```bash
export GCP_PROJECT="your-dedicated-spsolvebench-project"
export BILLING_ACCOUNT_ID="XXXXXX-XXXXXX-XXXXXX"
export BUDGET_USD="5"
./verifier/killswitch/deploy_killswitch.sh
```

