#!/usr/bin/env bash
# Deploy the $0/month mathematically capped Cloud Run Job + 5x/day Cloud Scheduler.
#
# Cost ceiling math:
#   5 runs/day * 30 days = 150 runs/month
#   1 vCPU * 1200s (20m) hard timeout * max-retries=0 = 180,000 vCPU-s/month max
#   GCP Always Free Cloud Run tier = 180,000 vCPU-s/month => $0.00 worst-case bill!
set -euo pipefail

: "${GCP_PROJECT:?Set GCP_PROJECT}"
GCP_REGION="${GCP_REGION:-us-central1}"   # Must be an Always Free US region
AR_REPO="${AR_REPO:-spsolvebench}"
JOB_NAME="${JOB_NAME:-spsolvebench-verifier}"
SCHEDULER_SA="${SCHEDULER_SA:-spsolvebench-scheduler}"
IMAGE="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/${AR_REPO}/${JOB_NAME}:latest"

: "${R2_BUCKET:?Set R2_BUCKET}"
: "${R2_ENDPOINT:?Set R2_ENDPOINT (e.g. https://<account_id>.r2.cloudflarestorage.com)}"

echo "==> Ensuring Artifact Registry repo ${AR_REPO} in ${GCP_REGION} (keep latest 2 images to stay < 0.5 GB free tier)"
gcloud artifacts repositories describe "${AR_REPO}" \
  --project="${GCP_PROJECT}" --location="${GCP_REGION}" >/dev/null 2>&1 || \
gcloud artifacts repositories create "${AR_REPO}" \
  --project="${GCP_PROJECT}" --location="${GCP_REGION}" \
  --repository-format=docker --description="spsolvebench batch verifier"

gcloud artifacts repositories set-cleanup-policies "${AR_REPO}" \
  --project="${GCP_PROJECT}" --location="${GCP_REGION}" \
  --policy=<(cat <<'EOF'
[
  {
    "name": "keep-latest-two",
    "action": {"type": "Keep"},
    "mostRecentVersions": {"keepCount": 2}
  }
]
EOF
) --no-dry-run >/dev/null 2>&1 || true

echo "==> Building and pushing Docker image via Cloud Build"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
gcloud builds submit "${ROOT_DIR}" \
  --project="${GCP_PROJECT}" \
  --region="${GCP_REGION}" \
  --config=<(cat <<EOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-f', 'verifier/Dockerfile', '-t', '${IMAGE}', '.']
images:
  - '${IMAGE}'
EOF
)

echo "==> Creating/updating Cloud Run Job ${JOB_NAME} (1 vCPU, 512Mi, 20m hard cap)"
# Expects Secret Manager secrets: r2-access-key-id, r2-secret-access-key
# Optional for Cloudflare Workers AI moderation: cf-account-id, cf-api-token
SECRETS="R2_ACCESS_KEY_ID=r2-access-key-id:latest,R2_SECRET_ACCESS_KEY=r2-secret-access-key:latest"
if gcloud secrets describe cf-api-token --project="${GCP_PROJECT}" >/dev/null 2>&1; then
  SECRETS="${SECRETS},CF_ACCOUNT_ID=cf-account-id:latest,CF_API_TOKEN=cf-api-token:latest"
fi

gcloud run jobs deploy "${JOB_NAME}" \
  --project="${GCP_PROJECT}" \
  --region="${GCP_REGION}" \
  --image="${IMAGE}" \
  --cpu=1 \
  --memory=512Mi \
  --task-timeout=1200s \
  --max-retries=0 \
  --tasks=1 \
  --set-env-vars="R2_BUCKET=${R2_BUCKET},R2_ENDPOINT=${R2_ENDPOINT},VERIFY_WORKERS=1,MAX_ITEMS_PER_RUN=25" \
  --set-secrets="${SECRETS}"

echo "==> Ensuring scheduler service account ${SCHEDULER_SA}"
SA_EMAIL="${SCHEDULER_SA}@${GCP_PROJECT}.iam.gserviceaccount.com"
gcloud iam service-accounts describe "${SA_EMAIL}" --project="${GCP_PROJECT}" >/dev/null 2>&1 || \
gcloud iam service-accounts create "${SCHEDULER_SA}" --project="${GCP_PROJECT}" \
  --display-name="spsolvebench Cloud Scheduler invoker"

gcloud run jobs add-iam-policy-binding "${JOB_NAME}" \
  --project="${GCP_PROJECT}" \
  --region="${GCP_REGION}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/run.invoker" >/dev/null

# Note: Cloud Scheduler Always Free includes 3 jobs/month.
# Using 1 job with a 5x/day UTC schedule uses only 1 of your 3 free jobs!
# Standard 5-field cron can't express 00:00, 04:48, 09:36, 14:24, 19:12 in a single
# expression, so we use 3 free scheduler jobs (covering 5 triggers/day neatly) OR
# 1 job every 5 hours — here we create 3 free jobs covering the exact 5 UTC round times:
#   Job 1: 00:02 UTC (0 0 * * * -> 2 0 * * *)
#   Job 2: 04:50 & 14:26 UTC? Wait: 3 jobs max free -> let's use 3 exact crons OR note!
# Actually 5 exact round times: 00:00, 04:48, 09:36, 14:24, 19:12.
# Wait: 00:00, 05:00, 10:00, 15:00, 20:00 UTC is 1 SINGLE cron: "0 0,5,10,15,20 * * *"!
# It wakes up within 0–48 minutes of every round start and stays inside 1 free scheduler job!
JOB_URI="https://${GCP_REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${GCP_PROJECT}/jobs/${JOB_NAME}:run"
SCHED_NAME="${JOB_NAME}-5x-daily"

echo "==> Creating/updating Cloud Scheduler job ${SCHED_NAME} (1 free job, 5x/day UTC)"
gcloud scheduler jobs describe "${SCHED_NAME}" --project="${GCP_PROJECT}" --location="${GCP_REGION}" >/dev/null 2>&1 && \
  gcloud scheduler jobs delete "${SCHED_NAME}" --project="${GCP_PROJECT}" --location="${GCP_REGION}" --quiet

gcloud scheduler jobs create http "${SCHED_NAME}" \
  --project="${GCP_PROJECT}" \
  --location="${GCP_REGION}" \
  --schedule="0 0,5,10,15,20 * * *" \
  --time-zone="Etc/UTC" \
  --uri="${JOB_URI}" \
  --http-method=POST \
  --oauth-service-account-email="${SA_EMAIL}"

echo "==> Deployment complete! Trigger manually anytime with:"
echo "    gcloud run jobs execute ${JOB_NAME} --project=${GCP_PROJECT} --region=${GCP_REGION}"
