#!/usr/bin/env bash
# Deploy a hard $5/month auto-takedown kill-switch on a DEDICATED GCP project.
# WARNING: Only run this on a dedicated spsolvebench GCP project — when the
# $5 budget threshold is reached, billing is unlinked from the entire project!
set -euo pipefail

: "${GCP_PROJECT:?Set GCP_PROJECT (use a dedicated project for spsolvebench!)}"
: "${BILLING_ACCOUNT_ID:?Set BILLING_ACCOUNT_ID (format: XXXXXX-XXXXXX-XXXXXX)}"
GCP_REGION="${GCP_REGION:-us-central1}"
BUDGET_USD="${BUDGET_USD:-5}"
TOPIC="${TOPIC:-spsolvebench-budget-alerts}"
FN_NAME="${FN_NAME:-spsolvebench-billing-killswitch}"

echo "==> Enabling required APIs"
gcloud services enable pubsub.googleapis.com cloudfunctions.googleapis.com \
  cloudbilling.googleapis.com billingbudgets.googleapis.com run.googleapis.com \
  --project="${GCP_PROJECT}"

echo "==> Creating Pub/Sub topic ${TOPIC}"
gcloud pubsub topics describe "${TOPIC}" --project="${GCP_PROJECT}" >/dev/null 2>&1 || \
  gcloud pubsub topics create "${TOPIC}" --project="${GCP_PROJECT}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Deploying kill-switch Cloud Function (${FN_NAME})"
gcloud functions deploy "${FN_NAME}" \
  --gen2 \
  --project="${GCP_PROJECT}" \
  --region="${GCP_REGION}" \
  --runtime=python312 \
  --source="${SCRIPT_DIR}" \
  --entry-point=stop_billing \
  --trigger-topic="${TOPIC}" \
  --memory=256Mi \
  --set-env-vars="GCP_PROJECT=${GCP_PROJECT}"

PROJECT_NUM="$(gcloud projects describe "${GCP_PROJECT}" --format='value(projectNumber)')"
SA_EMAIL="${PROJECT_NUM}-compute@developer.gserviceaccount.com"

echo "==> Granting Billing Account Administrator to ${SA_EMAIL} on billing account ${BILLING_ACCOUNT_ID}"
gcloud billing accounts add-iam-policy-binding "${BILLING_ACCOUNT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/billing.admin" >/dev/null

echo "==> Creating \$${BUDGET_USD}/month Cloud Billing Budget wired to ${TOPIC}"
gcloud billing budgets create \
  --billing-account="${BILLING_ACCOUNT_ID}" \
  --display-name="spsolvebench-hard-cap-${BUDGET_USD}usd" \
  --filter-projects="projects/${PROJECT_NUM}" \
  --budget-amount="${BUDGET_USD}USD" \
  --threshold-rule="percent=0.5" \
  --threshold-rule="percent=0.9" \
  --threshold-rule="percent=1.0" \
  --notifications-rule-pubsub-topic="projects/${GCP_PROJECT}/topics/${TOPIC}"

echo "==> Hard \$${BUDGET_USD}/month GCP kill-switch active for ${GCP_PROJECT}."
