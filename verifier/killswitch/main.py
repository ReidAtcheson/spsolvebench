"""GCP Cloud Function billing kill-switch for a dedicated spsolvebench project.

Triggered by a Cloud Billing Budget Pub/Sub notification (e.g. $5/month cap).
If costAmount >= budgetAmount, unlinks billing from GCP_PROJECT, immediately
halting all GCP resources so spend cannot exceed the configured ceiling.
(The static Cloudflare Pages site remains up read-only.)
"""
import base64
import json
import os
from googleapiclient import discovery

PROJECT_ID = os.environ["GCP_PROJECT"]
PROJECT_NAME = f"projects/{PROJECT_ID}"


def stop_billing(event, _context):
    raw = base64.b64decode(event["data"]).decode("utf-8")
    data = json.loads(raw)
    cost_amount = float(data.get("costAmount", 0.0))
    budget_amount = float(data.get("budgetAmount", 0.0))
    print(f"[killswitch] project={PROJECT_ID} cost={cost_amount} budget={budget_amount}")

    if budget_amount <= 0 or cost_amount < budget_amount:
        print("[killswitch] Below cap; taking no action.")
        return

    billing = discovery.build("cloudbilling", "v1", cache_discovery=False)
    info = billing.projects().getBillingInfo(name=PROJECT_NAME).execute()
    if not info.get("billingEnabled"):
        print("[killswitch] Billing already disabled.")
        return

    print(f"[killswitch] CAP REACHED ({cost_amount} >= {budget_amount})! Disabling billing on {PROJECT_NAME}.")
    billing.projects().updateBillingInfo(
        name=PROJECT_NAME,
        body={"billingAccountName": ""},
    ).execute()
    print("[killswitch] Billing disabled.")
