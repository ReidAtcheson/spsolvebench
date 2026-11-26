"""GCP Cloud Function (Gen 2) billing kill-switch for dedicated spsolvebench project.

Triggered by a Cloud Billing Budget Pub/Sub notification ($5/month cap).
If costAmount >= budgetAmount, unlinks billing from GCP_PROJECT, immediately
halting all GCP resources so spend cannot exceed the configured ceiling.
(The static Cloudflare Pages site remains up read-only.)
"""
import base64
import json
import os
import functions_framework
from googleapiclient import discovery

PROJECT_ID = os.environ["GCP_PROJECT"]
PROJECT_NAME = f"projects/{PROJECT_ID}"


@functions_framework.cloud_event
def stop_billing(cloud_event):
    msg = cloud_event.data.get("message", {})
    raw = base64.b64decode(msg["data"]).decode("utf-8")
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
