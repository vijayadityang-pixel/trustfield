import asyncio
import os
from config import settings  # adjust import path if your Settings instance lives elsewhere

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = settings.GOOGLE_APPLICATION_CREDENTIALS

from collectors.gcp_collector import GCPCollector

async def test():
    collector = GCPCollector(project_id=settings.GCP_PROJECT_ID)
    data = await collector.collect()
    print("Errors:", data.errors)
    print("Service accounts:", len(data.service_accounts))
    print("IAM bindings:", len(data.iam_bindings))
    print("Custom roles:", len(data.custom_roles))
    print("Trust relationships:", len(data.trust_relationships))
    for t in data.trust_relationships:
        if t.get("relationship") == "CAN_ASSUME":
            print("CAN_ASSUME edge:", t)

asyncio.run(test())