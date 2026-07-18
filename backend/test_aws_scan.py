"""
Quick manual test: trigger a live AWS IAM scan and print a summary.
Delete after Week 2 verification — not part of the permanent test suite.
"""

import asyncio
import json
import logging

from config import settings
from collectors.aws_collector import AWSCollector

logging.basicConfig(level=logging.INFO)


async def main():
    collector = AWSCollector(
        region=settings.AWS_REGION,
        access_key_id=settings.AWS_ACCESS_KEY_ID,
        secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        role_arn=settings.AWS_ROLE_ARN,
    )

    data = await collector.collect()

    print("\n" + "=" * 50)
    print("SCAN RESULT SUMMARY")
    print("=" * 50)
    print(f"Account ID:          {data.account_id}")
    print(f"Region:               {data.region}")
    print(f"Users collected:      {len(data.users)}")
    print(f"Roles collected:      {len(data.roles)}")
    print(f"Groups collected:     {len(data.groups)}")
    print(f"Policies collected:   {len(data.policies)}")
    print(f"Trust relationships:  {len(data.trust_relationships)}")
    print(f"Errors:               {data.errors}")
    print("=" * 50)

    if data.users:
        print("\nSample user:")
        print(json.dumps(data.users[0], indent=2, default=str))

    if data.trust_relationships:
        print("\nSample trust relationship:")
        print(json.dumps(data.trust_relationships[0], indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())