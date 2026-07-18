"""
TrustField - Database Seed Script
Creates initial test users for local development.

Usage:
    python seed.py
"""

import logging

from auth.dependencies import get_password_hash
from db.database import SessionLocal
from db.models import User, UserRole

logging.basicConfig(level=logging.INFO, format="%(levelname)-8s | %(message)s")
logger = logging.getLogger(__name__)


SEED_USERS = [
    {
        "email": "admin@trustfield.com",
        "username": "admin",
        "password": "Admin123!",
        "full_name": "Admin User",
        "role": UserRole.ADMIN,
    },
    {
        "email": "analyst@trustfield.com",
        "username": "analyst",
        "password": "Analyst123!",
        "full_name": "Analyst User",
        "role": UserRole.ANALYST,
    },
    {
        "email": "viewer@trustfield.com",
        "username": "viewer",
        "password": "Viewer123!",
        "full_name": "Viewer User",
        "role": UserRole.VIEWER,
    },
]


def seed_users():
    db = SessionLocal()
    try:
        for entry in SEED_USERS:
            existing = db.query(User).filter(User.email == entry["email"]).first()
            if existing:
                logger.info(f"Skipping {entry['email']} — already exists")
                continue

            user = User(
                email=entry["email"],
                username=entry["username"],
                hashed_password=get_password_hash(entry["password"]),
                full_name=entry["full_name"],
                role=entry["role"],
                is_active=True,
            )
            db.add(user)
            logger.info(f"Created {entry['role'].value}: {entry['email']} / {entry['password']}")

        db.commit()
        logger.info("Seeding complete.")
    except Exception as exc:
        db.rollback()
        logger.error(f"Seeding failed: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_users()