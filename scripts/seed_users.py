"""
scripts/seed_users.py
---------------------
Bootstrap the Firestore database with:

  - one organization document
  - five demo users (one per role)
  - per-user cryptographic key material

Run with:
    python -m scripts.seed_users

Safe to re-run: users are looked up by email and skipped if they exist.
Key material is issued only for newly created users.
"""

import logging
import sys
import os
from pathlib import Path

# Allow `python -m scripts.seed_users` from the project root.
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config import Config, get_config
import extensions
from services import auth_service, key_service
from datetime import datetime, timezone


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("seed")


# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------

ORG_ID = "org-lagos-general"

ORG_DOC = {
    "organizationId": ORG_ID,
    "name": "Lagos General Digital Services",
    "type": "Healthcare",
    "location": "Lagos, Nigeria",
    "description": "Demonstration digital organization used as the case environment.",
    "status": "active",
}

DEMO_USERS = [
    {
        "email": "admin@cryptonet.local",
        "full_name": "Adaeze Okafor",
        "password": "AdminPass!2026x",
        "role": "ADMINISTRATOR",
        "department": "IT Operations",
        "clearance": "TOP_SECRET",
    },
    {
        "email": "security@cryptonet.local",
        "full_name": "Bola Adeyemi",
        "password": "SecurityPass!2026x",
        "role": "SECURITY_OFFICER",
        "department": "Security",
        "clearance": "SECRET",
    },
    {
        "email": "doctor@cryptonet.local",
        "full_name": "Dr. Chinedu Eze",
        "password": "DoctorPass!2026x",
        "role": "DOCTOR",
        "department": "Clinical",
        "clearance": "CONFIDENTIAL",
    },
    {
        "email": "records@cryptonet.local",
        "full_name": "Damilola Bello",
        "password": "RecordsPass!2026x",
        "role": "RECORDS_OFFICER",
        "department": "Records",
        "clearance": "CONFIDENTIAL",
    },
    {
        "email": "lab@cryptonet.local",
        "full_name": "Emeka Nwosu",
        "password": "LabPass!2026x",
        "role": "LABORATORY_OFFICER",
        "department": "Laboratory",
        "clearance": "INTERNAL",
    },
]


# ---------------------------------------------------------------------------
# Seed logic
# ---------------------------------------------------------------------------

def seed_organization() -> None:
    ref = extensions.db.collection(Config.COLLECTION_ORGANIZATIONS).document(ORG_ID)
    if ref.get().exists:
        logger.info("Organization %s already exists — skipping.", ORG_ID)
        return
    ref.set({**ORG_DOC, "createdAt": datetime.now(timezone.utc)})
    logger.info("Created organization %s.", ORG_ID)


def seed_users() -> None:
    for spec in DEMO_USERS:
        existing = auth_service.find_user_by_email(spec["email"])
        if existing:
            logger.info("User %s already exists — skipping.", spec["email"])
            continue

        user_id = auth_service.create_user(
            email=spec["email"],
            full_name=spec["full_name"],
            password=spec["password"],
            role=spec["role"],
            department=spec["department"],
            organization_id=ORG_ID,
            clearance=spec["clearance"],
        )
        logger.info("Created user %s (role=%s, id=%s).",
                    spec["email"], spec["role"], user_id)

        attrs = [
            f"ROLE:{spec['role']}",
            f"DEPT:{spec['department']}",
            f"CLEARANCE:{spec['clearance']}",
            f"ORG:{ORG_ID}",
        ]

        try:
            key_service.issue_user_keys(user_id, attrs)
            logger.info("Issued cryptographic keys for %s.", spec["email"])
        except ImportError as e:
            logger.warning(
                "Skipping CP-ABE key issuance (charm-crypto missing): %s",
                e,
            )

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    get_config()  # raises if env vars are missing
    extensions.db = extensions.init_firebase()

    logger.info("Seeding organization …")
    seed_organization()

    logger.info("Seeding users …")
    seed_users()
    for spec in DEMO_USERS:
        logger.info("  %-30s %-20s %s", spec["email"], spec["role"], spec["password"])
    logger.info("These passwords are for local demonstration only. Never reuse them.")


if __name__ == "__main__":
    main()
