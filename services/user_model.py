"""
services/user_model.py
----------------------
CryptoNetUser — the Flask-Login user object.

This class is a thin, read-only view over a Firestore `users` document.
It exposes exactly the attributes the authorization decorators need:

    .id                    -> str (Firestore doc ID)
    .email                 -> str
    .full_name             -> str
    .role                  -> str (one of Config.ROLES)
    .department            -> str
    .organization_id       -> str
    .clearance_level       -> str (one of Config.CLEARANCE_LEVELS)
    .status                -> str ('active' | 'disabled')
    .attributes            -> list[str] (CP-ABE attribute set)
    .is_active             -> bool (Flask-Login contract)

The CP-ABE attribute set is derived from role + department + clearance,
so that an administrator only has to edit the user document.
"""

from flask_login import UserMixin
from typing import Optional

import extensions


class CryptoNetUser(UserMixin):
    """Flask-Login user, backed by a Firestore users doc."""

    def __init__(self, data: dict):
        # data is the Firestore document dict with 'userId' already populated
        self._data = data
        self.id = data["userId"]
        self.email = data.get("email", "")
        self.full_name = data.get("fullName", "")
        self.role = data.get("role", "RECORDS_OFFICER")
        self.department = data.get("department", "")
        self.organization_id = data.get("organizationId", "")
        self.clearance_level = data.get("clearanceLevel", "INTERNAL")
        self.status = data.get("status", "active")
        self._attributes = self._derive_attributes()

    # ---------- Flask-Login contract ----------

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def get_id(self) -> str:
        return self.id

    # ---------- CP-ABE attributes ----------

    @property
    def attributes(self) -> list[str]:
        """
        CP-ABE attribute set. Convention:
            role          -> "ROLE:<ROLE>"
            department    -> "DEPT:<DEPT>"
            organization  -> "ORG:<ORGID>"
            clearance     -> "CLEARANCE:<LEVEL>"
            location      -> "LOC:LAGOS"  (from organization doc, optional)
        """
        return self._attributes

    def _derive_attributes(self) -> list[str]:
        attrs = [
            f"ROLE:{self.role}",
            f"DEPT:{self.department}",
            f"CLEARANCE:{self.clearance_level}",
        ]
        if self.organization_id:
            attrs.append(f"ORG:{self.organization_id}")
        return attrs

    # ---------- lookup ----------

    @classmethod
    def from_id(cls, user_id: str) -> Optional["CryptoNetUser"]:
        """Load a user from Firestore by ID. Returns None if absent."""
        if extensions.db is None:
            return None
        doc = (
            extensions.db.collection("users").document(user_id).get()
        )
        if not doc.exists:
            return None
        data = doc.to_dict() or {}
        data["userId"] = doc.id
        return cls(data)

    # ---------- debugging ----------

    def __repr__(self) -> str:
        return f"<CryptoNetUser {self.email} role={self.role}>"
