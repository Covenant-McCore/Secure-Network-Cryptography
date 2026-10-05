"""
tests/test_auth.py
------------------
Unit tests for the authentication service.
"""

from unittest.mock import MagicMock

import pytest

import extensions
from services import auth_service


def test_authenticate_success(monkeypatch):
    """Correct credentials should authenticate successfully."""

    user = {
        "userId": "user-001",
        "email": "doctor@example.com",
        "passwordHash": "argon2-hash",
        "status": "active",
        "role": "DOCTOR",
        "clearanceLevel": "CONFIDENTIAL",
    }

    monkeypatch.setattr(
        auth_service,
        "find_user_by_email",
        lambda email: user,
    )

    monkeypatch.setattr(
        auth_service.pw,
        "verify_password",
        lambda stored, candidate: True,
    )

    monkeypatch.setattr(
        auth_service.pw,
        "needs_rehash",
        lambda stored: False,
    )

    monkeypatch.setattr(
        auth_service,
        "_touch_last_login",
        lambda user_id: None,
    )

    result = auth_service.authenticate(
        "doctor@example.com",
        "SecurePassword123!",
    )

    assert result["userId"] == "user-001"
    assert result["role"] == "DOCTOR"


def test_authenticate_wrong_password(monkeypatch):
    """An incorrect password should raise InvalidCredentials."""

    user = {
        "userId": "user-001",
        "email": "doctor@example.com",
        "passwordHash": "argon2-hash",
        "status": "active",
    }

    monkeypatch.setattr(
        auth_service,
        "find_user_by_email",
        lambda email: user,
    )

    monkeypatch.setattr(
        auth_service.pw,
        "verify_password",
        lambda stored, candidate: False,
    )

    with pytest.raises(auth_service.InvalidCredentials):
        auth_service.authenticate(
            "doctor@example.com",
            "WrongPassword123!",
        )


def test_authenticate_unknown_user(monkeypatch):
    """An unknown email should raise UserNotFound."""

    monkeypatch.setattr(
        auth_service,
        "find_user_by_email",
        lambda email: None,
    )

    with pytest.raises(auth_service.UserNotFound):
        auth_service.authenticate(
            "unknown@example.com",
            "SecurePassword123!",
        )


def test_authenticate_disabled_account(monkeypatch):
    """A disabled account should not authenticate."""

    user = {
        "userId": "user-002",
        "email": "disabled@example.com",
        "passwordHash": "argon2-hash",
        "status": "disabled",
    }

    monkeypatch.setattr(
        auth_service,
        "find_user_by_email",
        lambda email: user,
    )

    monkeypatch.setattr(
        auth_service.pw,
        "verify_password",
        lambda stored, candidate: True,
    )

    with pytest.raises(auth_service.AccountDisabled):
        auth_service.authenticate(
            "disabled@example.com",
            "SecurePassword123!",
        )


def test_create_user_validates_role(monkeypatch):
    """Invalid RBAC roles should be rejected."""

    mock_db = MagicMock()
    monkeypatch.setattr(extensions, "db", mock_db)

    with pytest.raises(auth_service.AuthError):
        auth_service.create_user(
            email="test@example.com",
            full_name="Test User",
            password="SecurePassword123!",
            role="INVALID_ROLE",
            department="Medical",
            organization_id="org-001",
            clearance="CONFIDENTIAL",
        )


