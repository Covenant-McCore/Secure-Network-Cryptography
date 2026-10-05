import pytest

from services.authorization_service import (
    user_has_role,
    user_has_any_role,
    user_meets_clearance,
    user_in_organization,
)


def test_user_has_role():
    user = {"role": "DOCTOR"}

    assert user_has_role(user, "DOCTOR") is True


def test_user_has_any_role():
    user = {"role": "DOCTOR"}

    assert user_has_any_role(user, ["DOCTOR", "ADMINISTRATOR"]) is True
    assert user_has_any_role(user, ["SECURITY_OFFICER", "ADMINISTRATOR"]) is False


def test_user_meets_clearance():
    user = {
        "clearanceLevel": "SECRET",
    }

    assert user_meets_clearance(user, "PUBLIC") is True
    assert user_meets_clearance(user, "CONFIDENTIAL") is True
    assert user_meets_clearance(user, "SECRET") is True
    assert user_meets_clearance(user, "TOP_SECRET") is False


def test_user_in_organization():
    user = {
        "organizationId": "org-001",
    }

    assert user_in_organization(user, "org-001") is True
    assert user_in_organization(user, "org-002") is False


def test_user_has_role_is_case_sensitive():
    user = {"role": "DOCTOR"}

    assert user_has_role(user, "DOCTOR") is True
    assert user_has_role(user, "doctor") is False


def test_missing_role_is_denied():
    user = {}

    assert user_has_role(user, "DOCTOR") is False


def test_missing_clearance_is_denied():
    user = {}

    assert user_meets_clearance(user, "INTERNAL") is False
