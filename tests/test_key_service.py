from unittest.mock import MagicMock

import extensions
from services import key_service


def test_get_user_public_keys_returns_public_material_only(monkeypatch):
    fake_doc = MagicMock()
    fake_doc.exists = True
    fake_doc.to_dict.return_value = {
        "userId": "user-001",
        "ed25519": {
            "publicKey": b"ed-public",
            "algorithm": "Ed25519",
        },
        "mlKem768": {
            "publicKey": b"kem-public",
            "algorithm": "ML-KEM-768",
        },
        "attributes": ["DOCTOR", "LAGOS"],
        "status": "active",
        "privateMaterial": {
            "ed25519PrivateKey": b"secret-ed",
            "mlKem768PrivateKey": b"secret-kem",
        },
    }

    fake_ref = MagicMock()
    fake_ref.get.return_value = fake_doc

    fake_collection = MagicMock()
    fake_collection.document.return_value = fake_ref

    fake_db = MagicMock()
    fake_db.collection.return_value = fake_collection

    monkeypatch.setattr(extensions, "db", fake_db)

    result = key_service.get_user_public_keys("user-001")

    assert result["userId"] == "user-001"
    assert result["ed25519PublicKey"] == b"ed-public"
    assert result["mlKem768PublicKey"] == b"kem-public"
    assert result["cpabeAttributes"] == ["DOCTOR", "LAGOS"]
    assert result["status"] == "active"

    assert "privateMaterial" not in result
    assert "ed25519PrivateKey" not in result
    assert "mlKem768PrivateKey" not in result


def test_get_user_public_keys_returns_none_for_missing_user(monkeypatch):
    fake_doc = MagicMock()
    fake_doc.exists = False

    fake_ref = MagicMock()
    fake_ref.get.return_value = fake_doc

    fake_collection = MagicMock()
    fake_collection.document.return_value = fake_ref

    fake_db = MagicMock()
    fake_db.collection.return_value = fake_collection

    monkeypatch.setattr(extensions, "db", fake_db)

    result = key_service.get_user_public_keys("missing-user")

    assert result is None


def test_get_user_private_material_returns_private_components(monkeypatch):
    fake_doc = MagicMock()
    fake_doc.exists = True
    fake_doc.to_dict.return_value = {
        "ed25519": {
            "publicKey": b"ed-public",
        },
        "mlKem768": {
            "publicKey": b"kem-public",
        },
        "cpabe": {
            "secretKeyBlob": "cpabe-secret",
        },
        "attributes": ["DOCTOR", "LAGOS"],
        "privateMaterial": {
            "ed25519PrivateKey": b"ed-private",
            "mlKem768PrivateKey": b"kem-private",
        },
    }

    fake_ref = MagicMock()
    fake_ref.get.return_value = fake_doc

    fake_collection = MagicMock()
    fake_collection.document.return_value = fake_ref

    fake_db = MagicMock()
    fake_db.collection.return_value = fake_collection

    monkeypatch.setattr(extensions, "db", fake_db)

    result = key_service.get_user_private_material("user-001")

    assert result["userId"] == "user-001"
    assert result["ed25519PrivateKey"] == b"ed-private"
    assert result["mlKem768PrivateKey"] == b"kem-private"
    assert result["cpabeSecretKeyBlob"] == "cpabe-secret"
    assert result["cpabeAttributes"] == ["DOCTOR", "LAGOS"]


def test_get_user_private_material_returns_none_for_missing_user(monkeypatch):
    fake_doc = MagicMock()
    fake_doc.exists = False

    fake_ref = MagicMock()
    fake_ref.get.return_value = fake_doc

    fake_collection = MagicMock()
    fake_collection.document.return_value = fake_ref

    fake_db = MagicMock()
    fake_db.collection.return_value = fake_collection

    monkeypatch.setattr(extensions, "db", fake_db)

    result = key_service.get_user_private_material("missing-user")

    assert result is None


def test_revoke_user_keys_updates_status(monkeypatch):
    fake_ref = MagicMock()

    fake_collection = MagicMock()
    fake_collection.document.return_value = fake_ref

    fake_db = MagicMock()
    fake_db.collection.return_value = fake_collection

    monkeypatch.setattr(extensions, "db", fake_db)

    key_service.revoke_user_keys("user-001")

    fake_db.collection.assert_called_once_with(
        key_service.Config.COLLECTION_KEYS
    )
    fake_collection.document.assert_called_once_with("user-001")

    fake_ref.update.assert_called_once()

    update_data = fake_ref.update.call_args.args[0]

    assert update_data["status"] == "revoked"
    assert "updatedAt" in update_data


def test_issue_user_keys_generates_and_persists_key_material(monkeypatch):
    fake_ed_private = b"ed-private"
    fake_ed_public = b"ed-public"
    fake_kem_public = b"kem-public"
    fake_kem_private = b"kem-private"
    fake_cpabe_secret = "cpabe-secret"

    monkeypatch.setattr(
        key_service.signatures,
        "generate_keypair",
        lambda: (fake_ed_private, fake_ed_public),
    )

    monkeypatch.setattr(
        key_service.ml_kem,
        "keygen",
        lambda: (fake_kem_public, fake_kem_private),
    )

    fake_abe = MagicMock()
    fake_abe.keygen.return_value = fake_cpabe_secret

    monkeypatch.setattr(key_service, "get_abe_system", lambda: fake_abe)
    monkeypatch.setattr(
        key_service,
        "get_abe_master_public_key",
        lambda: "master-public",
    )
    monkeypatch.setattr(
        key_service,
        "get_abe_master_secret_key",
        lambda: "master-secret",
    )

    keys_ref = MagicMock()
    user_ref = MagicMock()

    def collection_side_effect(name):
        collection = MagicMock()

        if name == key_service.Config.COLLECTION_KEYS:
            collection.document.return_value = keys_ref
        elif name == key_service.Config.COLLECTION_USERS:
            collection.document.return_value = user_ref

        return collection

    fake_db = MagicMock()
    fake_db.collection.side_effect = collection_side_effect

    monkeypatch.setattr(extensions, "db", fake_db)

    result = key_service.issue_user_keys(
        "user-001",
        ["DOCTOR", "LAGOS", "CLEARANCE-3"],
    )

    assert result["userId"] == "user-001"
    assert result["ed25519PublicKeyLength"] == len(fake_ed_public)
    assert result["mlKem768PublicKeyLength"] == len(fake_kem_public)
    assert result["cpabeAttributes"] == [
        "DOCTOR",
        "LAGOS",
        "CLEARANCE-3",
    ]

    keys_ref.set.assert_called_once()
    user_ref.update.assert_called_once_with({
        "publicKeyId": "user-001",
    })

    stored = keys_ref.set.call_args.args[0]

    assert stored["userId"] == "user-001"
    assert stored["status"] == "active"
    assert stored["attributes"] == [
        "DOCTOR",
        "LAGOS",
        "CLEARANCE-3",
    ]

    assert stored["ed25519"]["publicKey"] == fake_ed_public
    assert stored["mlKem768"]["publicKey"] == fake_kem_public
    assert stored["cpabe"]["secretKeyBlob"] == fake_cpabe_secret

    assert stored["privateMaterial"]["ed25519PrivateKey"] == fake_ed_private
    assert stored["privateMaterial"]["mlKem768PrivateKey"] == fake_kem_private

    fake_abe.keygen.assert_called_once_with(
        "master-public",
        "master-secret",
        ["DOCTOR", "LAGOS", "CLEARANCE-3"],
    )


def test_issue_user_keys_generates_and_persists_key_material(monkeypatch):
    fake_ed_private = b"ed-private"
    fake_ed_public = b"ed-public"
    fake_kem_public = b"kem-public"
    fake_kem_private = b"kem-private"
    fake_cpabe_secret = "cpabe-secret"

    monkeypatch.setattr(
        key_service.signatures,
        "generate_keypair",
        lambda: (fake_ed_private, fake_ed_public),
    )

    monkeypatch.setattr(
        key_service.ml_kem,
        "keygen",
        lambda: (fake_kem_public, fake_kem_private),
    )

    fake_abe = MagicMock()
    fake_abe.keygen.return_value = fake_cpabe_secret

    monkeypatch.setattr(key_service, "get_abe_system", lambda: fake_abe)
    monkeypatch.setattr(
        key_service,
        "get_abe_master_public_key",
        lambda: "master-public",
    )
    monkeypatch.setattr(
        key_service,
        "get_abe_master_secret_key",
        lambda: "master-secret",
    )

    keys_ref = MagicMock()
    user_ref = MagicMock()

    def collection_side_effect(name):
        collection = MagicMock()

        if name == key_service.Config.COLLECTION_KEYS:
            collection.document.return_value = keys_ref
        elif name == key_service.Config.COLLECTION_USERS:
            collection.document.return_value = user_ref

        return collection

    fake_db = MagicMock()
    fake_db.collection.side_effect = collection_side_effect

    monkeypatch.setattr(extensions, "db", fake_db)

    result = key_service.issue_user_keys(
        "user-001",
        ["DOCTOR", "LAGOS", "CLEARANCE-3"],
    )

    assert result["userId"] == "user-001"
    assert result["ed25519PublicKeyLength"] == len(fake_ed_public)
    assert result["mlKem768PublicKeyLength"] == len(fake_kem_public)
    assert result["cpabeAttributes"] == [
        "DOCTOR",
        "LAGOS",
        "CLEARANCE-3",
    ]

    keys_ref.set.assert_called_once()
    user_ref.update.assert_called_once_with({
        "publicKeyId": "user-001",
    })

    stored = keys_ref.set.call_args.args[0]

    assert stored["userId"] == "user-001"
    assert stored["status"] == "active"
    assert stored["attributes"] == [
        "DOCTOR",
        "LAGOS",
        "CLEARANCE-3",
    ]

    assert stored["ed25519"]["publicKey"] == fake_ed_public
    assert stored["mlKem768"]["publicKey"] == fake_kem_public
    assert stored["cpabe"]["secretKeyBlob"] == fake_cpabe_secret

    assert stored["privateMaterial"]["ed25519PrivateKey"] == fake_ed_private
    assert stored["privateMaterial"]["mlKem768PrivateKey"] == fake_kem_private

    fake_abe.keygen.assert_called_once_with(
        "master-public",
        "master-secret",
        ["DOCTOR", "LAGOS", "CLEARANCE-3"],
    )


def test_rotate_user_keys_issues_new_keys_and_returns_public_keys(monkeypatch):
    issued_summary = {
        "userId": "user-001",
        "ed25519PublicKeyLength": 32,
        "mlKem768PublicKeyLength": 1184,
        "cpabeAttributes": ["DOCTOR", "LAGOS"],
        "algorithm": {
            "signature": "Ed25519",
            "kem": "ML-KEM-768",
            "abe": "CP-ABE (BSW07)",
        },
    }

    public_keys = {
        "userId": "user-001",
        "ed25519PublicKey": b"new-ed-public",
        "mlKem768PublicKey": b"new-kem-public",
        "cpabeAttributes": ["DOCTOR", "LAGOS"],
        "status": "active",
    }

    issue_mock = MagicMock(return_value=issued_summary)
    public_mock = MagicMock(return_value=public_keys)

    monkeypatch.setattr(key_service, "issue_user_keys", issue_mock)
    monkeypatch.setattr(key_service, "get_user_public_keys", public_mock)

    fake_ref = MagicMock()
    fake_collection = MagicMock()
    fake_collection.document.return_value = fake_ref

    fake_db = MagicMock()
    fake_db.collection.return_value = fake_collection

    monkeypatch.setattr(extensions, "db", fake_db)

    result = key_service.rotate_user_keys(
        "user-001",
        ["DOCTOR", "LAGOS"],
    )

    issue_mock.assert_called_once_with(
        "user-001",
        ["DOCTOR", "LAGOS"],
    )

    public_mock.assert_called_once_with("user-001")

    assert result == public_keys

    fake_ref.set.assert_called_once_with(
        issued_summary,
        merge=True,
    )
