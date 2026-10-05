from unittest.mock import MagicMock

import services.key_service as key_service
import extensions


def test_get_abe_master_keys_creates_and_reuses_master_keys(monkeypatch):
    fake_doc = MagicMock()
    fake_doc.exists = False

    fake_ref = MagicMock()
    fake_ref.get.return_value = fake_doc

    fake_collection = MagicMock()
    fake_collection.document.return_value = fake_ref

    fake_db = MagicMock()
    fake_db.collection.return_value = fake_collection

    monkeypatch.setattr(extensions, "db", fake_db)

    class FakeSystem:
        def setup(self):
            return b"master-public", b"master-secret"

    monkeypatch.setattr(
        key_service,
        "CPABESystem",
        lambda: FakeSystem(),
    )

    key_service._abe_system = None
    key_service._abe_master_pk_blob = None
    key_service._abe_master_sk_blob = None

    assert key_service.get_abe_master_public_key() == b"master-public"
    assert key_service.get_abe_master_secret_key() == b"master-secret"

    fake_ref.set.assert_called_once()

    # Calling again should reuse the already-loaded master keys.
    assert key_service.get_abe_master_public_key() == b"master-public"
    assert key_service.get_abe_master_secret_key() == b"master-secret"

    assert fake_doc.exists is False

