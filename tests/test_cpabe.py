"""Sanity tests for the CP-ABE module."""
from crypto.cpabe import CPABESystem


def test_cpabe_happy_path():
    sys = CPABESystem()
    pk, mk = sys.setup()

    policy = "ADMIN and LAGOS"
    plaintext = "Confidential organizational message."

    ct = sys.encrypt(pk, plaintext, policy)

    # Authorized user
    sk_ok = sys.keygen(pk, mk, ["ADMIN", "LAGOS"])
    assert sys.decrypt(pk, sk_ok, ct) == plaintext

    # Unauthorized user
    sk_bad = sys.keygen(pk, mk, ["ADMIN", "ABUJA"])
    try:
        sys.decrypt(pk, sk_bad, ct)
        assert False, "Expected PermissionError"
    except PermissionError:
        pass

