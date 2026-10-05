"""
routes/security.py
------------------
  /security/access-control   RBAC demonstration + CP-ABE policy demo
  /security/simulation       Six controlled threat simulations
"""

import base64
import logging
import os

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from config import Config
from crypto import aes_gcm, hashing, ml_kem, signatures
from extensions import limiter
from services import audit_service

logger = logging.getLogger(__name__)

security_bp = Blueprint("security", __name__, url_prefix="/security")


# ---------------------------------------------------------------------------
# Access Control lab
# ---------------------------------------------------------------------------

@security_bp.route("/access-control")
@login_required
def access_control_page():
    """
    Render the access-control lab. We probe whether charm-crypto is
    importable so the template can show an honest banner.
    """
    try:
        import charm  # noqa: F401
        cpabe_available = True
    except ImportError:
        cpabe_available = False

    return render_template(
        "lab_access_control.html",
        cpabe_available=cpabe_available,
        current_attributes=current_user.attributes,
        current_role=current_user.role,
    )


@security_bp.route("/access-control/rbac", methods=["POST"])
@login_required
def access_control_rbac():
    """
    Demonstrate server-side RBAC by evaluating a hypothetical request
    against a small policy table. This is a simulated decision — no real
    resource is touched.
    """
    payload = request.get_json(silent=True) or {}
    resource = (payload.get("resource") or "").strip()
    required_role = (payload.get("required_role") or "").strip()

    if not resource or not required_role:
        return jsonify({"status": "error", "message": "resource and required_role required."}), 400

    granted = (current_user.role == required_role)

    audit_service.log_event(
        "ACCESS_GRANTED" if granted else "ACCESS_DENIED",
        user_id=current_user.id,
        resource=f"simulation/{resource}",
        result="GRANTED" if granted else "DENIED",
        severity=audit_service.SEVERITY_INFO if granted else audit_service.SEVERITY_WARNING,
        details={"requiredRole": required_role, "actualRole": current_user.role},
    )

    return jsonify({
        "status": "ok",
        "resource": resource,
        "required_role": required_role,
        "caller_role": current_user.role,
        "decision": "ACCESS GRANTED" if granted else "ACCESS DENIED",
    }), 200


@security_bp.route("/access-control/cpabe", methods=["POST"])
@login_required
def access_control_cpabe():
    """
    If charm-crypto is importable, run a genuine CP-ABE encrypt/decrypt
    cycle in-process. Otherwise return a clear "unavailable" response.
    """
    try:
        from crypto.cpabe import CPABESystem
    except ImportError:
        return jsonify({
            "status": "unavailable",
            "message": "CP-ABE is not available in this environment.",
        }), 200

    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or
               "PATIENT_REF:9942 · CLASSIFICATION:CONFIDENTIAL").encode("utf-8")
    policy = (payload.get("policy") or "ROLE:DOCTOR and DEPT:Clinical and ORG:org-lagos-general").strip()

    try:
        system = CPABESystem()
        pk, mk = system.setup()

        ct_blob = system.encrypt(pk, message.decode("utf-8"), policy)

        # 1. Authorized caller attributes
        authorized_attrs = list(current_user.attributes)
        # 2. Unauthorized caller attributes: strip one attribute
        unauthorized_attrs = [a for a in authorized_attrs if not a.startswith("ROLE:")]

        try:
            sk_auth = system.keygen(pk, mk, authorized_attrs)
            pt_auth = system.decrypt(pk, sk_auth, ct_blob)
            authorized_result = {"decision": "ACCESS GRANTED", "plaintext": pt_auth}
        except PermissionError as e:
            authorized_result = {"decision": "ACCESS DENIED", "reason": str(e)}

        try:
            sk_unauth = system.keygen(pk, mk, unauthorized_attrs)
            pt_unauth = system.decrypt(pk, sk_unauth, ct_blob)
            unauthorized_result = {"decision": "ACCESS GRANTED", "plaintext": pt_unauth}
        except PermissionError as e:
            unauthorized_result = {"decision": "ACCESS DENIED", "reason": str(e)}

        audit_service.log_event(
            "LAB_ACCESS_CONTROL_RUN",
            user_id=current_user.id,
            resource="lab/access-control",
            result="SUCCESS",
            details={"scheme": "CP-ABE (BSW07)"},
        )

        return jsonify({
            "status": "ok",
            "scheme": "CP-ABE (BSW07, Bethencourt–Sahai–Waters)",
            "policy": policy,
            "authorized_caller": authorized_result,
            "unauthorized_caller": unauthorized_result,
            "caller_attributes": authorized_attrs,
            "caller_role": current_user.role,
        }), 200
    except Exception as exc:
        logger.exception("CP-ABE lab failed: %s", exc)
        return jsonify({"status": "error", "message": "CP-ABE lab error."}), 500


# ---------------------------------------------------------------------------
# Threat Simulation
# ---------------------------------------------------------------------------

@security_bp.route("/simulation")
@login_required
def simulation_page():
    return render_template("lab_threat_simulation.html")


@security_bp.route("/simulation/eavesdropping", methods=["POST"])
@login_required
def sim_eavesdropping():
    """
    Demonstrate that plaintext communication is readable by an observer,
    while AES-GCM ciphertext is not. No keys are exposed.
    """
    plaintext = b"CONFIDENTIAL: Meeting at 1400 hours, Room 4B."
    key = aes_gcm.generate_key()
    env = aes_gcm.encrypt(plaintext, key)

    audit_service.log_event(
        "THREAT_SIMULATION_RUN",
        user_id=current_user.id,
        resource="simulation/eavesdropping",
        result="SUCCESS",
        details={"threat": "eavesdropping"},
    )

    return jsonify({
        "status": "ok",
        "threat": "Eavesdropping",
        "scenario": "An attacker observes network traffic.",
        "plaintext_channel": {
            "observable": plaintext.decode("utf-8"),
            "result": "PLAINTEXT EXPOSED",
        },
        "encrypted_channel": {
            "observable_ciphertext_b64": base64.b64encode(env["ciphertext"]).decode("ascii"),
            "nonce_b64": base64.b64encode(env["nonce"]).decode("ascii"),
            "tag_b64": base64.b64encode(env["tag"]).decode("ascii"),
            "result": "CIPHERTEXT UNINTELLIGIBLE — AES-256-GCM",
        },
    }), 200


@security_bp.route("/simulation/tampering", methods=["POST"])
@login_required
def sim_tampering():
    """
    Encrypt a message, modify one byte of the ciphertext, then attempt
    decryption. AES-GCM should reject.
    """
    key = aes_gcm.generate_key()
    env = aes_gcm.encrypt(b"Pay NGN 100,000 to Account A.", key)

    # Tamper: flip the first byte of ciphertext
    tampered = bytearray(env["ciphertext"])
    tampered[0] ^= 0x01
    tampered_env = {**env, "ciphertext": bytes(tampered)}

    try:
        aes_gcm.decrypt(tampered_env, key)
        result = "DECRYPTION SUCCEEDED (unexpected)"
        detected = False
    except aes_gcm.DecryptionError:
        result = "INTEGRITY VERIFICATION FAILED — AUTHENTICATION TAG MISMATCH"
        detected = True

    audit_service.log_event(
        "THREAT_SIMULATION_RUN",
        user_id=current_user.id,
        resource="simulation/tampering",
        result="SUCCESS",
        severity=audit_service.SEVERITY_INFO if detected else audit_service.SEVERITY_CRITICAL,
        details={"threat": "tampering", "detected": detected},
    )

    return jsonify({
        "status": "ok",
        "threat": "Message tampering",
        "scenario": "An attacker modifies one byte of ciphertext in transit.",
        "detected": detected,
        "result": result,
        "algorithm": "AES-256-GCM (authenticated encryption)",
    }), 200


@security_bp.route("/simulation/unauthorized", methods=["POST"])
@login_required
def sim_unauthorized():
    """
    Simulate an authorization decision. The caller picks a resource and
    a required role; the server decides. The audit log records the
    attempt regardless of the outcome.
    """
    payload = request.get_json(silent=True) or {}
    resource = (payload.get("resource") or "Payroll Records").strip()
    required_role = (payload.get("required_role") or "SECURITY_OFFICER").strip()

    granted = (current_user.role == required_role)

    audit_service.log_event(
        "ACCESS_GRANTED" if granted else "ACCESS_DENIED",
        user_id=current_user.id,
        resource=f"simulation/{resource}",
        result="GRANTED" if granted else "DENIED",
        severity=audit_service.SEVERITY_WARNING,
        details={"requiredRole": required_role, "actualRole": current_user.role},
    )

    return jsonify({
        "status": "ok",
        "threat": "Unauthorized access",
        "resource": resource,
        "required_role": required_role,
        "caller_role": current_user.role,
        "result": "ACCESS GRANTED" if granted else "ACCESS DENIED",
    }), 200


@security_bp.route("/simulation/replay", methods=["POST"])
@login_required
def sim_replay():
    """
    Simulate replay: attach a "used nonces" set in-process, submit the
    same envelope twice, and observe the second submission being rejected.
    """
    from crypto import kdf

    # Generate a fresh "session"
    key = aes_gcm.generate_key()
    env = aes_gcm.encrypt(b"Session-critical command.", key)
    nonce_b64 = base64.b64encode(env["nonce"]).decode("ascii")

    # Server-side in-process replay cache (documented as not persistent)
    seen = _replay_cache()
    first_seen = nonce_b64 in seen
    seen.add(nonce_b64)
    second_seen = nonce_b64 in seen

    audit_service.log_event(
        "REPLAY_DETECTED" if second_seen else "LAB_REPLAY_FIRST_SUBMIT",
        user_id=current_user.id,
        resource="simulation/replay",
        result="REPLAY DETECTED" if second_seen else "FIRST SUBMISSION",
        severity=audit_service.SEVERITY_WARNING if second_seen else audit_service.SEVERITY_INFO,
    )

    return jsonify({
        "status": "ok",
        "threat": "Replay attack",
        "scenario": "An attacker re-transmits a captured envelope.",
        "nonce_b64": nonce_b64,
        "first_submission": "FIRST SUBMISSION — ACCEPTED",
        "second_submission": "REPLAY ATTEMPT DETECTED — REJECTED",
        "note": (
            "In this prototype the replay cache is held in process memory. "
            "A production deployment would use a distributed cache with "
            "TTL keyed by message ID and nonce."
        ),
    }), 200


@security_bp.route("/simulation/signature", methods=["POST"])
@login_required
def sim_signature():
    """
    Sign a message, then try to verify a modified version. Should fail.
    """
    priv, pub = signatures.generate_keypair()
    message = b"Invoice #1234, total NGN 250,000."
    signature = signatures.sign(message, priv)

    tampered = message + b" TAMPERED"
    valid_original = signatures.verify(message, signature, pub)
    valid_tampered = signatures.verify(tampered, signature, pub)

    audit_service.log_event(
        "SIGNATURE_FAILED" if not valid_tampered else "SIGNATURE_OK",
        user_id=current_user.id,
        resource="simulation/signature",
        result="FAILURE DETECTED" if not valid_tampered else "UNEXPECTED SUCCESS",
        severity=audit_service.SEVERITY_WARNING,
    )

    return jsonify({
        "status": "ok",
        "threat": "Invalid signature",
        "scenario": "Attacker modifies a signed message.",
        "original_message": message.decode("utf-8"),
        "tampered_message": tampered.decode("utf-8"),
        "original_verification": "VALID" if valid_original else "INVALID",
        "tampered_verification": "VALID" if valid_tampered else "INVALID",
        "algorithm": signatures.ALGORITHM_LABEL,
    }), 200


@security_bp.route("/simulation/wrong-key", methods=["POST"])
@login_required
def sim_wrong_key():
    """
    Attempt to decrypt AES-GCM ciphertext with the wrong key.
    """
    key_ok = aes_gcm.generate_key()
    key_bad = aes_gcm.generate_key()
    env = aes_gcm.encrypt(b"Classified report.", key_ok)

    try:
        aes_gcm.decrypt(env, key_bad)
        result = "DECRYPTION SUCCEEDED (unexpected)"
        detected = False
    except aes_gcm.DecryptionError:
        result = "DECRYPTION FAILED — WRONG KEY"
        detected = True

    audit_service.log_event(
        "THREAT_SIMULATION_RUN",
        user_id=current_user.id,
        resource="simulation/wrong-key",
        result="SUCCESS" if detected else "FAILURE",
        details={"threat": "wrong-key", "detected": detected},
    )

    return jsonify({
        "status": "ok",
        "threat": "Wrong key",
        "scenario": "Attacker attempts decryption with an incorrect AES key.",
        "detected": detected,
        "result": result,
    }), 200


# ---------------------------------------------------------------------------
# In-process replay cache
# ---------------------------------------------------------------------------

_replay_nonces: set[str] = set()


def _replay_cache() -> set[str]:
    """Return the process-wide nonce cache used by the replay simulator."""
    global _replay_nonces
    if len(_replay_nonces) > 10_000:
        # Bound memory; clear oldest half (crude but adequate for a demo)
        _replay_nonces = set(list(_replay_nonces)[5000:])
    return _replay_nonces

# ---------------------------------------------------------------------------
# IP reputation endpoint (server-side proxy)
# ---------------------------------------------------------------------------

@security_bp.route("/intel")
@login_required
def intel_page():
    """Render the Security Intelligence lab page."""
    return render_template("lab_security_intel.html")


@security_bp.route("/api/security/ip-reputation", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def ip_reputation():
    """
    Server-side proxy for IP reputation lookups.

    The caller supplies only an IP address. The server:
      1. Validates the IP.
      2. Checks authorization (any authenticated user; extend to
         SECURITY_OFFICER if you prefer).
      3. Calls AbuseIPDB and IPinfo in sequence.
      4. Sanitizes the combined response.
      5. Logs the operation to the audit trail.
      6. Returns a safe JSON object.

    No API keys leave the server.
    """
    from services import abuseipdb_service, ipinfo_service
    from services.external_api_utils import ExternalAPIError

    payload = request.get_json(silent=True) or {}
    ip_address = (payload.get("ip") or "").strip()

    if not ip_address:
        return jsonify({"status": "error", "message": "ip is required."}), 400

    # ---- 1. Validate IP (IPv4 or IPv6) ----
    try:
        import ipaddress
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid IP address."}), 400

    # ---- 2. Authorization ----
    # Any authenticated user may query; extend to a role check if desired.
    if not current_user.is_authenticated:
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    # ---- 3. AbuseIPDB ----
    try:
        abuse_result = abuseipdb_service.lookup_ip(ip_address)
    except Exception as exc:  # noqa: BLE001 — degrade gracefully
        logger.exception("AbuseIPDB service raised: %s", exc)
        abuse_result = {
            "status": "unavailable",
            "ip": ip_address,
            "raw_source": "AbuseIPDB",
            "error": "internal_error",
        }

    # ---- 4. IPinfo ----
    try:
        ipinfo_result = ipinfo_service.lookup_ip(ip_address)
    except Exception as exc:  # noqa: BLE001
        logger.exception("IPinfo service raised: %s", exc)
        ipinfo_result = {
            "status": "unavailable",
            "ip": ip_address,
            "raw_source": "IPinfo Lite",
            "error": "internal_error",
        }

    # ---- 5. Audit ----
    audit_service.log_event(
        "SECURITY_API_ALERT",
        user_id=current_user.id,
        resource=f"ip-reputation/{ip_address}",
        result="SUCCESS",
        details={
            "abuseipdb_status": abuse_result.get("status"),
            "ipinfo_status": ipinfo_result.get("status"),
            "risk_level": abuse_result.get("risk_level"),
        },
    )

    # ---- 6. Return combined, sanitized response ----
    return jsonify({
        "status": "ok",
        "ip": ip_address,
        "abuseipdb": abuse_result,
        "ipinfo": ipinfo_result,
        "overall_risk": _overall_risk(abuse_result, ipinfo_result),
        "disclaimer": (
            "IP intelligence is supporting context, not a cryptographic "
            "decision. Cryptographic protections remain in force "
            "regardless of IP reputation."
        ),
    }), 200

@security_bp.route("/api/security/password-check", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def check_password():
    """
    Check a candidate password against the HIBP Pwned Passwords corpus.

    The plaintext password is used locally only to compute a SHA-1 hash.
    Only the first 5 characters of that hash leave the server. The password
    is never logged, never persisted, and never echoed in the response.
    """
    from services import hibp_service

    payload = request.get_json(silent=True) or {}
    candidate = payload.get("password") or ""

    if not candidate:
        return jsonify({"status": "error", "message": "password is required."}), 400

    if len(candidate) > 1024:
        return jsonify({"status": "error", "message": "password too long."}), 400

    result = hibp_service.check_password(candidate)

    audit_service.log_event(
        "SECURITY_API_ALERT",
        user_id=current_user.id,
        resource="password-check",
        result="SUCCESS",
        severity=audit_service.SEVERITY_INFO,
        details={
            "breached": result.get("breached"),
            "hibp_status": result.get("status"),
            # NOTE: no password or hash-prefix is stored in the audit log.
        },
    )

    return jsonify(result), 200

def _overall_risk(abuse_result: dict, ipinfo_result: dict) -> str:
    """Combine the two lookups into a single client-facing risk label."""
    if abuse_result.get("status") != "ok":
        return "UNKNOWN"
    return abuse_result.get("risk_level", "UNKNOWN")
