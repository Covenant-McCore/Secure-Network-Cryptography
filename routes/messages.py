"""
routes/messages.py
------------------
Secure messaging UI and action endpoints.
"""

import logging

from flask import (
    Blueprint, abort, flash, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

from crypto.message_envelope import (
    DecryptionFailure,
    SignatureVerificationError,
)
from services import audit_service, message_service


logger = logging.getLogger(__name__)

messages_bp = Blueprint("messages", __name__, url_prefix="/messages")


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

@messages_bp.route("/")
@login_required
def index():
    tab = request.args.get("tab", "inbox")
    if tab == "sent":
        items = message_service.list_sent(current_user.id)
    else:
        tab = "inbox"
        items = message_service.list_inbox(current_user.id)
    return render_template("messages_list.html", tab=tab, items=items)


# ---------------------------------------------------------------------------
# Compose
# ---------------------------------------------------------------------------

@messages_bp.route("/new", methods=["GET", "POST"])
@login_required
def compose():
    recipients = message_service.list_eligible_recipients(current_user.id)

    if request.method == "POST":
        recipient_id = (request.form.get("recipient_id") or "").strip()
        subject = (request.form.get("subject") or "").strip()
        body = (request.form.get("body") or "").strip()

        if not recipient_id or not subject or not body:
            flash("Recipient, subject, and body are all required.", "warning")
            return render_template(
                "messages_compose.html",
                recipients=recipients,
                form=request.form,
            ), 400

        try:
            message_id = message_service.send_message(
                sender_id=current_user.id,
                sender_attributes=current_user.attributes,
                recipient_id=recipient_id,
                organization_id=current_user.organization_id,
                subject=subject,
                body=body,
            )
        except message_service.RecipientNotFound:
            flash("Recipient not found.", "danger")
            return render_template(
                "messages_compose.html",
                recipients=recipients,
                form=request.form,
            ), 400
        except message_service.RecipientKeyMissing:
            flash("Recipient's keys are unavailable. Contact your administrator.",
                  "danger")
            return render_template(
                "messages_compose.html",
                recipients=recipients,
                form=request.form,
            ), 400
        except message_service.MessageServiceError as exc:
            logger.exception("send_message failed: %s", exc)
            flash("Could not send the message. Please try again.", "danger")
            return render_template(
                "messages_compose.html",
                recipients=recipients,
                form=request.form,
            ), 500

        flash(
            "Message sealed: ML-KEM-768 key established, AES-256-GCM ciphertext "
            "created, Ed25519 signature applied.",
            "success",
        )
        return redirect(url_for("messages.view_sent", message_id=message_id))

    return render_template(
        "messages_compose.html",
        recipients=recipients,
        form={},
    )


# ---------------------------------------------------------------------------
# Recipient view
# ---------------------------------------------------------------------------

@messages_bp.route("/<message_id>")
@login_required
def view(message_id: str):
    msg = message_service.get_message(message_id)
    if msg is None:
        abort(404)

    # Enforce recipient-only access to the interactive view.
    if msg["recipientId"] != current_user.id:
        audit_service.access_denied(
            user_id=current_user.id,
            resource=f"message/{message_id}",
            reason="not the recipient",
        )
        abort(403)

    # Sender display name (best-effort; do not leak email addresses).
    from services import auth_service
    sender = auth_service.get_user(msg["senderId"]) or {}
    sender_display = sender.get("fullName") or msg["senderId"]

    return render_template(
        "messages_view.html",
        message=msg,
        sender_display=sender_display,
        plaintext=None,
    )


@messages_bp.route("/<message_id>/decrypt", methods=["POST"])
@login_required
def decrypt(message_id: str):
    user_dict = {"userId": current_user.id}
    try:
        plaintext = message_service.decrypt_message(message_id, user_dict)
    except message_service.NotAuthorizedToRead:
        abort(403)
    except SignatureVerificationError:
        flash(
            "Signature verification FAILED. The message may have been tampered "
            "with, and was not decrypted. This event has been logged.",
            "danger",
        )
        return redirect(url_for("messages.view", message_id=message_id))
    except DecryptionFailure:
        flash(
            "Decryption FAILED. The ciphertext failed AES-GCM authentication. "
            "This event has been logged.",
            "danger",
        )
        return redirect(url_for("messages.view", message_id=message_id))
    except message_service.MessageServiceError as exc:
        logger.exception("decrypt failed: %s", exc)
        flash("Could not decrypt the message.", "danger")
        return redirect(url_for("messages.view", message_id=message_id))

    msg = message_service.get_message(message_id)
    from services import auth_service
    sender = auth_service.get_user(msg["senderId"]) or {}
    sender_display = sender.get("fullName") or msg["senderId"]

    return render_template(
        "messages_view.html",
        message=msg,
        sender_display=sender_display,
        plaintext=plaintext,
    )


# ---------------------------------------------------------------------------
# Sender view (ciphertext only, no decrypt button)
# ---------------------------------------------------------------------------

@messages_bp.route("/<message_id>/sent")
@login_required
def view_sent(message_id: str):
    msg = message_service.get_message(message_id)
    if msg is None:
        abort(404)

    if msg["senderId"] != current_user.id:
        audit_service.access_denied(
            user_id=current_user.id,
            resource=f"message/{message_id}",
            reason="not the sender",
        )
        abort(403)

    from services import auth_service
    recipient = auth_service.get_user(msg["recipientId"]) or {}
    recipient_display = recipient.get("fullName") or msg["recipientId"]

    return render_template(
        "messages_sent_detail.html",
        message=msg,
        recipient_display=recipient_display,
    )
