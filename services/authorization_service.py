"""
services/authorization_service.py
---------------------------------
Server-side role-based access control.

CRITICAL DESIGN RULE
--------------------
Every protected backend endpoint MUST independently check authorization.
Hiding a button in the frontend is not access control. OWASP API Security
Top 10 2023 #1 is Broken Object Level Authorization (BOLA) and #5 is
Broken Function Level Authorization (BFLA); both are prevented here by
enforcing on the server, per request, with the actual resource owner.
"""

from functools import wraps
from typing import Callable, Iterable, Optional

from flask import abort, current_app
from flask_login import current_user

from config import Config
from services import audit_service


# ---------------------------------------------------------------------------
# Role / clearance checks
# ---------------------------------------------------------------------------

def user_has_role(user: dict, role: str) -> bool:
    return user.get("role") == role


def user_has_any_role(user: dict, roles: Iterable[str]) -> bool:
    return user.get("role") in set(roles)


def user_meets_clearance(user: dict, required: str) -> bool:
    user_level = Config.CLEARANCE_LEVELS.get(user.get("clearanceLevel", "PUBLIC"), -1)
    required_level = Config.CLEARANCE_LEVELS.get(required, 99)
    return user_level >= required_level


def user_in_organization(user: dict, organization_id: str) -> bool:
    return user.get("organizationId") == organization_id


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_role(*roles: str) -> Callable:
    """
    Decorator: only allow the request if the authenticated user's role is
    one of the given roles.

    Usage:
        @require_role("ADMINISTRATOR")
        @require_role("SECURITY_OFFICER", "ADMINISTRATOR")
    """
    allowed = set(roles)
    if not allowed:
        raise ValueError("require_role must be given at least one role.")

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                # 401 distinguishes unauthenticated from unauthorized.
                abort(401)
            if current_user.role not in allowed:
                audit_service.access_denied(
                    user_id=current_user.id,
                    resource=view.__name__,
                    reason=f"role '{current_user.role}' not in {sorted(allowed)}",
                )
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def require_clearance(min_level: str) -> Callable:
    """
    Decorator: only allow the request if the user's clearance is >= min_level.
    """
    if min_level not in Config.CLEARANCE_LEVELS:
        raise ValueError(f"Unknown clearance level: {min_level}")
    required = Config.CLEARANCE_LEVELS[min_level]

    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            user_level = Config.CLEARANCE_LEVELS.get(
                current_user.clearance_level, -1
            )
            if user_level < required:
                audit_service.access_denied(
                    user_id=current_user.id,
                    resource=view.__name__,
                    reason=f"clearance {current_user.clearance_level} < {min_level}",
                )
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def require_ownership(get_owner_id: Callable[[], Optional[str]]) -> Callable:
    """
    Decorator factory for object-level authorization (BOLA prevention).

    The view must call `get_owner_id()` — typically by reading an ID from
    the URL or request — and return the owner's userId. If the authenticated
    user is neither the owner nor an ADMINISTRATOR, the request is denied.

    Usage:
        @require_ownership(lambda: get_message_sender(request.view_args['mid']))
        def read_message(mid): ...
    """
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            owner_id = get_owner_id()
            if owner_id is None:
                abort(404)
            if current_user.id != owner_id and current_user.role != "ADMINISTRATOR":
                audit_service.access_denied(
                    user_id=current_user.id,
                    resource=view.__name__,
                    reason="not resource owner",
                )
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator
