"""Clean Python API module — should produce zero findings.

Demonstrates proper practices: type hints, parameterized queries,
environment-based secrets, specific exception handling, no eval/exec.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    """Represents a user in the system."""

    id: int
    name: str
    email: str
    active: bool = True


def get_database_url() -> str:
    """Load database URL from environment — never hardcode credentials."""
    return os.environ["DATABASE_URL"]


def find_user_by_id(cursor: object, user_id: int) -> Optional[User]:
    """Find a user by ID using parameterized queries.

    Args:
        cursor: Database cursor object.
        user_id: The user ID to look up.

    Returns:
        User if found, None otherwise.
    """
    query = "SELECT id, name, email, active FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))  # type: ignore[attr-defined]
    row = cursor.fetchone()  # type: ignore[attr-defined]
    if row is None:
        return None
    return User(id=row[0], name=row[1], email=row[2], active=row[3])


def validate_email(email: str) -> bool:
    """Validate an email address format.

    Args:
        email: The email string to validate.

    Returns:
        True if the email has a valid format.
    """
    if not email or "@" not in email:
        return False
    local, domain = email.rsplit("@", 1)
    return len(local) > 0 and "." in domain


def process_users(users: list[User]) -> dict[str, int]:
    """Compute summary statistics for a list of users.

    Args:
        users: List of User objects.

    Returns:
        Dictionary with 'total', 'active', and 'inactive' counts.
    """
    active_count = sum(1 for u in users if u.active)
    return {
        "total": len(users),
        "active": active_count,
        "inactive": len(users) - active_count,
    }
