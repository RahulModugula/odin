"""User management module with clean, well-documented code."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    """Represents a user in the system."""
    id: int
    name: str
    email: str
    active: bool = True


def find_user_by_email(users: list[User], email: str) -> Optional[User]:
    """Find a user by their email address.

    Args:
        users: List of users to search through.
        email: Email address to search for.

    Returns:
        The matching User, or None if not found.
    """
    for user in users:
        if user.email == email and user.active:
            return user
    return None


def deactivate_user(user: User) -> User:
    """Mark a user as inactive.

    Args:
        user: The user to deactivate.

    Returns:
        The updated user with active=False.
    """
    user.active = False
    return user
