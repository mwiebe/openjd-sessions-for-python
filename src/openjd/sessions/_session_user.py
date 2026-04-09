# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""Session user types — thin wrappers over Rust implementations."""

from typing import Optional

from openjd._openjd_rs import PosixSessionUser

__all__ = (
    "PosixSessionUser",
    "SessionUser",
    "WindowsSessionUser",
    "BadCredentialsException",
)


class BadCredentialsException(Exception):
    """Exception raised for incorrect username or password."""
    pass


# Abstract base for type checking — both Rust types satisfy this interface
SessionUser = PosixSessionUser  # TODO: Union[PosixSessionUser, WindowsSessionUser] when Windows bindings added


class WindowsSessionUser:
    """Placeholder — Windows bindings not yet exposed through Rust.
    Will be replaced with Rust WindowsSessionUser when available."""

    def __init__(self, user: str, *, password: Optional[str] = None, logon_token=None):
        raise RuntimeError("WindowsSessionUser Rust bindings not yet available on this platform")
