# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

from ._logging import LOG, LogContent
from ._path_mapping import PathFormat, PathMappingRule
from ._session import ActionStatus, Session, SessionCallbackType, SessionState
from ._session_user import (
    PosixSessionUser,
    SessionUser,
    WindowsSessionUser,
    BadCredentialsException,
)
from ._types import (
    ActionState,
    EnvironmentIdentifier,
    EnvironmentModel,
    EnvironmentScriptModel,
    StepScriptModel,
)
from .._version import version

# Rust-backed types
from openjd._openjd_rs import (
    ScriptRunnerState,
    ActionResult,
    SessionError as SessionRuntimeError,
)

# PyO3's create_exception! macro cannot accept a dotted module path, so
# SessionError otherwise reports `_openjd_rs.PySessionError`. Fix it up so
# repr / pickle / traceback report its canonical user-facing home.
SessionRuntimeError.__module__ = "openjd.sessions.v1"
if SessionRuntimeError.__name__.startswith("Py"):
    SessionRuntimeError.__name__ = SessionRuntimeError.__name__[2:]
    SessionRuntimeError.__qualname__ = SessionRuntimeError.__name__

__all__ = (
    "ActionState",
    "ActionStatus",
    "ActionResult",
    "EnvironmentIdentifier",
    "EnvironmentModel",
    "EnvironmentScriptModel",
    "LOG",
    "LogContent",
    "PathFormat",
    "PathMappingRule",
    "PosixSessionUser",
    "ScriptRunnerState",
    "Session",
    "SessionCallbackType",
    "SessionRuntimeError",
    "SessionState",
    "SessionUser",
    "StepScriptModel",
    "WindowsSessionUser",
    "BadCredentialsException",
    "version",
)
