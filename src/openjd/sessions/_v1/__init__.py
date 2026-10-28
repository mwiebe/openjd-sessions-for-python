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

# ENV_PARAMS (RFC 0010, draft): the values passed to
# ``Session.enter_environment(parameters=...)``.
from openjd.model._v1.job import EnvironmentParameterValues

# Rust-backed types
from openjd._openjd_rs import (
    ScriptRunnerState,
    ActionResult,
    SessionError as SessionRuntimeError,
)

# Note: the `__module__` / `__name__` / `__qualname__` of the Rust-backed
# exceptions (SessionError, BadCredentialsException) are set by the
# `_openjd_rs` module init in Rust to their canonical user-facing values
# (e.g. `openjd.sessions._v1.SessionError`). No Python-side fix-up needed.

__all__ = (
    "ActionState",
    "ActionStatus",
    "ActionResult",
    "EnvironmentIdentifier",
    "EnvironmentModel",
    "EnvironmentParameterValues",
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
