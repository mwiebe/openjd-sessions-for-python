# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""Open Job Description Session — thin wrapper over Rust implementation."""

import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from openjd._openjd_rs import (
    Session as _RustSession,
    SessionState,
    ActionState,
    ActionStatus,
    PathMappingRule,
)
from openjd.model.v1 import (
    ParameterValue,
    RevisionExtensions,
    SpecificationRevision,
)

from ._session_user import SessionUser
from ._types import (
    EnvironmentIdentifier,
    EnvironmentModel,
    StepScriptModel,
)

# Bridge Rust logging (openjd_sessions) to Python logging (openjd.sessions).
# pyo3-log sends Rust log records to Python logger "openjd_sessions" (underscore),
# but the CLI/worker attach handlers to "openjd.sessions" (dot). We redirect by
# adding the Python logger's handlers to the Rust logger.
import logging as _logging
_rust_logger = _logging.getLogger("openjd_sessions")
_py_logger = _logging.getLogger("openjd.sessions")
_rust_logger.parent = _py_logger
_rust_logger.setLevel(_logging.DEBUG)

SessionCallbackType = Callable[[str, ActionStatus], None]

__all__ = [
    "ActionStatus",
    "Session",
    "SessionCallbackType",
    "SessionState",
]

JobParameterValues = dict[str, ParameterValue]
TaskParameterSet = dict[str, Any]


class Session:
    """A context for running actions of an Open Job Description Job."""

    _rust_session: _RustSession
    _callback: Optional[SessionCallbackType]
    _session_id: str

    def __init__(
        self,
        *,
        session_id: str,
        job_parameter_values: JobParameterValues,
        path_mapping_rules: Optional[list[PathMappingRule]] = None,
        retain_working_dir: bool = False,
        user: Optional[SessionUser] = None,
        callback: Optional[SessionCallbackType] = None,
        os_env_vars: Optional[dict[str, str]] = None,
        session_root_directory: Optional[Path] = None,
        revision_extensions: RevisionExtensions = RevisionExtensions(
            spec_rev=SpecificationRevision.v2023_09, supported_extensions=[]
        ),
    ):
        self._session_id = session_id
        self._callback = callback

        # Convert ParameterValue dicts to {name: {type: str, value: ...}} for Rust
        rust_params = {}
        if job_parameter_values:
            for name, pv in job_parameter_values.items():
                rust_params[name] = {"type": pv.type.as_str(), "value": pv.value}

        self._rust_session = _RustSession(
            session_id=session_id,
            job_parameter_values=rust_params,
            path_mapping_rules=path_mapping_rules,
            retain_working_dir=retain_working_dir,
            os_env_vars=os_env_vars,
            session_root_directory=str(session_root_directory) if session_root_directory else None,
            user=user,
        )

    def _poll_for_completion(self):
        """Watch the Rust session and fire callbacks as the action transitions.

        Mirrors the v0 (Pydantic) Session's callback contract: exactly two
        callback invocations per action — one when it starts RUNNING, and one
        when it ends (state != RUNNING). The caller (the worker agent) holds a
        map from action-id to current_action and mutates state on each fire;
        double-firing the same state breaks that map and trips assertion
        errors in the agent's `_action_updated_impl`.

        We guard against:
          1. Racing between action start and this poll loop — the Rust session
             may already be back to READY by the time we enter the loop if the
             subprocess ran in < 10ms. In that case we still need to report the
             terminal status exactly once.
          2. Stale callbacks from previous actions — each call to a run_*
             method starts a fresh poll thread; we only observe the session's
             current action_status.
        """
        def _poll():
            reported_running = False
            # Phase 1: observe RUNNING at least once, then wait for transition.
            while True:
                state = self._rust_session.state
                status = self._rust_session.action_status
                if state == SessionState.RUNNING:
                    if not reported_running and status is not None:
                        reported_running = True
                        if self._callback:
                            self._callback(self._session_id, status)
                    time.sleep(0.01)
                    continue
                # Not RUNNING anymore — action is done.
                # If we never saw RUNNING (e.g. Rust finished before we got here),
                # still report the RUNNING transition first, so the agent state
                # machine sees Start → End in order.
                if not reported_running and status is not None and self._callback:
                    # Fabricate a RUNNING status so the agent registers the
                    # action before we deliver its terminal status.
                    running_status = ActionStatus(
                        state=ActionState.RUNNING,
                        exit_code=None,
                        fail_message=None,
                        progress=status.progress,
                        status_message=status.status_message,
                    )
                    self._callback(self._session_id, running_status)
                    reported_running = True
                # Report terminal state.
                if status is not None and self._callback:
                    self._callback(self._session_id, status)
                return

        t = threading.Thread(target=_poll, daemon=True)
        t.start()

    @property
    def working_directory(self) -> Path:
        return Path(self._rust_session.working_directory)

    @property
    def files_directory(self) -> Path:
        return Path(self._rust_session.files_directory)

    @property
    def state(self) -> SessionState:
        return self._rust_session.state

    @property
    def action_status(self) -> Optional[ActionStatus]:
        return self._rust_session.action_status

    @property
    def environments_entered(self) -> tuple[EnvironmentIdentifier, ...]:
        return tuple(self._rust_session.environments_entered)

    def cancel_action(
        self, *, time_limit=None, mark_action_failed=False
    ) -> None:
        seconds = time_limit.total_seconds() if time_limit else None
        self._rust_session.cancel_action(seconds, mark_action_failed)

    def enter_environment(
        self,
        *,
        environment: EnvironmentModel,
        identifier: Optional[EnvironmentIdentifier] = None,
        os_env_vars: Optional[dict[str, str]] = None,
        resolved_bindings: Optional[list[dict[str, Any]]] = None,
    ) -> EnvironmentIdentifier:
        eid = self._rust_session.enter_environment(
            environment=environment,
            identifier=identifier,
            os_env_vars=os_env_vars,
        )
        self._poll_for_completion()
        return eid

    def exit_environment(
        self,
        *,
        identifier: EnvironmentIdentifier,
        os_env_vars: Optional[dict[str, str]] = None,
        keep_session_running: bool = True,
        resolved_bindings: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        self._rust_session.exit_environment(
            identifier=identifier,
            keep_session_running=keep_session_running,
            os_env_vars=os_env_vars,
        )
        self._poll_for_completion()

    def run_task(
        self,
        *,
        step_script: StepScriptModel,
        task_parameter_values: TaskParameterSet,
        os_env_vars: Optional[dict[str, str]] = None,
        log_task_banner: bool = True,
        resolved_bindings: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        rust_task_params = None
        if task_parameter_values:
            rust_task_params = {}
            for name, pv in task_parameter_values.items():
                if hasattr(pv, 'type') and hasattr(pv, 'value'):
                    rust_task_params[name] = {"type": pv.type.as_str(), "value": pv.value}
                else:
                    rust_task_params[name] = {"type": "STRING", "value": str(pv)}

        self._rust_session.run_task(
            step_script=step_script,
            task_parameter_values=rust_task_params,
            os_env_vars=os_env_vars,
        )
        self._poll_for_completion()

    def run_subprocess(
        self,
        *,
        command: str,
        args: Optional[list[str]] = None,
        timeout: Optional[int] = None,
        os_env_vars: Optional[dict[str, str]] = None,
        use_session_env_vars: bool = True,
        log_banner_message: Optional[str] = None,
    ) -> None:
        self._rust_session.run_subprocess(
            command=command,
            args=args,
            timeout=float(timeout) if timeout else None,
            os_env_vars=os_env_vars,
            use_session_env_vars=use_session_env_vars,
            log_banner_message=log_banner_message,
        )
        self._poll_for_completion()

    def cleanup(self) -> None:
        self._rust_session.cleanup()

    def extend_path_mapping_rules(
        self, additional: list[PathMappingRule]
    ) -> None:
        """Append additional path mapping rules to this session's rule set.

        Forwards to the Rust Session.extend_path_mapping_rules, which re-sorts
        rules by source-path length (longest first) so the most specific rule
        matches first during FormatString resolution.

        Consumers like the Deadline Cloud worker agent call this between
        actions — after an assigned action delivers per-storage-profile or
        per-attachment path mappings — to extend the rules set up at session
        construction time.

        Raises
        ------
        RuntimeError
            If an action is currently in-flight. Call between actions only.
        """
        self._rust_session.extend_path_mapping_rules(additional)

    def get_enabled_extensions(self) -> list[str]:
        return []

    def __del__(self):
        self.cleanup()
