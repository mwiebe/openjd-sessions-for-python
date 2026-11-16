# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The _v1 Session raises the openjd-sessions crate's refusal and offers
``clear_ending_only``, as the Rust Session does.

A failed action makes the session ending-only, even after
``exit_environment(keep_session_running=True)``. The crate then refuses
``run_task``; the wrapper must raise rather than report the call as started,
and must not fire a callback for an action that never ran.
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import pytest

from openjd._openjd_rs import create_environment, decode_environment_template, deserialize_step
from openjd.sessions._v1 import (
    ActionState,
    ActionStatus,
    Session,
    SessionRuntimeError,
    SessionState,
)


def _python(code: str) -> dict[str, Any]:
    return {"command": sys.executable, "args": ["-c", code]}


def _step_script(code: str) -> Any:
    return deserialize_step({"name": "S", "script": {"actions": {"onRun": _python(code)}}}).script


def _environment() -> Any:
    return create_environment(
        decode_environment_template(
            template={
                "specificationVersion": "environment-2023-09",
                "environment": {"name": "E", "script": {"actions": {"onEnter": _python("")}}},
            }
        )
    )


def _settle(session: Session, callbacks: Optional[list[ActionStatus]] = None) -> None:
    """Wait for the action to end and, given ``callbacks``, for the wrapper's
    polling thread to deliver its terminal callback."""
    deadline = time.monotonic() + 10
    while session.state == SessionState.RUNNING and time.monotonic() < deadline:
        time.sleep(0.02)
    assert session.state != SessionState.RUNNING, "action did not finish within 10s"
    if callbacks is not None:
        while time.monotonic() < deadline and (
            not callbacks or callbacks[-1].state == ActionState.RUNNING
        ):
            time.sleep(0.02)
        assert callbacks and callbacks[-1].state != ActionState.RUNNING


def test_a_refused_run_task_raises_and_clear_ending_only_recovers(tmp_path: Path) -> None:
    callbacks: list[ActionStatus] = []
    with Session(
        session_id=uuid.uuid4().hex,
        job_parameter_values={},
        session_root_directory=tmp_path,
        callback=lambda _id, status: callbacks.append(status),
    ) as session:
        identifier = session.enter_environment(environment=_environment())
        _settle(session, callbacks)
        session.run_task(step_script=_step_script("raise SystemExit(1)"), task_parameter_values={})
        _settle(session, callbacks)
        session.exit_environment(identifier=identifier, keep_session_running=True)
        _settle(session, callbacks)
        assert session.state == SessionState.READY_ENDING
        status = session.action_status
        assert status is not None and status.state == ActionState.SUCCESS

        seen = len(callbacks)
        entered = session.environments_entered
        with pytest.raises(SessionRuntimeError) as exc_info:
            session.run_task(step_script=_step_script(""), task_parameter_values={})
        assert str(exc_info.value) == "Session must be in READY state, current: READY_ENDING"
        assert session.action_status == status
        assert session.environments_entered == entered
        # A refused call starts no polling thread, so nothing can arrive.
        time.sleep(0.2)
        assert len(callbacks) == seen
        assert session.state == SessionState.READY_ENDING

        session.clear_ending_only()
        assert session.state == SessionState.READY
        session.run_task(step_script=_step_script(""), task_parameter_values={})
        _settle(session, callbacks)
        status = session.action_status
        assert status is not None and status.state == ActionState.SUCCESS
        assert callbacks[-1].state == ActionState.SUCCESS


def test_clear_ending_only_on_a_ready_session_raises(tmp_path: Path) -> None:
    with Session(
        session_id=uuid.uuid4().hex, job_parameter_values={}, session_root_directory=tmp_path
    ) as session:
        with pytest.raises(SessionRuntimeError) as exc_info:
            session.clear_ending_only()
        assert str(exc_info.value) == "Session must be in READY_ENDING state, current: READY"
        assert session.state == SessionState.READY
        assert session.action_status is None
        assert session.environments_entered == ()


@pytest.mark.parametrize(
    "timeout, error, message",
    [
        pytest.param(0, SessionRuntimeError, "timeout must be positive", id="zero"),
        pytest.param(
            -5,
            ValueError,
            "timeout must be a finite, non-negative number of seconds, got -5",
            id="negative",
        ),
    ],
)
def test_run_subprocess_timeout_is_checked(
    tmp_path: Path, timeout: int, error: type[Exception], message: str
) -> None:
    """``timeout=0`` reaches the crate, which refuses it. Before, the wrapper
    turned it into no timeout."""
    with Session(
        session_id=uuid.uuid4().hex, job_parameter_values={}, session_root_directory=tmp_path
    ) as session:
        with pytest.raises(error) as exc_info:
            session.run_subprocess(command=sys.executable, args=["-c", ""], timeout=timeout)
        assert str(exc_info.value) == message
        assert session.state == SessionState.READY
        assert session.action_status is None
        assert session.environments_entered == ()


def test_cancel_with_a_zero_time_limit_terminates_at_once(tmp_path: Path) -> None:
    """``timedelta(0)`` reaches the crate, which terminates at once instead of
    giving the action its notify-then-terminate grace period. Before, the
    wrapper turned it into no time limit."""
    from datetime import timedelta

    # Ignore the notify signal: SIGTERM on POSIX, CTRL_BREAK (SIGBREAK) on
    # Windows. Only a terminate then ends the task before the grace period.
    # The marker says the child is running with the signals ignored; a cancel
    # before that would end it at once whatever the time limit.
    marker = tmp_path / "started"
    ignore_term = (
        "import signal, time\n"
        "for name in ('SIGTERM', 'SIGBREAK'):\n"
        "    if hasattr(signal, name):\n"
        "        signal.signal(getattr(signal, name), signal.SIG_IGN)\n"
        f"open({str(marker)!r}, 'w').close()\n"
        "time.sleep(30)"
    )
    step = deserialize_step(
        {
            "name": "S",
            "script": {
                "actions": {
                    "onRun": {
                        **_python(ignore_term),
                        "cancelation": {
                            "mode": "NOTIFY_THEN_TERMINATE",
                            "notifyPeriodInSeconds": 20,
                        },
                    }
                }
            },
        }
    ).script
    with Session(
        session_id=uuid.uuid4().hex, job_parameter_values={}, session_root_directory=tmp_path
    ) as session:
        session.run_task(step_script=step, task_parameter_values={})
        wait_until = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < wait_until:
            time.sleep(0.02)
        assert marker.exists()
        began = time.monotonic()
        session.cancel_action(time_limit=timedelta(0))
        deadline = began + 10
        while (
            session.state in (SessionState.RUNNING, SessionState.CANCELING)
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        # Without the time limit the notify period would run first.
        assert time.monotonic() - began < 3
        status = session.action_status
        assert status is not None and status.state == ActionState.CANCELED
