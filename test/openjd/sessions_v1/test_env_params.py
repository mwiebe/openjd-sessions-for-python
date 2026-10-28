# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""ENV_PARAMS (RFC 0010, draft) through the Rust-backed ``openjd.sessions._v1``.

``support_files/env_params/`` holds conformance job tests copied from
openjd-specifications (``conformance-tests/2023-09/ENV_PARAMS/jobs/``). When the
specification checkout is present at ``OPENJD_SPECIFICATIONS_DIR`` (or the
sibling ``../openjd-specifications-ep``), ``TestConformanceSuite`` runs every
ENV_PARAMS job test of that suite too.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from openjd.expr import SerializedSymbolTable
from openjd.model._v1 import create_job, decode_job_template
from openjd.sessions._v1 import (
    ActionState,
    EnvironmentParameterValues,
    Session,
    SessionRuntimeError,
    SessionState,
)

from .env_params_conformance import check_expectations, run_conformance_job, should_run

_HERE = Path(__file__).parent
_COPIES = _HERE / "support_files" / "env_params"
_QUIESCENT = {SessionState.READY, SessionState.ENDED, SessionState.READY_ENDING}


def _spec_suite() -> Path | None:
    configured = os.environ.get("OPENJD_SPECIFICATIONS_DIR")
    candidates = [Path(configured)] if configured else []
    candidates.append(_HERE.parents[3] / "openjd-specifications-ep")
    for c in candidates:
        jobs = c / "conformance-tests" / "2023-09" / "ENV_PARAMS" / "jobs"
        if jobs.is_dir():
            return jobs
    return None


_SUITE = _spec_suite()


def _run_file(path: Path, tmp_path: Path) -> None:
    test = yaml.safe_load(path.read_text())
    if not should_run(test):
        pytest.skip(f"runOn {test.get('runOn')}")
    result = run_conformance_job(test, tmp_path)
    check_expectations(test, ".invalid." in path.name, result)


class TestConformanceCopies:
    @pytest.mark.parametrize(
        "path", sorted(_COPIES.glob("*.test.yaml")), ids=lambda p: p.name.split(".test.")[0]
    )
    def test_job(self, path: Path, tmp_path: Path) -> None:
        _run_file(path, tmp_path)


@pytest.mark.skipif(_SUITE is None, reason="openjd-specifications ENV_PARAMS suite not found")
class TestConformanceSuite:
    @pytest.mark.parametrize(
        "path",
        sorted(_SUITE.glob("*.yaml")) if _SUITE else [],
        ids=lambda p: p.name.split(".test.")[0],
    )
    def test_job(self, path: Path, tmp_path: Path) -> None:
        _run_file(path, tmp_path)


# ── Session.enter_environment(parameters=...) directly ──

_TEMPLATE: dict[str, Any] = {
    "specificationVersion": "jobtemplate-2023-09",
    "extensions": ["ENV_PARAMS", "EXPR"],
    "name": "J",
    "jobEnvironments": [
        {
            "name": "Tool",
            "envParameterDefinitions": [
                {"name": "Flavor", "type": "STRING", "default": "plain"},
                {"name": "Dir", "type": "PATH", "default": "/src/data"},
            ],
            "variables": {"TOOL_FLAVOR": "{{Env.Param.Flavor}}"},
            "script": {
                "actions": {
                    "onEnter": {
                        "command": "echo",
                        "args": ["ENTER", "{{Env.Param.Flavor}}", "{{Env.Param.Dir}}"],
                    },
                    "onExit": {
                        "command": "echo",
                        "args": ["EXIT", "{{Env.Param.Flavor}}", "{{Env.RawParam.Dir}}"],
                    },
                }
            },
        }
    ],
    "steps": [
        {
            "name": "S",
            "dependencies": [{"environment": "Tool", "parameters": {"Flavor": "red"}}],
            "script": {"actions": {"onRun": {"command": "echo", "args": ["TASK"]}}},
        }
    ],
}


def _wait(session: Session) -> None:
    deadline = time.monotonic() + 30
    while session.state not in _QUIESCENT:
        assert time.monotonic() < deadline, "action did not finish"
        time.sleep(0.005)


@pytest.fixture
def job() -> Any:
    jt = decode_job_template(template=_TEMPLATE, supported_extensions=["ENV_PARAMS", "EXPR"])
    return create_job(job_template=jt, job_parameter_values={})


@pytest.mark.skipif(os.name == "nt", reason="POSIX echo and paths")
class TestEnterEnvironmentWithParameters:
    def test_values_bound_for_enter_and_exit(
        self, job: Any, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.INFO)
        from openjd.sessions._v1 import PathMappingRule

        rules = [
            PathMappingRule.from_dict(
                {"source_path_format": "POSIX", "source_path": "/src", "destination_path": "/dst"}
            )
        ]
        step = job.steps[0]
        env = job.job_environments[0]
        values = step.environment_parameters_for("Tool")
        assert values is not None
        with Session(
            session_id="s",
            job_parameter_values={},
            path_mapping_rules=rules,
            session_root_directory=tmp_path,
        ) as session:
            eid = session.enter_environment(
                environment=env, resolved_symtab=env.resolved_symtab, parameters=values
            )
            _wait(session)
            assert session.action_status is not None
            assert session.action_status.state == ActionState.SUCCESS
            stored = session.environment_parameters(eid)
            assert stored == values
            session.run_task(
                step_script=step.script,
                task_parameter_values={},
                resolved_symtab=step.resolved_symtab,
            )
            _wait(session)
            session.exit_environment(identifier=eid, resolved_symtab=env.resolved_symtab)
            _wait(session)
            assert session.environment_parameters(eid) is None
        messages = "\n".join(caplog.messages)
        # Env.Param.Dir is path-mapped; Env.RawParam.Dir is not.
        assert "ENTER red /dst/data" in messages
        assert "EXIT red /src/data" in messages

    def test_mismatched_environment_raises_before_running(self, job: Any, tmp_path: Path) -> None:
        env = job.job_environments[0]
        other = EnvironmentParameterValues(
            environment="Other",
            values=SerializedSymbolTable.from_json_str(
                '[{"name":"Flavor","type":"string","value":"x"}]'
            ),
        )
        with Session(
            session_id="s", job_parameter_values={}, session_root_directory=tmp_path
        ) as session:
            with pytest.raises(SessionRuntimeError) as exc:
                session.enter_environment(environment=env, parameters=other)
            assert str(exc.value) == (
                "Environment 'Tool': invalid Environment parameter values: "
                "the values are for Environment 'Other'."
            )
            assert session.state == SessionState.READY
            assert session.environments_entered == ()

    def test_unbindable_table_fails_the_action(self, job: Any, tmp_path: Path) -> None:
        env = job.job_environments[0]
        dotted = EnvironmentParameterValues(
            environment="Tool",
            values=SerializedSymbolTable.from_json_str(
                json.dumps([{"name": "Env.Param.Flavor", "type": "string", "value": "x"}])
            ),
        )
        statuses: list[Any] = []
        with Session(
            session_id="s",
            job_parameter_values={},
            session_root_directory=tmp_path,
            callback=lambda _sid, status: statuses.append(status),
        ) as session:
            # A first action that succeeds, so a stale SUCCESS would show.
            session.run_subprocess(command="true")
            _wait(session)
            assert session.action_status is not None
            assert session.action_status.state == ActionState.SUCCESS
            # Like the worker agent, wait for the action's terminal callback
            # before starting the next one: each action has its own poll
            # thread, and an earlier one may otherwise deliver late.
            deadline = time.monotonic() + 5
            while (not statuses or statuses[-1].state != ActionState.SUCCESS) and (
                time.monotonic() < deadline
            ):
                time.sleep(0.01)
            assert statuses[-1].state == ActionState.SUCCESS
            del statuses[:]

            session.enter_environment(environment=env, parameters=dotted)
            _wait(session)
            status = session.action_status
            assert status is not None
            assert status.state == ActionState.FAILED
            assert status.fail_message == (
                "Environment 'Tool': invalid Environment parameter values: 'Env.Param.Flavor' is not a "
                "parameter name; each entry must be keyed by the bare name."
            )
            assert session.state == SessionState.READY
            assert session.environments_entered == ()
        deadline = time.monotonic() + 5
        while (not statuses or statuses[-1].state != ActionState.FAILED) and (
            time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert [st.state for st in statuses] == [ActionState.RUNNING, ActionState.FAILED]
        assert statuses[-1].fail_message == status.fail_message

    def test_unbindable_table_as_first_action(self, job: Any, tmp_path: Path) -> None:
        # No earlier action: the status must still become FAILED, not stay None.
        env = job.job_environments[0]
        untyped = EnvironmentParameterValues(
            environment="Tool",
            values=SerializedSymbolTable.from_json_str('[{"name":"Flavor","value":"x"}]'),
        )
        with Session(
            session_id="s", job_parameter_values={}, session_root_directory=tmp_path
        ) as session:
            assert session.action_status is None
            session.enter_environment(environment=env, parameters=untyped)
            _wait(session)
            status = session.action_status
            assert status is not None
            assert status.state == ActionState.FAILED
            assert status.fail_message == (
                "Environment 'Tool': invalid Environment parameter values: parameter 'Flavor' "
                "has no string 'type'."
            )

    def test_terminal_state_never_shows_a_stale_status(self, job: Any, tmp_path: Path) -> None:
        # Repeats the refused enter many times and reads state and status the
        # way the Python poller does (state first, then status), checking the
        # status is never the previous action's SUCCESS once the state is
        # terminal.
        env = job.job_environments[0]
        dotted = EnvironmentParameterValues(
            environment="Tool",
            values=SerializedSymbolTable.from_json_str(
                '[{"name":"Env.Param.Flavor","type":"string","value":"x"}]'
            ),
        )
        with Session(
            session_id="s", job_parameter_values={}, session_root_directory=tmp_path
        ) as session:
            for _ in range(50):
                session.run_subprocess(command="true")
                _wait(session)
                session.enter_environment(environment=env, parameters=dotted)
                while session.state not in _QUIESCENT:
                    pass
                status = session.action_status
                assert status is not None and status.state == ActionState.FAILED

    def test_without_parameters_env_param_is_undefined(self, job: Any, tmp_path: Path) -> None:
        env = job.job_environments[0]
        with Session(
            session_id="s", job_parameter_values={}, session_root_directory=tmp_path
        ) as session:
            eid = session.enter_environment(environment=env, resolved_symtab=env.resolved_symtab)
            _wait(session)
            status = session.action_status
            assert status is not None
            assert status.state == ActionState.FAILED
            assert session.environment_parameters(eid) is None
