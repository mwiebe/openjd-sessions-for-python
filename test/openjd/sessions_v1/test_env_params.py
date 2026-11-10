# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""ENV_PARAMS (RFC 0010, draft) through the Rust-backed ``openjd.sessions._v1``.

``support_files/env_params/`` holds conformance job tests copied from
openjd-specifications (``conformance-tests/2023-09/ENV_PARAMS/jobs/``). When the
specification checkout is present at ``OPENJD_SPECIFICATIONS_DIR`` (or the
sibling ``../openjd-specifications-ep``), ``TestConformanceSuite`` runs every
ENV_PARAMS job test of that suite too.
"""

from __future__ import annotations

import gc
import json
import logging
import os
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from openjd.expr import SerializedSymbolTable
from openjd.model._v1 import create_job, decode_job_template
from openjd.model._v1.errors import ModelValidationError
from openjd.model._v1.types import JobParameterType, JobParameterValue
from openjd.sessions._v1 import (
    ActionState,
    EnvironmentParameterValues,
    Session,
    SessionRuntimeError,
    SessionState,
)

from .env_params_conformance import (
    RunResult,
    check_expectations,
    run_conformance_job,
    should_run,
)

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


_ECHO_TASK: dict[str, Any] = {"actions": {"onRun": {"command": "echo", "args": ["TASK"]}}}


class TestCheckExpectations:
    """The conformance harness's own checks, each branch of
    ``check_expectations``, so a weakened check fails here even where no
    conformance file uses the branch."""

    _OK = RunResult(output="ENTER Mnt Dir=/d\nTASK A")

    def test_a_matching_run_passes(self) -> None:
        check_expectations({"expected": {"output": ["ENTER Mnt Dir=/d"]}}, False, self._OK)

    def test_missing_expected_output_fails(self) -> None:
        with pytest.raises(AssertionError, match="missing expected output 'ENTER Mnt Dir=/x'"):
            check_expectations({"expected": {"output": ["ENTER Mnt Dir=/x"]}}, False, self._OK)

    def test_missing_any_of_output_fails(self) -> None:
        with pytest.raises(AssertionError, match="missing {'anyOf'"):
            check_expectations(
                {"expected": {"output": [{"anyOf": ["nope", "neither"]}]}}, False, self._OK
            )

    def test_any_of_output_needs_only_one_alternative(self) -> None:
        check_expectations(
            {"expected": {"output": [{"anyOf": ["nope", "TASK A"]}]}}, False, self._OK
        )

    @pytest.mark.skipif(os.name == "nt", reason="the _posix keys")
    def test_per_os_output_and_forbidden(self) -> None:
        with pytest.raises(AssertionError, match="missing expected output 'other'"):
            check_expectations({"expected": {"output_posix": ["other"]}}, False, self._OK)
        with pytest.raises(AssertionError, match="found forbidden output 'TASK A'"):
            check_expectations({"expected": {"forbidden_posix": ["TASK A"]}}, False, self._OK)

    def test_forbidden_output_fails(self) -> None:
        with pytest.raises(AssertionError, match="found forbidden output 'TASK A'"):
            check_expectations({"expected": {"forbidden": ["TASK A"]}}, False, self._OK)

    def test_an_invalid_test_that_succeeds_fails(self) -> None:
        with pytest.raises(AssertionError, match="expected the run to fail"):
            check_expectations({}, True, self._OK)

    def test_an_unexpected_failure_fails(self) -> None:
        with pytest.raises(AssertionError):
            check_expectations({}, False, RunResult(error="ModelValidationError: x"))

    def test_a_task_failure_with_the_wrong_exit_code_fails(self) -> None:
        # The first non-zero exit code is the one checked.
        run = RunResult(
            failed_actions=["A: task"],
            output="Process exited with code: 0\nProcess exited with code: 3\n"
            "Process exited with code: 4",
        )
        check_expectations({"expected": {"taskFailure": {"exitCode": 3}}}, False, run)
        with pytest.raises(AssertionError, match="expected exit code 4"):
            check_expectations({"expected": {"taskFailure": {"exitCode": 4}}}, False, run)

    def test_a_task_failure_test_does_not_accept_a_creation_error(self) -> None:
        with pytest.raises(AssertionError):
            check_expectations(
                {"expected": {"taskFailure": {}}},
                False,
                RunResult(error="ModelValidationError: x", failed_actions=["A: task"]),
            )

    @pytest.mark.skipif(os.name == "nt", reason="POSIX commands")
    def test_a_failed_exit_is_a_failed_action(self, tmp_path: Path) -> None:
        test = {
            "template": {
                "specificationVersion": "jobtemplate-2023-09",
                "extensions": ["ENV_PARAMS", "EXPR"],
                "name": "FailedExit",
                "jobEnvironments": [
                    {
                        "name": "E",
                        "script": {
                            "actions": {
                                "onEnter": {"command": "echo", "args": ["ENTER"]},
                                "onExit": {"command": "false"},
                            }
                        },
                    }
                ],
                "steps": [
                    {"name": "S", "script": _ECHO_TASK},
                    {"name": "T", "dependencies": [{"dependsOn": "S"}], "script": _ECHO_TASK},
                ],
            }
        }
        result = run_conformance_job(test, tmp_path)
        assert result.error is None
        # S's exit fails, so the run stops before T.
        assert len(result.failed_actions) == 1
        assert result.failed_actions[0].startswith("S: exit ")
        with pytest.raises(AssertionError):
            check_expectations({"expected": {"output": ["ENTER"]}}, False, result)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX commands")
    def test_each_step_runs_once_in_dependency_order(self, tmp_path: Path) -> None:
        def step(name: str, deps: list[str]) -> dict[str, Any]:
            result: dict[str, Any] = {
                "name": name,
                "script": {"actions": {"onRun": {"command": "echo", "args": [f"TASK-{name}"]}}},
            }
            if deps:
                result["dependencies"] = [{"dependsOn": d} for d in deps]
            return result

        test = {
            "template": {
                "specificationVersion": "jobtemplate-2023-09",
                "extensions": ["ENV_PARAMS", "EXPR"],
                "name": "Order",
                # Listed out of dependency order: C needs B, B needs A.
                "steps": [step("C", ["B"]), step("B", ["A"]), step("A", [])],
            }
        }
        result = run_conformance_job(test, tmp_path)
        assert not result.failed
        tasks = [line for line in result.output.splitlines() if line.startswith("TASK-")]
        assert tasks == ["TASK-A", "TASK-B", "TASK-C"]

    @pytest.mark.skipif(os.name == "nt", reason="POSIX commands")
    def test_a_failed_enter_is_a_failed_action(self, tmp_path: Path) -> None:
        test = {
            "template": {
                "specificationVersion": "jobtemplate-2023-09",
                "extensions": ["ENV_PARAMS", "EXPR"],
                "name": "FailedEnter",
                "jobEnvironments": [
                    {"name": "E", "script": {"actions": {"onEnter": {"command": "false"}}}}
                ],
                "steps": [{"name": "S", "script": _ECHO_TASK}],
            }
        }
        result = run_conformance_job(test, tmp_path)
        assert result.failed_actions == ["S: enter E"]
        assert "TASK" not in result.output

    @pytest.mark.parametrize("mismatch", ["job", "step"])
    def test_statuses_that_disagree_fail_the_step(self, mismatch: str, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from openjd.model._v1 import create_job_with_environment_templates, decode_job_template
        from openjd.model._v1.job import EnvironmentStatus

        from . import env_params_conformance

        jt = decode_job_template(
            template={
                "specificationVersion": "jobtemplate-2023-09",
                "extensions": ["ENV_PARAMS", "EXPR"],
                "name": "Statuses",
                "jobEnvironments": [{"name": "E", "variables": {"V": "e"}}],
                "steps": [
                    {
                        "name": "S",
                        "stepEnvironments": [{"name": "Own", "variables": {"V": "o"}}],
                        "script": _ECHO_TASK,
                    }
                ],
            },
            supported_extensions=["ENV_PARAMS", "EXPR"],
        )
        created = create_job_with_environment_templates(job_template=jt, job_parameter_values={})
        step = created.job.steps[0]
        assert not env_params_conformance._statuses_disagree(created, step)
        # The same items, with one of them (a Job or a Step Environment) not
        # entered.
        items = [
            SimpleNamespace(
                name=e.name,
                document=e.document,
                scope=e.scope,
                status=(
                    EnvironmentStatus.DISABLED
                    if e.scope.name.lower() == mismatch
                    else EnvironmentStatus.ENTERED
                ),
            )
            for e in created.environment_statuses[0].environments
        ]
        fake = SimpleNamespace(
            job=created.job,
            environment_documents=created.environment_documents,
            environment_statuses=[SimpleNamespace(environments=items)],
        )
        result = RunResult()
        env_params_conformance._run_step(fake, step, [], tmp_path, result)
        assert result.failed_actions == ["S: environment statuses disagree"]
        assert result.output == ""

    def test_a_task_failure_that_did_not_happen_fails(self) -> None:
        with pytest.raises(AssertionError, match="expected a task failure"):
            check_expectations({"expected": {"taskFailure": {}}}, False, self._OK)


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
        # The Session may end before the poll thread (50 ms period) reads the
        # terminal status; the refused action's FAILED must survive that.
        # This test rarely hits that window; test_refused_then_cleanup_reports_failed
        # and test_refused_status_survives_cleanup_and_cancel pin it.
        deadline = time.monotonic() + 5
        while (not statuses or statuses[-1].state != ActionState.FAILED) and (
            time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert [st.state for st in statuses] == [ActionState.RUNNING, ActionState.FAILED]
        assert statuses[-1].fail_message == status.fail_message

    @pytest.mark.parametrize("first", [True, False], ids=["first-action", "after-success"])
    def test_refused_status_survives_cleanup_and_cancel(
        self, job: Any, tmp_path: Path, first: bool
    ) -> None:
        # The Rust session never records a refused action, so its FAILED
        # status lives only in the binding; a later refresh must keep it.
        env = job.job_environments[0]
        dotted = EnvironmentParameterValues(
            environment="Tool",
            values=SerializedSymbolTable.from_json_str(
                '[{"name":"Env.Param.Flavor","type":"string","value":"x"}]'
            ),
        )
        session = Session(session_id="s", job_parameter_values={}, session_root_directory=tmp_path)
        if not first:
            session.run_subprocess(command="true")
            _wait(session)
        session.enter_environment(environment=env, parameters=dotted)
        _wait(session)
        with pytest.raises(SessionRuntimeError) as exc:
            session.cancel_action()
        assert str(exc.value) == "Session must be in RUNNING state, current: READY"
        status = session.action_status
        assert status is not None and status.state == ActionState.FAILED
        session.cleanup()
        assert session.state == SessionState.ENDED
        status = session.action_status
        assert status is not None and status.state == ActionState.FAILED
        assert status.fail_message == (
            "Environment 'Tool': invalid Environment parameter values: 'Env.Param.Flavor' is not a "
            "parameter name; each entry must be keyed by the bare name."
        )

    @pytest.mark.parametrize("first", [True, False], ids=["first-action", "after-success"])
    def test_a_later_action_replaces_the_refused_status(
        self, job: Any, tmp_path: Path, first: bool
    ) -> None:
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
            if not first:
                session.run_subprocess(command="true")
                _wait(session)
            session.enter_environment(environment=env, parameters=dotted)
            _wait(session)
            assert session.action_status is not None
            assert session.action_status.state == ActionState.FAILED
            session.run_subprocess(command="true")
            _wait(session)
            assert session.action_status is not None
            assert session.action_status.state == ActionState.SUCCESS
            session.cleanup()
            assert session.action_status is not None
            assert session.action_status.state == ActionState.SUCCESS

    def test_refused_then_cleanup_reports_failed(self, job: Any, tmp_path: Path) -> None:
        # A refused enter followed at once by cleanup: the poll thread may
        # read the status only after the Session has ended.
        env = job.job_environments[0]
        dotted = EnvironmentParameterValues(
            environment="Tool",
            values=SerializedSymbolTable.from_json_str(
                '[{"name":"Env.Param.Flavor","type":"string","value":"x"}]'
            ),
        )
        for i in range(20):
            statuses: list[Any] = []
            root = tmp_path / str(i)
            root.mkdir()
            session = Session(
                session_id="s",
                job_parameter_values={},
                session_root_directory=root,
                callback=lambda _sid, st: statuses.append(st),
            )
            session.run_subprocess(command="true")
            _wait(session)
            deadline = time.monotonic() + 5
            while (not statuses or statuses[-1].state != ActionState.SUCCESS) and (
                time.monotonic() < deadline
            ):
                time.sleep(0.01)
            del statuses[:]
            session.enter_environment(environment=env, parameters=dotted)
            _wait(session)
            session.cleanup()
            deadline = time.monotonic() + 5
            while len(statuses) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert [st.state for st in statuses] == [ActionState.RUNNING, ActionState.FAILED]

    def test_an_enter_that_ran_keeps_its_own_status(self, tmp_path: Path) -> None:
        # Only an action refused before it started gets the binding's FAILED;
        # an onEnter that ran and failed keeps the session's status.
        template = dict(_TEMPLATE)
        template["jobEnvironments"] = [
            {"name": "Bad", "script": {"actions": {"onEnter": {"command": "false"}}}}
        ]
        template["steps"] = [{"name": "S", "script": {"actions": {"onRun": {"command": "true"}}}}]
        jt = decode_job_template(template=template, supported_extensions=["ENV_PARAMS", "EXPR"])
        env = create_job(job_template=jt, job_parameter_values={}).job_environments[0]
        with Session(
            session_id="s", job_parameter_values={}, session_root_directory=tmp_path
        ) as session:
            session.enter_environment(environment=env, resolved_symtab=env.resolved_symtab)
            _wait(session)
            status = session.action_status
            assert status is not None
            assert status.state == ActionState.FAILED
            assert status.exit_code == 1
            assert status.fail_message is None

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


# ── Other actions refused before they start ──


# ── PATH values used as given (spec af53020, Template Schemas §4.5 item 3) ──

_AS_GIVEN_TEMPLATE: dict[str, Any] = {
    "specificationVersion": "jobtemplate-2023-09",
    "extensions": ["ENV_PARAMS", "EXPR"],
    "name": "AsGiven",
    "parameterDefinitions": [{"name": "Dir", "type": "PATH", "default": "/unused"}],
    "jobEnvironments": [
        {
            "name": "Mnt",
            "activation": "ON_REQUEST",
            "envParameterDefinitions": [
                {"name": "Dir", "type": "PATH"},
                {"name": "Mounts", "type": "LIST[PATH]"},
            ],
            "script": {
                "actions": {
                    "onEnter": {
                        "command": "echo",
                        "args": [
                            "ENTER",
                            "{{Env.Param.Dir}}",
                            "{{Env.RawParam.Dir}}",
                            "{{Env.Param.Mounts}}",
                            "{{Env.RawParam.Mounts}}",
                        ],
                    },
                    "onExit": {
                        "command": "echo",
                        "args": ["EXIT", "{{Env.Param.Dir}}", "{{Env.RawParam.Dir}}"],
                    },
                }
            },
        }
    ],
    "steps": [
        {
            "name": "S",
            "dependencies": [
                {
                    "environment": "Mnt",
                    "parameters": {
                        "Dir": "{{RawParam.Dir}}",
                        "Mounts": ["C:\\proj\\a", "rel/b", "/src/c"],
                    },
                }
            ],
            "script": {"actions": {"onRun": {"command": "echo", "args": ["TASK"]}}},
        }
    ],
}


@pytest.mark.skipif(os.name == "nt", reason="POSIX echo and paths")
class TestPathValuesAsGiven:
    """A relative or Windows value travels through create_job and is mapped by
    the Session only when a rule matches; Env.RawParam keeps the text."""

    @pytest.mark.parametrize(
        "value, mapped",
        [
            ("C:\\proj\\sub", "/mnt/proj/sub"),
            ("\\\\srv\\share\\x", "/mnt/share/x"),
            ("/src/d", "/dst/d"),
            ("rel/dir", "rel/dir"),
            ("C:dir", "C:dir"),
            ("\\dir", "\\dir"),
            ("s3://bucket/key", "s3://bucket/key"),
            ("", ""),
        ],
    )
    def test_value_is_mapped_only_when_a_rule_matches(
        self, value: str, mapped: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.INFO)
        from openjd.sessions._v1 import PathMappingRule

        # A literal entry, since Job Parameters still refuse URIs.
        template = json.loads(json.dumps(_AS_GIVEN_TEMPLATE))
        template["steps"][0]["dependencies"][0]["parameters"]["Dir"] = value
        jt = decode_job_template(template=template, supported_extensions=["ENV_PARAMS", "EXPR"])
        job = create_job(job_template=jt, job_parameter_values={})
        step = job.steps[0]
        env = job.job_environments[0]
        values = step.environment_parameters_for("Mnt")
        assert values is not None
        stored = {v["name"]: v["value"] for v in json.loads(values.to_json_str())["values"]}
        assert stored == {"Dir": value, "Mounts": ["C:\\proj\\a", "rel/b", "/src/c"]}
        rules = [
            PathMappingRule.from_dict(r)
            for r in (
                {
                    "source_path_format": "WINDOWS",
                    "source_path": "C:\\proj",
                    "destination_path": "/mnt/proj",
                },
                {
                    "source_path_format": "WINDOWS",
                    "source_path": "\\\\srv\\share",
                    "destination_path": "/mnt/share",
                },
                {"source_path_format": "POSIX", "source_path": "/src", "destination_path": "/dst"},
            )
        ]
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
            session.exit_environment(identifier=eid, resolved_symtab=env.resolved_symtab)
            _wait(session)
            assert session.action_status is not None
            assert session.action_status.state == ActionState.SUCCESS
        enter = f"ENTER {mapped} {value} /mnt/proj/a rel/b /dst/c C:\\proj\\a rel/b /src/c"
        assert [m for m in caplog.messages if m.startswith("ENTER")] == [enter]
        assert [m for m in caplog.messages if m.startswith("EXIT")] == [f"EXIT {mapped} {value}"]

    # openjd-rs #516: a join onto an empty path gives the other operand, as
    # pathlib does. Before, '' / 'k' was '/k'.
    @pytest.mark.parametrize("value", ["", "rel", "/abs"])
    def test_an_empty_value_joins_as_pathlib_does(
        self, value: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.INFO)
        template = json.loads(json.dumps(_AS_GIVEN_TEMPLATE))
        template["steps"][0]["dependencies"][0]["parameters"]["Dir"] = value
        env_template = template["jobEnvironments"][0]
        env_template["script"]["actions"]["onEnter"]["args"] = [
            "JOINED",
            "{{Env.Param.Dir / 'k'}}",
        ]
        jt = decode_job_template(template=template, supported_extensions=["ENV_PARAMS", "EXPR"])
        job = create_job(job_template=jt, job_parameter_values={})
        env = job.job_environments[0]
        values = job.steps[0].environment_parameters_for("Mnt")
        with Session(
            session_id="s", job_parameter_values={}, session_root_directory=tmp_path
        ) as session:
            session.enter_environment(
                environment=env, resolved_symtab=env.resolved_symtab, parameters=values
            )
            _wait(session)
        joined = str(PurePosixPath(value) / "k")
        assert joined == {"": "k", "rel": "rel/k", "/abs": "/abs/k"}[value]
        assert [m for m in caplog.messages if m.startswith("JOINED")] == [f"JOINED {joined}"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX commands and paths")
class TestRefusedActions:
    @staticmethod
    def _collect(session_root: Path, long_path: bool = True) -> tuple[Session, list[Any]]:
        # ``long_path``: a PATH Job Parameter over 32 KiB, which no action
        # that builds the Job's symbols can map.
        statuses: list[Any] = []
        values = (
            {"P": JobParameterValue(type=JobParameterType.PATH, value="/" + "a" * 40000)}
            if long_path
            else {}
        )
        session = Session(
            session_id="s",
            job_parameter_values=values,
            session_root_directory=session_root,
            callback=lambda _sid, st: statuses.append(st),
        )
        return session, statuses

    @staticmethod
    def _terminal(statuses: list[Any]) -> Any:
        deadline = time.monotonic() + 5
        while (not statuses or statuses[-1].state == ActionState.RUNNING) and (
            time.monotonic() < deadline
        ):
            time.sleep(0.01)
        return statuses[-1]

    @pytest.mark.parametrize("first", [True, False], ids=["first-action", "after-success"])
    def test_run_task_that_cannot_build_its_symbols(self, tmp_path: Path, first: bool) -> None:
        # openjd-sessions 0.8.2: a PATH value longer than 32 KiB cannot be
        # mapped, so the task is refused before it runs.
        jt = decode_job_template(
            template={
                "specificationVersion": "jobtemplate-2023-09",
                "name": "J",
                "parameterDefinitions": [{"name": "P", "type": "PATH"}],
                "steps": [
                    {
                        "name": "S",
                        "script": {
                            "actions": {"onRun": {"command": "echo", "args": ["{{Param.P}}"]}}
                        },
                    }
                ],
            }
        )
        job = create_job(job_template=jt, job_parameter_values={"P": "/" + "a" * 40000})
        session, statuses = self._collect(tmp_path)
        with session:
            if not first:
                session.run_subprocess(command="true")
                _wait(session)
                assert self._terminal(statuses).state == ActionState.SUCCESS
                del statuses[:]
            session.run_task(
                step_script=job.steps[0].script,
                task_parameter_values={},
                resolved_symtab=job.steps[0].resolved_symtab,
            )
            _wait(session)
            status = session.action_status
            assert status is not None
            assert status.state == ActionState.FAILED
            assert status.fail_message == (
                "Failed to apply path mapping to Param.P: the path is 40001 bytes long, more than "
                "the limit of 32768 bytes"
            )
            terminal = self._terminal(statuses)
            assert [st.state for st in statuses] == [ActionState.RUNNING, ActionState.FAILED]
            assert terminal.fail_message == status.fail_message

    def test_run_subprocess_in_ready_ending(self, tmp_path: Path) -> None:
        # A failed onExit leaves the Session READY_ENDING, where
        # run_subprocess is refused before it starts.
        jt = decode_job_template(
            template={
                "specificationVersion": "jobtemplate-2023-09",
                "name": "J",
                "jobEnvironments": [
                    {"name": "E", "script": {"actions": {"onExit": {"command": "false"}}}}
                ],
                "steps": [{"name": "S", "script": {"actions": {"onRun": {"command": "true"}}}}],
            }
        )
        env = create_job(job_template=jt, job_parameter_values={}).job_environments[0]
        session, statuses = self._collect(tmp_path, long_path=False)
        with session:
            eid = session.enter_environment(environment=env, resolved_symtab=env.resolved_symtab)
            _wait(session)
            session.exit_environment(identifier=eid, resolved_symtab=env.resolved_symtab)
            _wait(session)
            # The onExit ran and failed: the session's own status, with its
            # exit code.
            status = session.action_status
            assert status is not None
            assert (status.state, status.exit_code, status.fail_message) == (
                ActionState.FAILED,
                1,
                None,
            )
            assert session.state == SessionState.READY_ENDING
            assert self._terminal(statuses).state == ActionState.FAILED
            del statuses[:]
            session.run_subprocess(command="true")
            _wait(session)
            status = session.action_status
            assert status is not None
            assert status.state == ActionState.FAILED
            assert status.fail_message == "Session must be in READY state, current: READY_ENDING"
            assert self._terminal(statuses).fail_message == status.fail_message
            assert [st.state for st in statuses] == [ActionState.RUNNING, ActionState.FAILED]

    @pytest.mark.parametrize("first", [True, False], ids=["first-action", "after-success"])
    def test_exit_of_an_unknown_environment(self, tmp_path: Path, first: bool) -> None:
        session, statuses = self._collect(tmp_path, long_path=False)
        with session:
            if not first:
                session.run_subprocess(command="true")
                _wait(session)
                assert self._terminal(statuses).state == ActionState.SUCCESS
                del statuses[:]
            session.exit_environment(identifier="nope")
            _wait(session)
            status = session.action_status
            assert status is not None
            assert status.state == ActionState.FAILED
            assert status.fail_message == "Unknown environment identifier: nope"
            assert self._terminal(statuses).fail_message == status.fail_message
            assert [st.state for st in statuses] == [ActionState.RUNNING, ActionState.FAILED]

    def test_failed_onexit_after_a_failed_task_keeps_its_exit_code(self, tmp_path: Path) -> None:
        # After a failed action the Session is READY_ENDING, and an onExit
        # that then runs and fails must keep its own status (exit code 1),
        # not be reported as a refusal.
        jt = decode_job_template(
            template={
                "specificationVersion": "jobtemplate-2023-09",
                "name": "J",
                "jobEnvironments": [
                    {"name": "E", "script": {"actions": {"onExit": {"command": "false"}}}}
                ],
                "steps": [{"name": "S", "script": {"actions": {"onRun": {"command": "true"}}}}],
            }
        )
        env = create_job(job_template=jt, job_parameter_values={}).job_environments[0]
        session, statuses = self._collect(tmp_path, long_path=False)
        with session:
            eid = session.enter_environment(environment=env, resolved_symtab=env.resolved_symtab)
            _wait(session)
            session.run_subprocess(command="false")
            _wait(session)
            assert session.state == SessionState.READY_ENDING
            assert self._terminal(statuses).state == ActionState.FAILED
            del statuses[:]
            session.exit_environment(identifier=eid, resolved_symtab=env.resolved_symtab)
            _wait(session)
            status = session.action_status
            assert status is not None
            assert (status.state, status.exit_code, status.fail_message) == (
                ActionState.FAILED,
                1,
                None,
            )
            terminal = self._terminal(statuses)
            assert (terminal.state, terminal.exit_code, terminal.fail_message) == (
                ActionState.FAILED,
                1,
                None,
            )


# ── Dropping a Session cleans it up ──


def test_dropping_a_session_removes_its_working_directory(tmp_path: Path) -> None:
    session = Session(session_id="s", job_parameter_values={}, session_root_directory=tmp_path)
    working = session.working_directory
    assert working.is_dir()
    del session
    gc.collect()
    assert not working.exists()


# ── exclusiveGroup: a superseded Environment is never entered or exited ──

_GROUP_TEMPLATE: dict[str, Any] = {
    "specificationVersion": "jobtemplate-2023-09",
    "extensions": ["ENV_PARAMS", "EXPR"],
    "name": "GroupJob",
    "jobEnvironments": [
        {
            "name": name,
            "exclusiveGroup": "G",
            **extra,
            "script": {
                "actions": {
                    "onEnter": {"command": "echo", "args": ["ENTER", name]},
                    "onExit": {"command": "echo", "args": ["EXIT", name]},
                }
            },
        }
        for name, extra in (
            ("A", {"enableIf": "Param.UseA"}),
            # B's Seats has no default and no Step supplies it: B is only
            # valid where A supersedes it.
            ("B", {"envParameterDefinitions": [{"name": "Seats", "type": "INT"}]}),
        )
    ],
    "parameterDefinitions": [{"name": "UseA", "type": "BOOL", "default": True}],
    "steps": [
        {"name": "S", "script": {"actions": {"onRun": {"command": "echo", "args": ["TASK"]}}}}
    ],
}


@pytest.mark.skipif(os.name == "nt", reason="POSIX echo")
class TestSupersededEnvironment:
    def test_never_entered_or_exited(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The Session gets no exclusiveGroup information: it enters what it is
        # given. This checks the caller's rule (Step.enters_environment, as the
        # worker agent uses it) together with the Session's enter and exit.
        caplog.set_level(logging.INFO)
        jt = decode_job_template(
            template=_GROUP_TEMPLATE, supported_extensions=["ENV_PARAMS", "EXPR"]
        )
        job = create_job(job_template=jt, job_parameter_values={})
        step = job.steps[0]
        # The worker's rule: enter exactly the Job Environments the Step's
        # Sessions enter, in Job order, and exit those in reverse.
        entering = [e for e in job.job_environments if step.enters_environment(e.name)]
        assert [e.name for e in entering] == ["A"]
        assert step.environment_parameters_for("B") is None
        with Session(
            session_id="s", job_parameter_values={}, session_root_directory=tmp_path
        ) as session:
            ids = []
            for env in entering:
                ids.append(
                    session.enter_environment(
                        environment=env,
                        resolved_symtab=env.resolved_symtab,
                        parameters=step.environment_parameters_for(env.name),
                    )
                )
                _wait(session)
                assert session.action_status is not None
                assert session.action_status.state == ActionState.SUCCESS
            assert list(session.environments_entered) == ids
            for env_id, env in reversed(list(zip(ids, entering))):
                session.exit_environment(identifier=env_id, resolved_symtab=env.resolved_symtab)
                _wait(session)
                assert session.action_status is not None
                assert session.action_status.state == ActionState.SUCCESS
        lines = [r.getMessage() for r in caplog.records]
        assert "ENTER A" in lines and "EXIT A" in lines
        assert not any(" B" in line and line.split()[0] in ("ENTER", "EXIT") for line in lines)

    def test_falls_through_when_the_first_is_disabled(self) -> None:
        # With A disabled, B is entered, and its missing Seats is an error.
        jt = decode_job_template(
            template=_GROUP_TEMPLATE, supported_extensions=["ENV_PARAMS", "EXPR"]
        )
        with pytest.raises(ModelValidationError) as exc:
            create_job(job_template=jt, job_parameter_values={"UseA": "false"})
        assert str(exc.value) == (
            "1 validation error for JobTemplate\n"
            "steps[0]:\n"
            "\tmust supply, in an 'environment:' dependency, every parameter without a default "
            "of each Environment its Sessions enter (every jobEnvironments entry with activation "
            "ALWAYS, each one with activation BY_DEFAULT that the Step does not decline, and each "
            "one with activation ON_REQUEST that the Step requests; Template Schemas §3.2 "
            "constraint 7); missing: 'Seats' of Environment 'B'."
        )


# ── Path mapping rules are validated (openjd-sessions 0.8.2) ──


class TestInvalidPathMappingRules:
    _BAD = {"source_path_format": "POSIX", "source_path": "rel", "destination_path": "/d"}
    _OK = {"source_path_format": "POSIX", "source_path": "/s", "destination_path": "/d"}
    _MESSAGE = (
        "Invalid path mapping rules: path mapping rule 1: source_path 'rel' must be an absolute "
        "POSIX path, starting with '/'"
    )

    def test_session_constructor_rejects_an_invalid_rule(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from openjd.sessions._v1 import PathMappingRule

        unraisable: list[Any] = []
        monkeypatch.setattr(sys, "unraisablehook", unraisable.append)
        rules = [PathMappingRule.from_dict(self._OK), PathMappingRule.from_dict(self._BAD)]
        with pytest.raises(SessionRuntimeError) as exc:
            Session(
                session_id="s",
                job_parameter_values={},
                path_mapping_rules=rules,
                session_root_directory=tmp_path,
            )
        assert str(exc.value) == self._MESSAGE
        # No session directory is created for a rejected Session.
        assert list(tmp_path.iterdir()) == []
        # Freeing the half-built Session must not raise from __del__.
        del exc
        gc.collect()
        assert unraisable == []

    @pytest.mark.skipif(os.name == "nt", reason="POSIX echo and paths")
    def test_extend_adds_rules_that_take_precedence(
        self, job: Any, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from openjd.sessions._v1 import PathMappingRule

        caplog.set_level(logging.INFO)

        def rule(dst: str) -> Any:
            return PathMappingRule.from_dict(
                {"source_path_format": "POSIX", "source_path": "/src", "destination_path": dst}
            )

        step = job.steps[0]
        env = job.job_environments[0]
        with Session(
            session_id="s",
            job_parameter_values={},
            path_mapping_rules=[rule("/first")],
            session_root_directory=tmp_path,
        ) as session:
            # A rejected extension leaves the rules unchanged.
            with pytest.raises(SessionRuntimeError) as exc:
                session.extend_path_mapping_rules(
                    [rule("/never"), PathMappingRule.from_dict(self._BAD)]
                )
            # The index counts the existing rule first.
            assert str(exc.value) == self._MESSAGE.replace("rule 1:", "rule 2:")

            def enter_and_exit() -> None:
                eid = session.enter_environment(
                    environment=env,
                    resolved_symtab=env.resolved_symtab,
                    parameters=step.environment_parameters_for("Tool"),
                )
                _wait(session)
                assert session.action_status is not None
                assert session.action_status.state == ActionState.SUCCESS
                session.exit_environment(identifier=eid, resolved_symtab=env.resolved_symtab)
                _wait(session)

            # The rejected extension added nothing: /first still applies.
            enter_and_exit()
            session.extend_path_mapping_rules([rule("/added"), rule("/last")])
            enter_and_exit()
        enters = [r.getMessage() for r in caplog.records if r.getMessage().startswith("ENTER ")]
        # Then the last rule given for /src wins.
        assert enters == ["ENTER red /first/data", "ENTER red /last/data"]

    def test_extend_rejects_an_invalid_rule(self, tmp_path: Path) -> None:
        from openjd.sessions._v1 import PathMappingRule

        with Session(
            session_id="s",
            job_parameter_values={},
            path_mapping_rules=[PathMappingRule.from_dict(self._OK)],
            session_root_directory=tmp_path,
        ) as session:
            with pytest.raises(SessionRuntimeError) as exc:
                session.extend_path_mapping_rules([PathMappingRule.from_dict(self._BAD)])
            assert str(exc.value) == self._MESSAGE
