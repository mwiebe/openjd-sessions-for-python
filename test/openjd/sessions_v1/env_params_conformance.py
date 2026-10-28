# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

"""Run an Open Job Description conformance ``jobs/*.test.yaml`` file through
the Rust-backed path (``openjd.model._v1`` + ``openjd.sessions._v1``).

The runner follows ``conformance-tests/README.md`` and the reference
``run_openjd_cli_tests.py``: decode the Job Template and the Environment
Templates, create the Job (with the Environment Templates attached, in order),
run one Session per Step in dependency order, and check the ``expected``
assertions against the Session log. A ``.invalid.`` test passes when
decoding, job creation, or any action fails.

For ENV_PARAMS a Session enters exactly the Job Environments
``Step.enters_environment`` names, in ``Job.job_environments`` order, each with
its own ``resolved_symtab`` and the Step's ``environment_parameters`` entry for
it.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from openjd.model._v1 import (
    create_job_with_environment_templates,
    decode_environment_template,
    decode_job_template,
)
from openjd.model._v1.job import StepParameterSpaceIterator
from openjd.model._v1.types import JobParameterValue, ModelExtension, ValidationContext
from openjd.sessions._v1 import (
    ActionState,
    PathMappingRule,
    Session,
    SessionState,
)

OPERATING_SYSTEM = "windows" if os.name == "nt" else "posix"

# Every extension the binding knows: the CLI's default allowlist.
ALL_EXTENSIONS = [
    name
    for name in (
        "TASK_CHUNKING",
        "REDACTED_ENV_VARS",
        "FEATURE_BUNDLE_1",
        "EXPR",
        "WRAP_ACTIONS",
        "ENV_PARAMS",
    )
    if ModelExtension.from_str(name) is not None
]

_QUIESCENT = {SessionState.READY, SessionState.ENDED, SessionState.READY_ENDING}
_EXIT_CODE_RE = re.compile(r"exited with code:\s*(-?\d+)")


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@dataclass
class RunResult:
    """What a conformance job run produced."""

    error: Optional[str] = None
    """Decode or job-creation error, if any."""
    failed_actions: list[str] = field(default_factory=list)
    output: str = ""

    @property
    def failed(self) -> bool:
        return self.error is not None or bool(self.failed_actions)


def should_run(test: dict[str, Any]) -> bool:
    run_on = test.get("runOn")
    return run_on is None or OPERATING_SYSTEM in run_on


def _wait(session: Session) -> bool:
    """Wait for the current action; True when it did not fail."""
    deadline = time.monotonic() + 60
    while session.state not in _QUIESCENT:
        if time.monotonic() > deadline:
            raise TimeoutError("action did not finish in 60 s")
        time.sleep(0.005)
    status = session.action_status
    return status is None or status.state != ActionState.FAILED


def _step_order(job: Any) -> list[Any]:
    steps = list(job.steps)
    by_name = {s.name: s for s in steps}
    done: list[str] = []

    def visit(s: Any) -> None:
        if s.name in done:
            return
        for dep in s.dependencies or []:
            visit(by_name[dep.depends_on])
        done.append(s.name)

    for s in steps:
        visit(s)
    return [by_name[n] for n in done]


def run_conformance_job(test: dict[str, Any], work_dir: Path) -> RunResult:
    result = RunResult()
    try:
        job_template = decode_job_template(
            template=test["template"], supported_extensions=ALL_EXTENSIONS
        )
        env_templates = [
            decode_environment_template(template=e, supported_extensions=ALL_EXTENSIONS)
            for e in test.get("environments", [])
        ]
        # The openjd CLI's submission policy (openjd-cli ``submission_context``):
        # the template's own profile, host path format, URI PATH values allowed.
        context = ValidationContext(job_template.profile, allow_uri_path_values=True)
        created = create_job_with_environment_templates(
            job_template=job_template,
            job_parameter_values=dict(test.get("parameters", {})),
            environment_templates=env_templates,
            validation_context=context,
        )
    except Exception as e:  # decode / create failures are the test's subject
        result.error = f"{type(e).__name__}: {e}"
        return result

    job = created.job
    rules = [PathMappingRule.from_dict(r) for r in test.get("pathMapping", [])]
    collector = _Collect()
    logger = logging.getLogger("openjd.sessions")
    old_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(collector)
    try:
        for step in _step_order(job):
            if result.failed_actions:
                break
            _run_step(created, step, rules, work_dir, result)
    finally:
        logger.removeHandler(collector)
        logger.setLevel(old_level)
    result.output = "\n".join(collector.messages)
    return result


def _run_step(
    created: Any, step: Any, rules: list[PathMappingRule], work_dir: Path, result: RunResult
) -> None:
    job = created.job
    entered: list[tuple[str, Any]] = []
    with Session(
        session_id=f"conformance-{step.name}",
        job_parameter_values={
            name: JobParameterValue(type=p.type, value=p.value)
            for name, p in job.parameters.items()
        },
        path_mapping_rules=rules or None,
        session_root_directory=work_dir,
    ) as session:
        ok = True
        for env, document in zip(job.job_environments or [], created.environment_documents):
            if not step.enters_environment(env.name, document):
                continue
            env_id = session.enter_environment(
                environment=env,
                resolved_symtab=env.resolved_symtab,
                parameters=step.environment_parameters_for(env.name, document),
            )
            entered.append((env_id, env.resolved_symtab))
            if not _wait(session):
                result.failed_actions.append(f"{step.name}: enter {env.name}")
                ok = False
                break
        if ok:
            for env in step.step_environments or []:
                env_id = session.enter_environment(
                    environment=env, resolved_symtab=step.resolved_symtab
                )
                entered.append((env_id, step.resolved_symtab))
                if not _wait(session):
                    result.failed_actions.append(f"{step.name}: enter {env.name}")
                    ok = False
                    break
        if ok:
            for task_params in StepParameterSpaceIterator(space=step.parameter_space):
                session.run_task(
                    step_script=step.script,
                    task_parameter_values=task_params,
                    resolved_symtab=step.resolved_symtab,
                )
                if not _wait(session):
                    result.failed_actions.append(f"{step.name}: task {task_params}")
                    break
        for env_id, symtab in reversed(entered):
            session.exit_environment(identifier=env_id, resolved_symtab=symtab)
            if not _wait(session):
                result.failed_actions.append(f"{step.name}: exit {env_id}")


def check_expectations(test: dict[str, Any], expect_failure: bool, result: RunResult) -> None:
    """Raise ``AssertionError`` when ``result`` does not meet the test file."""
    expected = test.get("expected", {})
    task_failure = expected.get("taskFailure")
    context = (
        f"error={result.error}\nfailed={result.failed_actions}\n--- output ---\n{result.output}"
    )
    if expect_failure:
        assert result.failed, f"expected the run to fail\n{context}"
    elif task_failure is not None:
        assert result.error is None, context
        assert result.failed_actions, f"expected a task failure\n{context}"
        code = task_failure.get("exitCode")
        if code is not None:
            codes = [int(c) for c in _EXIT_CODE_RE.findall(result.output) if int(c) != 0]
            assert codes and codes[0] == code, f"expected exit code {code}\n{context}"
    else:
        assert not result.failed, context
    output = result.output
    for line in expected.get("output", []) + expected.get(f"output_{OPERATING_SYSTEM}", []):
        if isinstance(line, dict) and "anyOf" in line:
            assert any(alt in output for alt in line["anyOf"]), f"missing {line}\n{context}"
        else:
            assert line in output, f"missing expected output {line!r}\n{context}"
    for line in expected.get("forbidden", []) + expected.get(f"forbidden_{OPERATING_SYSTEM}", []):
        assert line not in output, f"found forbidden output {line!r}\n{context}"
