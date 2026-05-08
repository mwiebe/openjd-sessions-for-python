# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

import time
from datetime import timedelta
from logging.handlers import QueueHandler
from pathlib import Path
from queue import SimpleQueue
from typing import Optional, Union
from unittest.mock import MagicMock, patch
import os

import pytest

from openjd.expr import get_default_library
from openjd.expr import SymbolTable
from openjd.model.v1._parse import _parse_model
from openjd.model.v1.v2023_09 import Action as Action_2023_09
from openjd.model.v1.v2023_09 import (
    CancelationMethodNotifyThenTerminate as CancelationMethodNotifyThenTerminate_2023_09,
)
from openjd.model.v1.v2023_09 import (
    CancelationMethodTerminate as CancelationMethodTerminate_2023_09,
)
from openjd.model.v1.v2023_09 import CancelationMode as CancelationMode_2023_09
from openjd.model.v1.v2023_09 import (
    EmbeddedFileText as EmbeddedFileText_2023_09,
)
from openjd.model.v1.v2023_09 import (
    EmbeddedFileTypes as EmbeddedFileTypes_2023_09,
)
from openjd.model.v1.v2023_09 import (
    CommandString as CommandString_2023_09,
    ArgString as ArgString_2023_09,
    DataString as DataString_2023_09,
)
from openjd.model.v1.v2023_09 import StepActions as StepActions_2023_09
from openjd.model.v1.v2023_09 import StepScript as StepScript_2023_09
from openjd.model.v1.v2023_09 import ModelParsingContext as ModelParsingContext_2023_09

from openjd.sessions import WindowsSessionUser
from openjd.sessions._runner_base import ScriptRunnerState
from openjd.sessions._runner_step_script import (
    CancelMethod,
    NotifyCancelMethod,
    StepScriptRunner,
    TerminateCancelMethod,
)
from openjd.sessions._tempdir import TempDir
from openjd.sessions._os_checker import is_posix, is_windows

from .conftest import (
    build_logger,
    collect_queue_messages,
    has_windows_user,
    WIN_SET_TEST_ENV_VARS_MESSAGE,
)


# tmp_path - builtin temporary directory
@pytest.mark.usefixtures("tmp_path", "message_queue", "queue_handler")
class TestStepScriptRunner:
    def test_run_basic(
        self,
        tmp_path: Path,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        python_exe: str,
    ) -> None:
        # Test that run of an action with no embedded files works as expected.

        # GIVEN
        script = StepScript_2023_09(
            actions=StepActions_2023_09(
                onRun=Action_2023_09(
                    command=CommandString_2023_09("{{ Task.Command }}"),
                    args=[ArgString_2023_09("-c"), ArgString_2023_09("print('\"Hello\"')")],
                )
            )
        )
        symtab = SymbolTable({"Task.Command": python_exe})
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmp_path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmp_path,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        # THEN
        assert runner.state == ScriptRunnerState.SUCCESS
        messages = collect_queue_messages(message_queue)
        assert '"Hello"' in messages

    def test_run_with_files(
        self,
        tmp_path: Path,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        python_exe: str,
    ) -> None:
        # Test that that en embedded file is properly materialized and can be used in the action

        # GIVEN
        script = StepScript_2023_09(
            actions=StepActions_2023_09(
                onRun=Action_2023_09(
                    command=CommandString_2023_09("{{ Task.Command }}"),
                    args=[ArgString_2023_09("{{ Task.File.Foo }}")],
                )
            ),
            embeddedFiles=[
                EmbeddedFileText_2023_09(
                    name="Foo",
                    type=EmbeddedFileTypes_2023_09.TEXT,
                    data=DataString_2023_09("print('Hello')"),
                )
            ],
        )
        symtab = SymbolTable({"Task.Command": python_exe})
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmp_path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmp_path,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        # THEN
        assert runner.state == ScriptRunnerState.SUCCESS
        messages = collect_queue_messages(message_queue)
        assert "Hello" in messages
        assert len(symtab.keys) == 1

    @pytest.mark.parametrize(
        "os_env_vars",
        (
            pytest.param(None, id="No defined env vars"),
            pytest.param({"PATH": os.environ.get("PATH", "")}),
        ),
    )
    def test_run_file_in_session_dir(
        self,
        tmp_path: Path,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        os_env_vars: Optional[dict[str, Optional[str]]],
    ) -> None:
        # Test that if we materialize a script into the session directory, then we can run it by
        # referencing it relative to the Session Working Directory.
        # This primarily is intended to test the locate_windows_executable path of ScriptRunnerBase.

        # GIVEN
        if is_posix():
            script = StepScript_2023_09(
                actions=StepActions_2023_09(
                    onRun=Action_2023_09(command=CommandString_2023_09("./test.sh"))
                ),
                embeddedFiles=[
                    EmbeddedFileText_2023_09(
                        name="Foo",
                        type=EmbeddedFileTypes_2023_09.TEXT,
                        filename="test.sh",
                        runnable=True,
                        data=DataString_2023_09("#!/bin/sh\necho 'Hello!'"),
                    )
                ],
            )
        else:
            script = StepScript_2023_09(
                actions=StepActions_2023_09(
                    onRun=Action_2023_09(command=CommandString_2023_09("test.bat"))
                ),
                embeddedFiles=[
                    EmbeddedFileText_2023_09(
                        name="Foo",
                        type=EmbeddedFileTypes_2023_09.TEXT,
                        filename="test.bat",
                        data=DataString_2023_09("echo Hello!"),
                    )
                ],
            )
        symtab = SymbolTable()
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmp_path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmp_path,
            os_env_vars=os_env_vars,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        # THEN
        assert runner.state == ScriptRunnerState.SUCCESS
        messages = collect_queue_messages(message_queue)
        assert "Hello!" in messages

    @pytest.mark.parametrize(
        "cancel_method,expected",
        [
            pytest.param(None, TerminateCancelMethod(), id="default is terminate"),
            pytest.param(
                CancelationMethodTerminate_2023_09(mode=CancelationMode_2023_09.TERMINATE),
                TerminateCancelMethod(),
                id="terminate is terminate",
            ),
            pytest.param(
                CancelationMethodNotifyThenTerminate_2023_09(
                    mode=CancelationMode_2023_09.NOTIFY_THEN_TERMINATE
                ),
                NotifyCancelMethod(terminate_delay=timedelta(seconds=120)),
                id="default notify period is 120s",
            ),
            pytest.param(
                CancelationMethodNotifyThenTerminate_2023_09(
                    mode=CancelationMode_2023_09.NOTIFY_THEN_TERMINATE, notifyPeriodInSeconds=10
                ),
                NotifyCancelMethod(terminate_delay=timedelta(seconds=10)),
                id="uses notify period",
            ),
        ],
    )
    def test_cancel(
        self,
        tmp_path: Path,
        cancel_method: Optional[
            Union[
                CancelationMethodNotifyThenTerminate_2023_09,
                CancelationMethodTerminate_2023_09,
            ]
        ],
        expected: CancelMethod,
        python_exe: str,
    ) -> None:
        # Test that cancel invokes the base class' cancel with the appropriate arguments.

        # We'll do this one with mocks to avoid timing/race-condition issues.
        # The lower-level process runners have been thoroughly tested for cancel's
        # functionality, so this seems fine.

        with patch.object(StepScriptRunner, "_run_action"):
            with patch.object(StepScriptRunner, "_cancel") as mock_cancel:
                # GIVEN
                script = StepScript_2023_09(
                    actions=StepActions_2023_09(
                        onRun=Action_2023_09(
                            command=CommandString_2023_09("{{ Task.Command }}"),
                            args=[ArgString_2023_09("-c"), ArgString_2023_09("print('Hello')")],
                            cancelation=cancel_method,
                        )
                    )
                )
                symtab = SymbolTable({"Task.Command": python_exe})
                runner = StepScriptRunner(
                    logger=MagicMock(),
                    session_working_directory=tmp_path,
                    script=script,
                    symtab=symtab,
                    library=get_default_library(),
                    session_files_directory=tmp_path,
                )
                runner.run()
                time_limit = timedelta(30)

                # WHEN
                runner.cancel(time_limit=time_limit)

                # THEN
                arg0 = mock_cancel.call_args.args[0]
                assert arg0 == expected
                arg1 = mock_cancel.call_args.args[1]
                assert arg1 is time_limit

    @pytest.mark.timeout(60)  # GitHub CI file operations may be causing a timeout
    @pytest.mark.skipif(not is_windows(), reason="Windows-only test")
    @pytest.mark.xfail(
        not has_windows_user(),
        reason=WIN_SET_TEST_ENV_VARS_MESSAGE,
    )
    @pytest.mark.parametrize(
        "os_env_vars",
        (
            pytest.param(None, id="No defined env vars"),
            pytest.param({"PATH": os.environ.get("PATH", "")}),
        ),
    )
    def test_run_file_in_session_dir_as_windows_user(
        self,
        windows_user: WindowsSessionUser,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        os_env_vars: Optional[dict[str, Optional[str]]],
    ) -> None:
        # Test that if we materialize a script into the session directory, then we can run it by
        # referencing it relative to the Session Working Directory.
        # This primarily is intended to test the locate_windows_executable path of ScriptRunnerBase.

        # GIVEN
        tmpdir = TempDir(user=windows_user)
        script = StepScript_2023_09(
            actions=StepActions_2023_09(
                onRun=Action_2023_09(command=CommandString_2023_09(r"test.bat"))
            ),
            embeddedFiles=[
                EmbeddedFileText_2023_09(
                    name="Foo",
                    type=EmbeddedFileTypes_2023_09.TEXT,
                    filename="test.bat",
                    data=DataString_2023_09("echo Hello!"),
                )
            ],
        )
        symtab = SymbolTable()
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmpdir.path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmpdir.path,
            os_env_vars=os_env_vars,
            user=windows_user,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        tmpdir.cleanup()

        # THEN
        assert runner.state == ScriptRunnerState.SUCCESS
        messages = collect_queue_messages(message_queue)
        assert "Hello!" in messages

    def test_run_with_let_bindings(
        self,
        tmp_path: Path,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        python_exe: str,
    ) -> None:
        """Test that script-level let bindings are evaluated and available in args."""
        from openjd.model.v1.v2023_09 import LetBinding, ModelParsingContext

        # GIVEN
        ctx = ModelParsingContext(supported_extensions=["EXPR"])
        script = StepScript_2023_09(
            let=[LetBinding("greeting = 'Hello from let binding'", context=ctx)],
            actions=StepActions_2023_09(
                onRun=Action_2023_09(
                    command=CommandString_2023_09("{{ Task.Command }}"),
                    args=[ArgString_2023_09("-c"), ArgString_2023_09("print('{{ greeting }}')")],
                )
            ),
        )
        symtab = SymbolTable({"Task.Command": python_exe})
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmp_path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmp_path,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        # THEN
        assert runner.state == ScriptRunnerState.SUCCESS
        messages = collect_queue_messages(message_queue)
        assert "Hello from let binding" in messages

    def test_run_with_let_bindings_referencing_task_param(
        self,
        tmp_path: Path,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        python_exe: str,
    ) -> None:
        """Test that let bindings can reference Task.Param.* values."""
        from openjd.model.v1.v2023_09 import LetBinding, ModelParsingContext

        # GIVEN
        ctx = ModelParsingContext(supported_extensions=["EXPR"])
        script = StepScript_2023_09(
            let=[LetBinding("msg = 'Frame ' + string(Task.Param.Frame)", context=ctx)],
            actions=StepActions_2023_09(
                onRun=Action_2023_09(
                    command=CommandString_2023_09("{{ Task.Command }}"),
                    args=[ArgString_2023_09("-c"), ArgString_2023_09("print('{{ msg }}')")],
                )
            ),
        )
        symtab = SymbolTable({"Task.Command": python_exe, "Task.Param.Frame": 42})
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmp_path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmp_path,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        # THEN
        assert runner.state == ScriptRunnerState.SUCCESS
        messages = collect_queue_messages(message_queue)
        assert "Frame 42" in messages

    def test_run_with_chained_let_bindings(
        self,
        tmp_path: Path,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        python_exe: str,
    ) -> None:
        """Test that later let bindings can reference earlier ones."""
        from openjd.model.v1.v2023_09 import LetBinding, ModelParsingContext

        # GIVEN
        ctx = ModelParsingContext(supported_extensions=["EXPR"])
        script = StepScript_2023_09(
            let=[
                LetBinding("a = 10", context=ctx),
                LetBinding("b = a * 2", context=ctx),
                LetBinding("result = 'Result: ' + string(b)", context=ctx),
            ],
            actions=StepActions_2023_09(
                onRun=Action_2023_09(
                    command=CommandString_2023_09("{{ Task.Command }}"),
                    args=[ArgString_2023_09("-c"), ArgString_2023_09("print('{{ result }}')")],
                )
            ),
        )
        symtab = SymbolTable({"Task.Command": python_exe})
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmp_path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmp_path,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        # THEN
        assert runner.state == ScriptRunnerState.SUCCESS
        messages = collect_queue_messages(message_queue)
        # b = 10 * 2 = 20
        assert "Result: 20" in messages

    def test_run_with_let_binding_runtime_error(
        self,
        tmp_path: Path,
        message_queue: SimpleQueue,
        queue_handler: QueueHandler,
        python_exe: str,
    ) -> None:
        """Test that runtime errors in let binding evaluation cause task failure."""
        # GIVEN - a let binding that will fail at runtime (division by zero)
        ctx = ModelParsingContext_2023_09(supported_extensions=["EXPR"])
        script = _parse_model(
            model=StepScript_2023_09,
            obj={
                "let": ["bad = 1 // Task.Param.Divisor"],
                "actions": {
                    "onRun": {
                        "command": "{{ Task.Command }}",
                        "args": ["-c", "print('{{ bad }}')"],
                    }
                },
            },
            context=ctx,
        )
        symtab = SymbolTable({"Task.Command": python_exe, "Task.Param.Divisor": 0})
        logger = build_logger(queue_handler)
        runner = StepScriptRunner(
            logger=logger,
            session_working_directory=tmp_path,
            script=script,
            symtab=symtab,
            library=get_default_library(),
            session_files_directory=tmp_path,
        )

        # WHEN
        runner.run()
        while runner.state == ScriptRunnerState.RUNNING:
            time.sleep(0.2)

        # THEN - task should fail due to division by zero
        assert runner.state == ScriptRunnerState.FAILED
        messages = collect_queue_messages(message_queue)
        expected = [
            "openjd_fail: Error evaluating let binding 'bad': Division by zero\n",
            "  bad = 1 // Task.Param.Divisor\n",
            "        ~~^~~~~~~~~~~~~~~~~~~~~",
        ]
        assert "".join(expected) in messages
