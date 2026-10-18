import os
from enum import Enum
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import mcp_executor as executor
from mcp_armoriq import ArmorGate


class ExecutorPortabilityTests(unittest.TestCase):
    def test_native_lab_fallback_and_real_fixed_commands(self):
        with patch.dict(os.environ, {'MCP_WORKSPACE': ''}):
            self.assertEqual(executor.workspace_path(), executor.LAB.resolve())
            self.assertGreater(executor.execute('read_system_metrics', {'metric_name': 'disk'})['total_bytes'], 0)
            for command in ('pwd', 'date -u', 'df -h /workspace'):
                result = executor.execute('run_system_command', {'command_str': command})
                self.assertEqual(result['exit_code'], 0, result['stderr'])
                self.assertTrue(result['stdout'].strip())

    def test_workspace_with_spaces_and_shell_metacharacters_is_data(self):
        with tempfile.TemporaryDirectory(prefix="lab with spaces ' ") as temporary:
            marker = Path(temporary) / 'should-not-exist'
            with patch.dict(os.environ, {'MCP_WORKSPACE': temporary}):
                result = executor.execute('run_system_command', {'command_str': 'df -h /workspace'})
            self.assertEqual(result['exit_code'], 0, result['stderr'])
            self.assertFalse(marker.exists())

    def test_unknown_command_never_reaches_shell(self):
        with patch.object(executor.subprocess, 'run') as run:
            with self.assertRaises(PermissionError):
                executor.execute('run_system_command', {'command_str': 'pwd; env'})
            run.assert_not_called()

    def test_child_receives_no_provider_keys_or_startup_hooks(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {
            'MCP_WORKSPACE': temporary, 'ARMORIQ_API_KEY': 'do-not-inherit',
            'GROQ_API_KEY': 'do-not-inherit', 'BASH_ENV': 'evil.sh', 'ENV': 'evil.sh'}), patch.object(executor.subprocess, 'run') as run:
            run.return_value = Mock(returncode=0, stdout='ok', stderr='')
            executor.execute('run_system_command', {'command_str': 'pwd'})
            child = run.call_args.kwargs
            self.assertFalse(child['shell'])
            self.assertEqual(child['cwd'], Path(temporary).resolve())
            for key in ('ARMORIQ_API_KEY', 'GROQ_API_KEY', 'BASH_ENV', 'ENV'):
                self.assertNotIn(key, child['env'])

    def test_missing_workspace_does_not_create_host_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / 'missing'
            with patch.dict(os.environ, {'MCP_WORKSPACE': str(missing)}):
                with self.assertRaises(RuntimeError): executor.workspace_path()
            self.assertFalse(missing.exists())

    def test_explicit_bash_path_must_be_absolute(self):
        with patch.dict(os.environ, {'MCP_BASH_PATH': 'bash'}):
            with self.assertRaises(RuntimeError): executor.bash_path()

    def test_native_kernel_uptime_is_positive(self):
        self.assertGreater(executor.kernel_uptime(), 0)

    def test_windows_prefers_git_bash_and_retains_only_os_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            bash = Path(temporary) / 'Git/bin/bash.exe'
            bash.parent.mkdir(parents=True)
            bash.touch()
            env = {'ProgramFiles': temporary, 'SystemRoot': 'C:/Windows', 'GROQ_API_KEY': 'secret'}
            windows = SimpleNamespace(name='nt', getenv=lambda key, default=None: env.get(key, default), environ=env, pathsep=';')
            with patch.object(executor, 'os', windows), patch.object(executor.shutil, 'which', return_value=None):
                self.assertEqual(executor.bash_path(), bash.resolve())
                child = executor.command_environment(bash)
            self.assertEqual(child['SystemRoot'], 'C:/Windows')
            self.assertIn(';', child['PATH'])
            self.assertNotIn('GROQ_API_KEY', child)

    def test_windows_wsl_launcher_is_not_a_git_bash_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            wsl = Path(temporary) / 'System32/bash.exe'
            wsl.parent.mkdir()
            wsl.touch()
            env = {'ProgramFiles': str(Path(temporary) / 'missing')}
            windows = SimpleNamespace(name='nt', getenv=lambda key, default=None: env.get(key, default), environ=env, pathsep=';')
            with patch.object(executor, 'os', windows), patch.object(executor.shutil, 'which', side_effect=lambda name: str(wsl) if name == 'bash' else None):
                with self.assertRaises(RuntimeError): executor.bash_path()


class ArmorCompatibilityTests(unittest.TestCase):
    class Action(Enum):
        ALLOW = 'allow'
        HOLD = 'hold'

    def gate(self, result):
        # Construct an already-open adapter without contacting the provider.
        gate = ArmorGate.__new__(ArmorGate)
        gate.client, gate.session, gate.token = Mock(), Mock(), Mock()
        gate.state = 'plan_created'
        gate.session.check.return_value = result
        return gate

    def test_enum_and_string_actions_keep_strict_allow_semantics(self):
        for action, allowed, expected in ((self.Action.ALLOW, True, True),
                ('allow', True, True), (self.Action.HOLD, True, False),
                ('block', True, False), ('unexpected', True, False), ('allow', 'true', False)):
            with self.subTest(action=action, allowed=allowed):
                gate = self.gate(Mock(action=action, allowed=allowed))
                self.assertEqual(gate.check('read_system_metrics', {'metric_name': 'uptime'})[0], expected)

    def test_close_is_idempotent_and_closed_gate_cannot_allow(self):
        gate = self.gate(Mock(action='allow', allowed=True))
        client, session = gate.client, gate.session
        self.assertEqual(gate.close(), 'completed')
        self.assertEqual(gate.close(), 'not_applicable')
        session.close.assert_called_once()
        client.complete_plan.assert_called_once()
        self.assertFalse(gate.check('read_system_metrics', {'metric_name': 'uptime'})[0])

    def test_blank_key_stays_unavailable(self):
        with patch.dict(os.environ, {'MCP_ARMORIQ_MODE': 'required', 'ARMORIQ_API_KEY': '   '}):
            gate = ArmorGate('blank-key-test')
            self.assertFalse(gate.check('read_system_metrics', {'metric_name': 'uptime'})[0])
