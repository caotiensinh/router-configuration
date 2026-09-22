import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from router_configuration.network_sandbox_execution_bridge import (
    EXECUTION_EVIDENCE_SCHEMA,
    NetworkSandboxExecutionBinding,
    NetworkSandboxExecutionError,
    execute_compiled_network_sandbox_scenario,
)
from router_configuration.network_sandbox_scenario_compiler import (
    REQUEST_SCHEMA,
    compile_network_sandbox_scenario,
)


ROUTER_SHA = "4684719faa0ba7b2d15d13fb7a8df61575d6e938"
SANDBOX_SHA = "a9658656efa3b20ae233b1be92d99fda70de4fcc"


def _request():
    return {
        "schema_version": REQUEST_SCHEMA,
        "network_sandbox_sha": SANDBOX_SHA,
        "scenario_id": "execution-bridge-routing-v1",
        "nodes": [
            {
                "name": "client",
                "kind": "host",
                "interfaces": [{"name": "eth0", "address": "192.168.10.10/24"}],
                "routes": [
                    {
                        "destination": "0.0.0.0/0",
                        "out_interface": "eth0",
                        "next_hop": "192.168.10.1",
                    }
                ],
            },
            {
                "name": "edge",
                "kind": "router",
                "interfaces": [
                    {"name": "lan0", "address": "192.168.10.1/24"},
                    {"name": "wan0", "address": "203.0.113.2/30"},
                ],
                "routes": [
                    {
                        "destination": "0.0.0.0/0",
                        "out_interface": "wan0",
                        "next_hop": "203.0.113.1",
                    }
                ],
            },
            {
                "name": "internet",
                "kind": "internet",
                "interfaces": [
                    {"name": "edge0", "address": "203.0.113.1/30"},
                    {"name": "service0", "address": "198.51.100.1/24"},
                ],
                "routes": [
                    {
                        "destination": "192.168.10.0/24",
                        "out_interface": "edge0",
                        "next_hop": "203.0.113.2",
                    }
                ],
            },
        ],
        "links": [
            {
                "name": "client-edge",
                "endpoints": ["client:eth0", "edge:lan0"],
            },
            {
                "name": "edge-internet",
                "endpoints": ["edge:wan0", "internet:edge0"],
                "latency_ms": 20,
            },
        ],
        "tests": [
            {
                "name": "client-reaches-internet",
                "src_node": "client",
                "dst_ip": "198.51.100.1",
                "protocol": "icmp",
                "expect": "reachable",
            }
        ],
    }


def _write_pyproject(root: Path, name: str, version: str) -> None:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\n',
        encoding="utf-8",
    )


class NetworkSandboxExecutionBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.router_root = base / "router"
        self.sandbox_root = base / "sandbox"
        self.router_root.mkdir()
        self.sandbox_root.mkdir()
        _write_pyproject(self.router_root, "router-configuration", "0.1.0.dev0")
        _write_pyproject(self.sandbox_root, "network-sandbox-runtime", "0.6.0")

        self.python = base / "python"
        self.git = base / "git"
        self.python.write_text("", encoding="utf-8")
        self.git.write_text("", encoding="utf-8")

        self.compiled = compile_network_sandbox_scenario(_request()).as_dict()
        self.binding = NetworkSandboxExecutionBinding(
            router_configuration_root=str(self.router_root),
            router_configuration_sha=ROUTER_SHA,
            network_sandbox_root=str(self.sandbox_root),
            network_sandbox_sha=SANDBOX_SHA,
            python_executable=str(self.python),
            git_executable=str(self.git),
            timeout_seconds=30,
        )

    def tearDown(self):
        self.temp.cleanup()

    def _process_side_effect(self, *, passing=True, inspect_env=None):
        git_count = {"value": 0}

        def run(args, **kwargs):
            if inspect_env is not None:
                inspect_env(kwargs["env"])
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["cwd"], str(
                self.router_root if "-C" in args and str(self.router_root) in args
                else self.sandbox_root
            ))

            if args[0] == str(self.git):
                git_count["value"] += 1
                sha = ROUTER_SHA if git_count["value"] == 1 else SANDBOX_SHA
                return CompletedProcess(args, 0, stdout=sha + "\n", stderr="")

            self.assertEqual(args[0], str(self.python))
            self.assertEqual(args[1:3], ["-m", "network_sandbox.cli"])
            scenario_path = Path(args[-1])
            self.assertTrue(scenario_path.is_file())
            raw = scenario_path.read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.compiled["scenario_sha256"],
            )
            parsed = json.loads(raw.decode("utf-8"))
            self.assertEqual(parsed, self.compiled["scenario"])

            if args[3] == "validate":
                return CompletedProcess(
                    args,
                    0,
                    stdout=json.dumps({"valid": True, "snapshot": {"validated": True}}),
                    stderr="",
                )

            self.assertEqual(args[3], "run")
            passed = 1 if passing else 0
            failed = 0 if passing else 1
            result = {
                "scenario": str(scenario_path),
                "warmup": {"requested_ms": 0.0, "applied": False, "result": None},
                "convergence": None,
                "summary": {"total": 1, "passed": passed, "failed": failed},
                "pass": passing,
                "tests": [
                    {
                        "name": "client-reaches-internet",
                        "expect": "reachable",
                        "pass": passing,
                        "result": {
                            "delivered": passing,
                            "reason": "delivered" if passing else "no_route",
                            "trace": [],
                        },
                    }
                ],
                "snapshot": {"nodes": 3, "links": 2},
            }
            return CompletedProcess(
                args,
                0 if passing else 1,
                stdout=json.dumps(result),
                stderr="",
            )

        return run

    def test_executes_validate_then_run_with_exact_sha_provenance(self):
        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run",
            side_effect=self._process_side_effect(passing=True),
        ) as mocked:
            evidence = execute_compiled_network_sandbox_scenario(
                self.compiled,
                binding=self.binding,
            ).as_dict()

        self.assertEqual(mocked.call_count, 4)
        self.assertEqual(evidence["schema_version"], EXECUTION_EVIDENCE_SCHEMA)
        self.assertEqual(evidence["router_configuration_sha"], ROUTER_SHA)
        self.assertEqual(evidence["network_sandbox_sha"], SANDBOX_SHA)
        self.assertEqual(evidence["network_sandbox_release"], "0.6.0")
        self.assertTrue(evidence["runtime_source_verified"])
        self.assertTrue(evidence["scenario_pass"])
        self.assertEqual(
            evidence["summary"],
            {"total": 1, "passed": 1, "failed": 0},
        )
        self.assertEqual(evidence["result"]["scenario"], "execution-bridge-routing-v1")
        self.assertEqual(evidence["evidence_class_ceiling"], "VIRTUAL_VERIFIED")
        self.assertFalse(evidence["hardware_present"])
        self.assertFalse(evidence["hardware_verified"])
        self.assertFalse(evidence["physical_device_verified"])
        self.assertFalse(evidence["production_write_authorized"])
        self.assertFalse(evidence["production_writer_available"])

    def test_failed_scenario_is_preserved_as_negative_evidence(self):
        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run",
            side_effect=self._process_side_effect(passing=False),
        ):
            evidence = execute_compiled_network_sandbox_scenario(
                self.compiled,
                binding=self.binding,
            ).as_dict()

        self.assertFalse(evidence["scenario_pass"])
        self.assertEqual(
            evidence["summary"],
            {"total": 1, "passed": 0, "failed": 1},
        )
        self.assertFalse(evidence["result"]["pass"])

    def test_runtime_sha_mismatch_fails_before_sandbox_execution(self):
        calls = {"count": 0}

        def run(args, **kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                return CompletedProcess(args, 0, stdout=ROUTER_SHA + "\n", stderr="")
            return CompletedProcess(args, 0, stdout="f" * 40 + "\n", stderr="")

        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run",
            side_effect=run,
        ):
            with self.assertRaisesRegex(
                NetworkSandboxExecutionError,
                "network_sandbox_root git HEAD mismatch",
            ):
                execute_compiled_network_sandbox_scenario(
                    self.compiled,
                    binding=self.binding,
                )
        self.assertEqual(calls["count"], 2)

    def test_compiled_sandbox_sha_must_match_binding(self):
        wrong = copy.deepcopy(self.binding)
        wrong = NetworkSandboxExecutionBinding(
            router_configuration_root=wrong.router_configuration_root,
            router_configuration_sha=wrong.router_configuration_sha,
            network_sandbox_root=wrong.network_sandbox_root,
            network_sandbox_sha="f" * 40,
            python_executable=wrong.python_executable,
            git_executable=wrong.git_executable,
            timeout_seconds=wrong.timeout_seconds,
        )
        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run"
        ) as mocked:
            with self.assertRaisesRegex(
                NetworkSandboxExecutionError,
                "does not match execution binding",
            ):
                execute_compiled_network_sandbox_scenario(
                    self.compiled,
                    binding=wrong,
                )
        mocked.assert_not_called()

    def test_wrong_sandbox_project_identity_fails_closed(self):
        _write_pyproject(self.sandbox_root, "other-runtime", "0.6.0")
        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run"
        ) as mocked:
            with self.assertRaisesRegex(
                NetworkSandboxExecutionError,
                "project name must be network-sandbox-runtime",
            ):
                execute_compiled_network_sandbox_scenario(
                    self.compiled,
                    binding=self.binding,
                )
        mocked.assert_not_called()

    def test_invalid_validate_response_stops_before_run(self):
        git_count = {"value": 0}

        def run(args, **kwargs):
            if args[0] == str(self.git):
                git_count["value"] += 1
                sha = ROUTER_SHA if git_count["value"] == 1 else SANDBOX_SHA
                return CompletedProcess(args, 0, stdout=sha + "\n", stderr="")
            return CompletedProcess(
                args,
                0,
                stdout=json.dumps({"valid": False}),
                stderr="",
            )

        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run",
            side_effect=run,
        ) as mocked:
            with self.assertRaisesRegex(
                NetworkSandboxExecutionError,
                "did not confirm valid=true",
            ):
                execute_compiled_network_sandbox_scenario(
                    self.compiled,
                    binding=self.binding,
                )
        self.assertEqual(mocked.call_count, 3)

    def test_runtime_exit_code_outside_zero_or_one_is_rejected(self):
        git_count = {"value": 0}

        def run(args, **kwargs):
            if args[0] == str(self.git):
                git_count["value"] += 1
                sha = ROUTER_SHA if git_count["value"] == 1 else SANDBOX_SHA
                return CompletedProcess(args, 0, stdout=sha + "\n", stderr="")
            if args[3] == "validate":
                return CompletedProcess(args, 0, stdout='{"valid": true}', stderr="")
            return CompletedProcess(args, 2, stdout='{"pass": false}', stderr="")

        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run",
            side_effect=run,
        ):
            with self.assertRaisesRegex(
                NetworkSandboxExecutionError,
                "unsupported exit code 2",
            ):
                execute_compiled_network_sandbox_scenario(
                    self.compiled,
                    binding=self.binding,
                )

    def test_sensitive_environment_is_not_forwarded(self):
        observed = []

        def inspect_env(env):
            observed.append(dict(env))
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertNotIn("PYTHONPATH", env)
            self.assertEqual(env["PYTHONNOUSERSITE"], "1")

        with patch.dict(
            os.environ,
            {
                "GITHUB_TOKEN": "must-not-leak",
                "AWS_SECRET_ACCESS_KEY": "must-not-leak",
                "PYTHONPATH": "/unsafe",
                "PATH": os.environ.get("PATH", ""),
            },
            clear=False,
        ):
            with patch(
                "router_configuration.network_sandbox_execution_bridge.subprocess.run",
                side_effect=self._process_side_effect(
                    passing=True,
                    inspect_env=inspect_env,
                ),
            ):
                execute_compiled_network_sandbox_scenario(
                    self.compiled,
                    binding=self.binding,
                )
        self.assertEqual(len(observed), 4)

    def test_tampered_compiled_record_is_rejected_before_process_launch(self):
        tampered = copy.deepcopy(self.compiled)
        tampered["scenario"]["tests"][0]["expect"] = "blocked"

        with patch(
            "router_configuration.network_sandbox_execution_bridge.subprocess.run"
        ) as mocked:
            with self.assertRaisesRegex(
                NetworkSandboxExecutionError,
                "compiled scenario validation failed",
            ):
                execute_compiled_network_sandbox_scenario(
                    tampered,
                    binding=self.binding,
                )
        mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
