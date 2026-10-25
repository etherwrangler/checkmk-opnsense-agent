import importlib.util
import json
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _load_agent_module():
    modules = {
        "unbound": {"RR_TYPE_TXT": 16},
        "requests": {},
        "requests.adapters": {"HTTPAdapter": type("HTTPAdapter", (), {})},
        "urllib3": {},
        "urllib3.connection": {"HTTPConnection": type("HTTPConnection", (), {})},
        "urllib3.connectionpool": {
            "HTTPConnectionPool": type("HTTPConnectionPool", (), {})
        },
        "cryptography": {},
        "cryptography.x509": {},
        "cryptography.hazmat": {},
        "cryptography.hazmat.backends": {"default_backend": lambda: None},
        "cryptography.hazmat.primitives": {},
        "cryptography.hazmat.primitives.hashes": {},
        "cryptography.hazmat.primitives.ciphers": {
            "Cipher": type("Cipher", (), {}),
            "algorithms": types.SimpleNamespace(),
            "modes": types.SimpleNamespace(),
        },
        "cryptography.hazmat.primitives.kdf": {},
        "cryptography.hazmat.primitives.kdf.pbkdf2": {
            "PBKDF2HMAC": type("PBKDF2HMAC", (), {})
        },
        "OpenSSL": {
            "SSL": types.SimpleNamespace(),
            "crypto": types.SimpleNamespace(),
        },
    }
    for name, attributes in modules.items():
        module = types.ModuleType(name)
        for attribute, value in attributes.items():
            setattr(module, attribute, value)
        sys.modules.setdefault(name, module)

    spec = importlib.util.spec_from_file_location(
        "opnsense_checkmk_agent_under_test",
        REPOSITORY_ROOT / "opnsense_checkmk_agent.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AGENT = _load_agent_module()

NVME_JSON = json.dumps(
    {
        "json_format_version": [1, 0],
        "smartctl": {"version": [7, 5], "exit_status": 0},
        "device": {"name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"},
        "model_name": "WDC PC SN520",
        "serial_number": "REDACTED-NVME",
        "temperature": {"current": 49},
        "smart_status": {"passed": True, "nvme": {"value": 0}},
        "nvme_smart_health_information_log": {
            "critical_warning": 0,
            "temperature": 49,
            "available_spare": 100,
            "available_spare_threshold": 5,
            "percentage_used": 16,
            "media_errors": 0,
        },
    },
    separators=(",", ":"),
)

ATA_JSON = json.dumps(
    {
        "json_format_version": [1, 0],
        "smartctl": {"version": [7, 5], "exit_status": 0},
        "device": {"name": "/dev/ada0", "type": "atacam", "protocol": "ATA"},
        "model_name": "Synthetic SATA SSD",
        "serial_number": "REDACTED-ATA",
        "temperature": {"current": 35},
        "smart_status": {"passed": True},
        "ata_smart_attributes": {"table": []},
    },
    separators=(",", ":"),
)


class SmartPosixTests(unittest.TestCase):
    def setUp(self):
        self.checker = object.__new__(AGENT.checkmk_checker)

    def test_emits_official_sections_with_freebsd_scan_arguments(self):
        scan_output = "\n".join(
            (
                "/dev/nvme0 -d nvme # /dev/nvme0, NVMe device",
                "/dev/ada0 -d atacam # /dev/ada0, ATA device",
            )
        )
        calls = []

        def run_smartctl(arguments, timeout=30):
            calls.append((arguments, timeout))
            if arguments == ["-V"]:
                return "smartctl 7.5 2025-04-30 r5714 [FreeBSD]"
            if arguments == ["--scan"]:
                return scan_output
            if "/dev/nvme0" in arguments:
                return NVME_JSON + "\n"
            if "/dev/ada0" in arguments:
                return ATA_JSON + "\n"
            self.fail(f"Unexpected smartctl arguments: {arguments!r}")

        self.checker._run_smartctl = run_smartctl
        with mock.patch.object(AGENT.os.path, "exists", return_value=True):
            output = self.checker.check_smart_posix()

        self.assertEqual(
            output,
            [
                "<<<smart_posix_all:sep(0)>>>",
                NVME_JSON,
                "",
                ATA_JSON,
                "",
                "<<<smart_posix_scan_arg:sep(0)>>>",
                NVME_JSON,
                "",
                ATA_JSON,
                "",
            ],
        )
        self.assertEqual(
            calls,
            [
                (["-V"], 10),
                (["--scan"], 10),
                (["--all", "--json=c", "/dev/nvme0"], 30),
                (["--all", "--json=c", "/dev/ada0"], 30),
                (["--scan"], 10),
                (["--all", "--json=c", "/dev/nvme0", "-d", "nvme"], 30),
                (["--all", "--json=c", "/dev/ada0", "-d", "atacam"], 30),
            ],
        )

    def test_nonzero_smart_status_keeps_json_output(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=8, stdout=NVME_JSON
        )
        with mock.patch.object(AGENT.subprocess, "run", return_value=completed):
            output = self.checker._run_smartctl(["--all", "--json=c", "/dev/nvme0"])

        self.assertEqual(output, NVME_JSON)

    def test_timeout_returns_empty_output(self):
        with mock.patch.object(
            AGENT.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="smartctl", timeout=30),
        ):
            output = self.checker._run_smartctl(["--all", "--json=c", "/dev/nvme0"])

        self.assertEqual(output, "")

    def test_missing_smartctl_emits_no_sections(self):
        with mock.patch.object(AGENT.os.path, "exists", return_value=False):
            self.assertEqual(self.checker.check_smart_posix(), [])

    def test_smartctl_older_than_version_seven_emits_no_sections(self):
        self.checker._run_smartctl = mock.Mock(return_value="smartctl 6.6")
        with mock.patch.object(AGENT.os.path, "exists", return_value=True):
            self.assertEqual(self.checker.check_smart_posix(), [])


if __name__ == "__main__":
    unittest.main()
