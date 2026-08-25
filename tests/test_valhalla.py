import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

try:
    import tkinter  # noqa: F401
except ModuleNotFoundError:
    tkinter_stub = types.ModuleType("tkinter")
    tkinter_stub.ttk = types.SimpleNamespace()
    tkinter_stub.messagebox = types.SimpleNamespace()
    tkinter_stub.scrolledtext = types.SimpleNamespace()
    tkinter_stub.StringVar = object
    sys.modules["tkinter"] = tkinter_stub

import Valhalla


class DummyRoot:
    def update(self):
        pass


def make_tool(work_dir=None):
    tool = Valhalla.ValhallaUnlockTool.__new__(Valhalla.ValhallaUnlockTool)
    tool.root = DummyRoot()
    tool.work_dir = str(work_dir or Path.cwd())
    tool.serial_number = ""
    tool.unlock_key = ""
    tool.logs = []
    tool.log = tool.logs.append
    tool.update_status = Mock()
    tool.update_progress = Mock()
    return tool


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FastbootParsingTests(unittest.TestCase):
    def test_parses_serial_from_platform_tools_stderr_without_footer(self):
        stderr = "serialno: TESTSERIAL1\nFinished. Total time: 0.001s\n"

        value = Valhalla.parse_fastboot_var("", stderr, "serialno")

        self.assertEqual(value, "TESTSERIAL1")

    def test_parses_bootloader_prefixed_variable(self):
        stderr = "(bootloader) securestate: flashing_unlocked\nOKAY [  0.001s]\n"

        value = Valhalla.parse_fastboot_var("", stderr, "securestate")

        self.assertEqual(value, "flashing_unlocked")

    def test_does_not_accept_footer_as_variable_value(self):
        stderr = "Finished. Total time: 0.001s\n"

        value = Valhalla.parse_fastboot_var("", stderr, "serialno")

        self.assertIsNone(value)

    def test_frp_state_classification_handles_unprotected(self):
        self.assertTrue(Valhalla.is_frp_protected("protected (277)"))
        self.assertFalse(Valhalla.is_frp_protected("unprotected"))
        self.assertFalse(Valhalla.is_frp_protected("not protected"))


class FastbootWorkflowTests(unittest.TestCase):
    @patch("Valhalla.subprocess.run")
    def test_get_serial_uses_only_the_serial_line(self, run):
        tool = make_tool()
        tool.check_fastboot_access = Mock(return_value=True)
        run.return_value = completed(
            stderr="serialno: TESTSERIAL1\nFinished. Total time: 0.001s\n"
        )

        serial = tool.get_serial()

        self.assertEqual(serial, "TESTSERIAL1")
        self.assertEqual(tool.serial_number, "TESTSERIAL1")

    @patch("Valhalla.subprocess.run")
    def test_fastboot_access_requires_a_successful_serial(self, run):
        tool = make_tool()
        run.return_value = completed(returncode=1, stderr="< waiting for any device >")

        self.assertFalse(tool.check_fastboot_access())

    @patch("Valhalla.subprocess.run")
    def test_flash_reboots_before_reporting_success(self, run):
        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir) / "lk.unlock-serial.img"
            image.write_bytes(b"test image")
            tool = make_tool(temp_dir)
            tool.reboot_bootloader = Mock(return_value=True)
            run.return_value = completed(stderr="OKAY\n")

            result = tool.flash_lk(image.name)

        self.assertTrue(result)
        tool.reboot_bootloader.assert_called_once_with()
        self.assertEqual(run.call_args.args[0], ["fastboot", "flash", "lk", image.name])
        self.assertEqual(run.call_args.kwargs["cwd"], str(image.parent))

    @patch("Valhalla.subprocess.run")
    def test_flash_fails_when_bootloader_does_not_return(self, run):
        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir) / "lk.unlock-serial.img"
            image.write_bytes(b"test image")
            tool = make_tool(temp_dir)
            tool.reboot_bootloader = Mock(return_value=False)
            run.return_value = completed()

            result = tool.flash_lk(image.name)

        self.assertFalse(result)

    def test_frp_mode_refuses_an_already_unlocked_device(self):
        tool = make_tool()
        tool.get_fastboot_var = Mock(return_value="flashing_unlocked")
        tool.install_dependencies = Mock()

        result = tool.run_frp_only()

        self.assertFalse(result)
        tool.install_dependencies.assert_not_called()
        self.assertTrue(any("Already unlocked" in line for line in tool.logs))

    @patch("Valhalla.messagebox.askyesno", return_value=True, create=True)
    def test_combined_mode_stops_when_frp_verification_fails(self, _confirm):
        tool = make_tool()
        tool.run_frp_only = Mock(return_value=False)
        tool.run_bootloader_unlock = Mock(return_value=True)

        result = tool.run_both()

        self.assertFalse(result)
        tool.run_bootloader_unlock.assert_not_called()

    @patch("Valhalla.subprocess.run")
    def test_frp_mode_reports_protected_state_as_failure(self, run):
        tool = self._configured_frp_tool("protected (277)")
        run.return_value = completed(stderr="OKAY\n")

        result = tool.run_frp_only()

        self.assertFalse(result)
        self.assertTrue(any("failed verification" in line for line in tool.logs))
        self.assertFalse(any("FRP erase verified" in line for line in tool.logs))

    @patch("Valhalla.subprocess.run")
    def test_frp_mode_reports_success_only_after_unprotected_state(self, run):
        tool = self._configured_frp_tool("unprotected")
        run.return_value = completed(stderr="OKAY\n")

        result = tool.run_frp_only()

        self.assertTrue(result)
        self.assertTrue(any("FRP erase verified" in line for line in tool.logs))

    @patch("Valhalla.subprocess.run")
    def test_frp_mode_checks_trigger_return_code(self, run):
        tool = self._configured_frp_tool("unprotected")
        run.return_value = completed(returncode=1, stderr="FAILED\n")

        result = tool.run_frp_only()

        self.assertFalse(result)
        tool.reboot_bootloader.assert_not_called()

    @patch("Valhalla.time.sleep", return_value=None)
    @patch("Valhalla.subprocess.run")
    def test_unlock_requires_unlocked_securestate(self, run, _sleep):
        tool = make_tool()
        tool.get_fastboot_var = Mock(
            side_effect=["oem_locked", "oem_locked", "flashing_unlocked"]
        )
        run.return_value = completed(stderr="OKAY\n")

        result = tool.unlock_bootloader("test-key")

        self.assertTrue(result)
        self.assertTrue(any("unlock verified" in line for line in tool.logs))

    @patch("Valhalla.time.monotonic", side_effect=[0, 181])
    @patch("Valhalla.subprocess.run")
    def test_unlock_does_not_treat_okay_as_verified(self, run, _monotonic):
        tool = make_tool()
        tool.get_fastboot_var = Mock(return_value="oem_locked")
        run.return_value = completed(stderr="OKAY\n")

        result = tool.unlock_bootloader("test-key")

        self.assertFalse(result)
        self.assertTrue(any("was not unlocked" in line for line in tool.logs))

    @staticmethod
    def _configured_frp_tool(frp_state):
        tool = make_tool()
        tool.get_fastboot_var = Mock(side_effect=["oem_locked", frp_state])
        tool.install_dependencies = Mock(return_value=True)
        tool.patch_lk_frp = Mock(return_value=True)
        tool.flash_lk = Mock(return_value=True)
        tool.get_serial = Mock(return_value="TESTSERIAL1")
        tool.generate_key = Mock(return_value="test-key")
        tool.reboot_bootloader = Mock(return_value=True)
        return tool


if __name__ == "__main__":
    unittest.main()
