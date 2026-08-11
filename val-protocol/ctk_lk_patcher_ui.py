from __future__ import annotations

import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

try:
    import customtkinter as ctk
except ImportError as exc:
    raise SystemExit(
        "customtkinter is not installed. Run:\n"
        "  python -m pip install -r requirements.txt"
    ) from exc


ROOT = Path(__file__).resolve().parent
DEFAULT_SECRET = "Valeria"
FASTBOOT_TIMEOUT = 90


def parse_serialno(output: str) -> str:
    match = re.search(r"\bserialno:\s*([^\s]+)", output, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    match = re.search(r"\bSerial\s*Number:\s*([^\s]+)", output, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    raise RuntimeError("Could not read serialno from fastboot output.")


def parse_keygen_output(output: str) -> str:
    ignored_prefixes = ("mode", "secret", "device", "alphabet", "const", "partition")
    for line in reversed([item.strip() for item in output.splitlines() if item.strip()]):
        lowered = line.lower()
        if ":" in line:
            continue
        if any(lowered.startswith(prefix) for prefix in ignored_prefixes):
            continue
        if " " in line:
            continue
        if len(line) >= 10:
            return line
    raise RuntimeError("Could not parse generated key.")


class LkPatcherUi(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Val Protocol (Moto LK Patcher)")
        self.geometry("980x720")
        self.minsize(860, 620)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.log_queue: queue.Queue[str] = queue.Queue()
        self.worker: threading.Thread | None = None

        self.lk_path = ctk.StringVar()
        self.secret = ctk.StringVar(value=DEFAULT_SECRET)
        self.erase_partition = ctk.StringVar(value="frp")
        self.replace_partition = ctk.StringVar(value="frp")
        self.flash_partition = ctk.StringVar(value="lk")
        self.keep_analysis = ctk.BooleanVar(value=False)
        self.auto_flash = ctk.BooleanVar(value=True)

        self._build_layout()
        self.after(100, self._drain_log_queue)

    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        top = ctk.CTkFrame(self)
        top.grid(row=0, column=0, padx=14, pady=(14, 8), sticky="ew")
        top.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top, text="LK image").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(top, textvariable=self.lk_path).grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(top, text="Browse", width=110, command=self.browse_lk).grid(row=0, column=2, padx=10, pady=10)

        ctk.CTkLabel(top, text="Secret").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(top, textvariable=self.secret, show="*").grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkLabel(top, text="Fastboot partition").grid(row=1, column=2, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(top, textvariable=self.flash_partition, width=110).grid(row=1, column=3, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(top, text="Erase target").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(top, textvariable=self.erase_partition).grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkLabel(top, text="Replacement target").grid(row=2, column=2, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(top, textvariable=self.replace_partition, width=110).grid(row=2, column=3, padx=10, pady=10, sticky="ew")

        options = ctk.CTkFrame(self)
        options.grid(row=1, column=0, padx=14, pady=8, sticky="ew")
        options.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkCheckBox(options, text="Flash patched LK automatically", variable=self.auto_flash).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkCheckBox(options, text="Keep analysis directory", variable=self.keep_analysis).grid(row=0, column=1, padx=10, pady=10, sticky="w")
        ctk.CTkButton(options, text="Clear log", width=120, command=self.clear_log).grid(row=0, column=2, padx=10, pady=10, sticky="e")

        body = ctk.CTkFrame(self)
        body.grid(row=2, column=0, padx=14, pady=8, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)

        buttons = ctk.CTkFrame(body)
        buttons.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        buttons.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(buttons, text="Unlock Bootloader", command=lambda: self.start_preset("unlock-serial")).grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        ctk.CTkButton(buttons, text="Erase partition", command=lambda: self.start_preset("erase-serial")).grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        ctk.CTkButton(buttons, text="Unlock Bootloader + erase", command=lambda: self.start_preset("unlock-serial-nvdata")).grid(row=0, column=2, padx=8, pady=8, sticky="ew")

        self.log_box = ctk.CTkTextbox(body, wrap="word")
        self.log_box.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

        self.status = ctk.CTkLabel(self, text="Ready", anchor="w")
        self.status.grid(row=3, column=0, padx=14, pady=(0, 12), sticky="ew")

    def browse_lk(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Motorola LK image",
            filetypes=[
                ("LK images", "*.img *.bin"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.lk_path.set(path)

    def clear_log(self) -> None:
        self.log_box.delete("1.0", "end")

    def log(self, text: str) -> None:
        self.log_queue.put(text)

    def _drain_log_queue(self) -> None:
        while True:
            try:
                text = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self.log_box.insert("end", text)
            self.log_box.see("end")
        self.after(100, self._drain_log_queue)

    def set_status(self, text: str) -> None:
        self.status.configure(text=text)

    def start_preset(self, preset: str) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Busy", "A job is already running.")
            return

        lk = Path(self.lk_path.get().strip().strip('"'))
        if not lk.is_file():
            messagebox.showerror("Missing LK", "Select a valid LK image first.")
            return

        secret = self.secret.get().strip()
        if not secret:
            messagebox.showerror("Missing secret", "Secret cannot be empty.")
            return

        if self.auto_flash.get():
            confirmed = messagebox.askyesno(
                "Confirm flash",
                "This will generate a patched LK, flash it with fastboot, reboot to bootloader, "
                "and execute fastboot oem unlock with the generated key.\n\nContinue?",
            )
            if not confirmed:
                return

        self.worker = threading.Thread(target=self.run_workflow, args=(preset, lk, secret), daemon=True)
        self.worker.start()

    def run_command(self, command: list[str], timeout: int | None = None) -> str:
        printable = " ".join(f'"{item}"' if " " in item else item for item in command)
        self.log(f"\n$ {printable}\n")
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            errors="replace",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if output:
            self.log(output if output.endswith("\n") else output + "\n")
        if result.returncode != 0:
            raise RuntimeError(f"Command failed with exit code {result.returncode}: {printable}")
        return output

    def wait_for_fastboot(self) -> str:
        deadline = time.monotonic() + FASTBOOT_TIMEOUT
        last_error = ""
        while time.monotonic() < deadline:
            try:
                output = self.run_command(["fastboot", "getvar", "serialno"], timeout=15)
                return parse_serialno(output)
            except Exception as exc:
                last_error = str(exc)
                time.sleep(2)
        raise RuntimeError(f"Device did not return to fastboot in time. Last error: {last_error}")

    def output_path_for(self, lk: Path, preset: str) -> Path:
        suffix = {
            "unlock-serial": "unlock-serial",
            "erase-serial": f"erase-{self.erase_partition.get().strip() or 'partition'}",
            "unlock-serial-nvdata": f"unlock-{self.replace_partition.get().strip() or 'target'}",
        }[preset]
        return lk.with_name(f"{lk.stem}.{suffix}.patched{lk.suffix or '.img'}")

    def build_patch_command(self, preset: str, lk: Path, output: Path, secret: str) -> list[str]:
        command = [
            sys.executable,
            str(ROOT / "lk_auto_patch.py"),
            str(lk),
            "-o",
            str(output),
            "--preset",
            preset,
        ]
        if self.keep_analysis.get():
            command.extend(["--analysis-dir", str(output.with_suffix("").with_name(output.stem + "_analysis"))])

        if preset == "unlock-serial":
            command.extend(["--key-token-secret", secret])
        elif preset == "erase-serial":
            partition = self.erase_partition.get().strip()
            if not partition:
                raise RuntimeError("Erase target cannot be empty.")
            command.extend(["--erase-token-partition", partition, "--erase-token-secret", secret])
        elif preset == "unlock-serial-nvdata":
            partition = self.replace_partition.get().strip()
            if not partition:
                raise RuntimeError("Replacement target cannot be empty.")
            command.extend(["--key-token-secret", secret, "--erase-partition", partition])
        else:
            raise RuntimeError(f"Unknown preset: {preset}")
        return command

    def generate_key(self, secret: str, serialno: str) -> str:
        output = self.run_command(
            [
                sys.executable,
                str(ROOT / "lk_keygen.py"),
                "--secret",
                secret,
                "--serialno",
                serialno,
                "--count",
                "1",
            ],
            timeout=60,
        )
        return parse_keygen_output(output)

    def run_workflow(self, preset: str, lk: Path, secret: str) -> None:
        try:
            self.log(f"\n=== {preset} ===\n")
            self.after(0, self.set_status, "Reading fastboot serialno...")
            serial_output = self.run_command(["fastboot", "getvar", "serialno"], timeout=30)
            serialno = parse_serialno(serial_output)
            self.log(f"Serialno: {serialno}\n")

            self.after(0, self.set_status, "Generating key...")
            key = self.generate_key(secret, serialno)
            self.log(f"Generated key: {key}\n")

            output = self.output_path_for(lk, preset)
            self.after(0, self.set_status, "Patching LK...")
            self.run_command(self.build_patch_command(preset, lk, output, secret), timeout=300)
            self.log(f"Patched image: {output}\n")

            if self.auto_flash.get():
                partition = self.flash_partition.get().strip() or "lk"
                self.after(0, self.set_status, "Flashing patched LK...")
                self.run_command(["fastboot", "flash", partition, str(output)], timeout=120)

                self.after(0, self.set_status, "Rebooting to bootloader...")
                self.run_command(["fastboot", "reboot", "bootloader"], timeout=30)

                self.after(0, self.set_status, "Waiting for fastboot...")
                fastboot_serial = self.wait_for_fastboot()
                self.log(f"Fastboot ready: {fastboot_serial}\n")

                self.after(0, self.set_status, "Executing operation...")
                self.run_command(["fastboot", "oem", "unlock", key], timeout=120)

            self.after(0, self.set_status, "Done")
            self.log("\nDone.\n")
        except Exception as exc:
            self.after(0, self.set_status, "Failed")
            self.log(f"\nERROR: {exc}\n")
            self.after(0, messagebox.showerror, "Workflow failed", str(exc))


def main() -> int:
    app = LkPatcherUi()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
