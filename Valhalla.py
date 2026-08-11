#!/usr/bin/env python3
"""
🏔️ VALHALLA UNLOCK TOOL v> :)
====================================
Created by: RomLord14495
Exploit: Val Protocol by Maikyxd

🙏 SPECIAL THANKS 🙏
To Maikyxd for creating the Val Protocol exploit
which made this tool possible.
Without your work, this tool wouldn't exist.
Thank you! ❤️

⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️
THIS CAN PERMANENTLY BRICK YOUR DEVICE!
- Flashing a bad LK can hard-brick your phone
- DO NOT flash the original LK back after unlocking
- Keep a full stock firmware backup ready
- Use at your own risk! NO responsibility accepted!

Supported Devices:
- Motorola MediaTek devices only
- Moto G series, Edge series, Razr series with MTK chips
"""

import os
import sys
import subprocess
import platform
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, StringVar
import urllib.request
import zipfile
import io

VERSION = "> :)"
TOOL_NAME = "Valhalla Unlock Tool"
CREATOR = "RomLord14495"
EXPLOIT = "Val Protocol by Maikyxd"
SECRET = "Valeria"
VAL_PROTOCOL_ZIP = "https://github.com/Maikyxd/val-protocol/archive/refs/heads/main.zip"

class ValhallaUnlockTool:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{TOOL_NAME} v{VERSION}")
        self.root.geometry("850x750")
        self.root.resizable(True, True)
        self.root.configure(bg='#1a1a2e')
        
        self.serial_number = ""
        self.unlock_key = ""
        self.selected_mode = StringVar(value="bootloader")
        self.work_dir = os.path.dirname(os.path.abspath(__file__))
        self.os_name = platform.system()
        
        self.setup_ui()
        self.log("=" * 70)
        self.log(f"🏔️ {TOOL_NAME} v{VERSION}")
        self.log(f"👤 Created by: {CREATOR}")
        self.log(f"⚡ Exploit: {EXPLOIT}")
        self.log("=" * 70)
        self.log("")
        self.log("🙏 SPECIAL THANKS 🙏")
        self.log("To Maikyxd for creating the Val Protocol exploit")
        self.log("which made this tool possible.")
        self.log("Thank you! ❤️")
        self.log("=" * 70)
        self.log("")
        self.log("⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️")
        self.log("THIS CAN PERMANENTLY BRICK YOUR DEVICE!")
        self.log("DO NOT flash the original LK back after unlocking!")
        self.log("Use at your own risk. NO responsibility accepted!")
        self.log("=" * 70)
        self.log("")
        self.log("[*] Supported: Motorola MediaTek devices only")
        self.log("")
        self.log(f"[*] Operating System: {self.os_name}")
        self.log("[*] Starting system check...")
        self.log("")
        self.check_system()
        
    def setup_ui(self):
        title_frame = tk.Frame(self.root, bg='#1a1a2e')
        title_frame.pack(pady=10)
        
        title = tk.Label(title_frame, text=f"🏔️ {TOOL_NAME} v{VERSION}", 
                        font=("Arial", 26, "bold"), fg='#e94560', bg='#1a1a2e')
        title.pack()
        
        subtitle = tk.Label(title_frame, text=f"Created by {CREATOR} | Exploit: {EXPLOIT}",
                           font=("Arial", 10), fg='#eeeeee', bg='#1a1a2e')
        subtitle.pack()
        
        subtitle2 = tk.Label(title_frame, text="🙏 Thanks to Maikyxd for Val Protocol! ❤️",
                            font=("Arial", 9), fg='#ffd93d', bg='#1a1a2e')
        subtitle2.pack()
        
        subtitle3 = tk.Label(title_frame, text="Supported: Motorola MediaTek devices only",
                            font=("Arial", 9), fg='#ffd93d', bg='#1a1a2e')
        subtitle3.pack()
        
        warning_frame = tk.Frame(self.root, bg='#2d132c')
        warning_frame.pack(pady=10, padx=20, fill="x")
        
        warning_label = tk.Label(warning_frame, 
                               text="⚠️⚠️⚠️ WARNING: CAN PERMANENTLY BRICK YOUR DEVICE! ⚠️⚠️⚠️\nDO NOT flash original LK back! Use at your own risk!",
                               font=("Arial", 12, "bold"), fg='#ff6b6b', bg='#2d132c')
        warning_label.pack(pady=5)
        
        mode_frame = tk.LabelFrame(self.root, text="⚡ Select Operation Mode", 
                                   padx=10, pady=10, font=("Arial", 12, "bold"),
                                   fg='#eeeeee', bg='#16213e')
        mode_frame.pack(pady=10, padx=20, fill="x")
        
        modes = [
            ("🔓 Bootloader Unlock (Factory Reset)", "bootloader"),
            ("🔑 FRP Bypass Only (No Factory Reset)", "frp"),
            ("⚡ Bootloader Unlock + FRP Bypass", "both")
        ]
        
        for text, value in modes:
            rb = tk.Radiobutton(mode_frame, text=text, variable=self.selected_mode, 
                               value=value, font=("Arial", 10), fg='#eeeeee', 
                               bg='#16213e', selectcolor='#1a1a2e')
            rb.pack(anchor="w", pady=2)
        
        status_frame = tk.Frame(self.root, bg='#1a1a2e')
        status_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.status_display = scrolledtext.ScrolledText(status_frame, height=14, width=80,
                                                        bg='#0a0a1a', fg='#00ff88',
                                                        font=("Courier", 9), insertbackground='white')
        self.status_display.pack(fill="both", expand=True)
        self.status_display.config(state=tk.DISABLED)
        
        self.progress = ttk.Progressbar(self.root, length=500, mode='determinate')
        self.progress.pack(pady=5)
        
        button_frame = tk.Frame(self.root, bg='#1a1a2e')
        button_frame.pack(pady=10)
        
        style = {"width": 18, "height": 2, "font": ("Arial", 10, "bold")}
        
        self.check_btn = tk.Button(button_frame, text="🔍 Check Device", 
                                   command=self.check_device, bg='#00b894', fg='white',
                                   **style)
        self.check_btn.pack(side=tk.LEFT, padx=5)
        
        self.unlock_btn = tk.Button(button_frame, text="⚡ Run Valhalla", 
                                    command=self.run_unlock, bg='#e94560', fg='white',
                                    state=tk.DISABLED, **style)
        self.unlock_btn.pack(side=tk.LEFT, padx=5)
        
        self.reset_btn = tk.Button(button_frame, text="🔄 Reset", 
                                   command=self.reset_tool, bg='#fdcb6e', fg='#1a1a2e',
                                   width=10, height=2, font=("Arial", 10, "bold"))
        self.reset_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_bar = tk.Label(self.root, text="⚡ Ready", relief=tk.SUNKEN, 
                                   anchor=tk.W, bg='#0a0a1a', fg='#00ff88',
                                   font=("Arial", 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def log(self, message):
        self.status_display.config(state=tk.NORMAL)
        self.status_display.insert(tk.END, message + "\n")
        self.status_display.see(tk.END)
        self.status_display.config(state=tk.DISABLED)
        self.root.update()
        
    def update_status(self, message):
        self.status_bar.config(text=f"⚡ {message}")
        self.root.update()
        
    def update_progress(self, value):
        self.progress['value'] = value
        self.root.update()
        
    def check_system(self):
        self.log("[VERBOSE] ========================================")
        self.log("[VERBOSE] SYSTEM CHECK STARTING")
        self.log("[VERBOSE] ========================================")
        self.log(f"[VERBOSE] Python version: {sys.version.split()[0]}")
        self.log(f"[VERBOSE] Working directory: {os.getcwd()}")
        self.log(f"[VERBOSE] Script directory: {self.work_dir}")
        
        self.log("")
        self.log("[*] Checking fastboot...")
        fastboot_path = shutil.which("fastboot")
        if fastboot_path:
            self.log(f"[+] Fastboot found: {fastboot_path}")
            try:
                result = subprocess.run(["fastboot", "--version"], capture_output=True, text=True, timeout=3)
                version_line = result.stdout.strip().split('\n')[0] if result.stdout else "unknown"
                self.log(f"[VERBOSE] Fastboot version: {version_line}")
            except:
                self.log("[VERBOSE] Could not get fastboot version")
        else:
            self.log("[!] Fastboot not found")
            if self.os_name == "Windows":
                self.show_windows_fastboot_warning()
            else:
                self.install_fastboot_linux()
        
        self.log("")
        self.log("[*] Checking for lk.img...")
        lk_path = os.path.join(self.work_dir, "lk.img")
        if os.path.exists(lk_path):
            file_size = os.path.getsize(lk_path)
            self.log(f"[+] ✅ lk.img found! ({file_size} bytes)")
            self.log(f"[VERBOSE] lk.img path: {lk_path}")
        else:
            self.log("[!] ❌ lk.img NOT found!")
            self.log(f"[VERBOSE] Expected location: {lk_path}")
            self.log("[*] Please place your stock lk.img in the tool directory.")
            self.log("[*] You can extract it from your stock firmware ZIP.")
        
        if self.os_name == "Linux":
            self.log("")
            self.log("[*] Checking USB permissions...")
            self.setup_udev_rules_linux()
        
        self.log("")
        self.log("[VERBOSE] ========================================")
        self.log("[VERBOSE] SYSTEM CHECK COMPLETE")
        self.log("[VERBOSE] ========================================")
        self.log("")
        self.log("⚡ Ready. Select a mode and connect your phone in fastboot mode.")
        self.update_status("Ready")
        
    def show_windows_fastboot_warning(self):
        messagebox.showwarning(
            "Fastboot Required",
            "Fastboot is not installed or not in PATH.\n\n"
            "Please install Android Platform Tools:\n"
            "1. Download from: https://developer.android.com/studio/releases/platform-tools\n"
            "2. Extract the ZIP\n"
            "3. Add the folder to your system PATH\n"
            "4. Restart this tool"
        )
        
    def install_fastboot_linux(self):
        is_root = (os.geteuid() == 0)
        sudo_cmd = [] if is_root else ["sudo"]
        try:
            self.log("[VERBOSE] Attempting to install fastboot via apt...")
            self.log("[*] Installing fastboot via apt...")
            subprocess.run(sudo_cmd + ["apt", "update"], check=True, capture_output=True)
            subprocess.run(sudo_cmd + ["apt", "install", "android-tools-fastboot", "-y"], check=True, capture_output=True)
            self.log("[+] Fastboot installed successfully!")
            return True
        except:
            self.log("[!] Failed to install fastboot.")
            self.show_linux_fastboot_instructions()
            return False
            
    def show_linux_fastboot_instructions(self):
        messagebox.showinfo(
            "Fastboot Installation",
            "Fastboot could not be installed automatically.\n\n"
            "Please run:\n"
            "sudo apt update\n"
            "sudo apt install android-tools-fastboot -y\n\n"
            "Then restart this tool."
        )
        
    def setup_udev_rules_linux(self):
        is_root = (os.geteuid() == 0)
        sudo_cmd = [] if is_root else ["sudo"]
        
        self.log("[VERBOSE] Checking udev installation...")
        if not shutil.which("udevadm"):
            self.log("[!] udevadm not found. Installing udev...")
            try:
                subprocess.run(sudo_cmd + ["apt", "update"], check=True, capture_output=True)
                subprocess.run(sudo_cmd + ["apt", "install", "systemd", "udev", "-y"], check=True, capture_output=True)
                self.log("[+] udev installed successfully.")
                self.log(f"[VERBOSE] udevadm path: {shutil.which('udevadm')}")
            except:
                self.show_udev_instructions()
                return False
        else:
            self.log(f"[VERBOSE] udevadm found: {shutil.which('udevadm')}")
        
        self.log("[VERBOSE] Testing fastboot access...")
        try:
            result = subprocess.run(["fastboot", "getvar", "serialno"], 
                                   capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                self.log("[VERBOSE] Fastboot access: OK (return code 0)")
                self.log("[+] USB permissions OK")
                return True
            elif "permission" in result.stderr.lower():
                self.log("[VERBOSE] Fastboot access: Permission denied")
                self.log("[VERBOSE] stderr: " + result.stderr.strip())
            else:
                self.log(f"[VERBOSE] Fastboot return code: {result.returncode}")
                self.log("[VERBOSE] Fastboot access: Possibly working but no device")
        except FileNotFoundError:
            self.log("[VERBOSE] Fastboot not found")
        except Exception as e:
            self.log(f"[VERBOSE] Fastboot test error: {str(e)}")
        
        self.log("[VERBOSE] Checking for existing udev rules...")
        try:
            with open("/etc/udev/rules.d/51-android.rules", "r") as f:
                content = f.read()
                if "0e8d" in content:
                    self.log("[VERBOSE] udev rules already exist")
                    self.log("[+] udev rules already exist")
                    self.log("[!] You may need to log out and back in.")
                    return True
                else:
                    self.log("[VERBOSE] udev rules file exists but missing vendor IDs")
        except FileNotFoundError:
            self.log("[VERBOSE] No udev rules file found")
        except Exception as e:
            self.log(f"[VERBOSE] Error reading udev rules: {e}")
        
        try:
            self.log("[*] Setting up USB permissions...")
            self.log("[VERBOSE] Creating udev rules...")
            rules = 'SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", MODE="0666", GROUP="plugdev"\nSUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"\nSUBSYSTEM=="usb", ATTR{idVendor}=="2e04", MODE="0666", GROUP="plugdev"\n'
            with open("/tmp/51-android.rules", "w") as f:
                f.write(rules)
            self.log("[VERBOSE] Rules file created at /tmp/51-android.rules")
            
            subprocess.run(sudo_cmd + ["cp", "/tmp/51-android.rules", "/etc/udev/rules.d/"], check=True)
            self.log("[VERBOSE] Copied rules to /etc/udev/rules.d/")
            
            subprocess.run(sudo_cmd + ["udevadm", "control", "--reload-rules"], check=True)
            self.log("[VERBOSE] Reloaded udev rules")
            
            subprocess.run(sudo_cmd + ["udevadm", "trigger"], check=True)
            self.log("[VERBOSE] Triggered udev events")
            
            user = os.environ.get("SUDO_USER") or os.environ.get("USER")
            if user and user != "root":
                subprocess.run(sudo_cmd + ["usermod", "-a", "-G", "plugdev", user], check=True)
                subprocess.run(sudo_cmd + ["usermod", "-a", "-G", "dialout", user], check=True)
                self.log(f"[VERBOSE] Added user '{user}' to plugdev and dialout groups")
            
            self.log("[+] udev rules configured successfully!")
            self.log("[!] Please log out and back in for changes to take effect.")
            self.log("[VERBOSE] udev setup complete")
            return True
        except Exception as e:
            self.log(f"[!] Could not auto-setup udev rules: {e}")
            self.log("[VERBOSE] udev setup error: " + str(e))
            self.show_udev_instructions()
            return False
            
    def show_udev_instructions(self):
        instructions = (
            "Please set up USB permissions manually.\n\n"
            "Copy and paste these commands into a terminal:\n\n"
            "sudo bash -c 'cat > /etc/udev/rules.d/51-android.rules << EOF\n"
            'SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", MODE="0666", GROUP="plugdev"\n'
            'SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"\n'
            'SUBSYSTEM=="usb", ATTR{idVendor}=="2e04", MODE="0666", GROUP="plugdev"\n'
            "EOF'\n\n"
            "sudo udevadm control --reload-rules\n"
            "sudo udevadm trigger\n"
            "sudo usermod -a -G plugdev $USER\n"
            "sudo usermod -a -G dialout $USER\n\n"
            "Then log out and back in.\n\n"
            "After that, restart this tool."
        )
        messagebox.showinfo("USB Permissions Setup", instructions)
            
    def install_pip_package(self, *args):
        """Install pip packages with automatic fallback to --break-system-packages on Linux."""
        cmd = [sys.executable, "-m", "pip", "install"] + list(args)
        self.log(f"[VERBOSE] Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return True
            if self.os_name == "Linux" and "--break-system-packages" not in cmd:
                self.log("[VERBOSE] Retrying with --break-system-packages")
                cmd.append("--break-system-packages")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    return True
            self.log(f"[VERBOSE] Pip install failed: {result.stderr}")
            return False
        except Exception as e:
            self.log(f"[VERBOSE] Pip install error: {str(e)}")
            return False
            
    def check_fastboot_access(self):
        self.log("[VERBOSE] Checking fastboot accessibility...")
        try:
            result = subprocess.run(["fastboot", "getvar", "serialno"], 
                                   capture_output=True, text=True, timeout=3)
            self.log(f"[VERBOSE] Fastboot return code: {result.returncode}")
            if result.returncode == 0:
                self.log("[VERBOSE] Fastboot is accessible")
                return True
            elif result.returncode == 1:
                self.log("[VERBOSE] Fastboot returned 1 (device not connected)")
                return True
            else:
                self.log(f"[VERBOSE] Fastboot returned {result.returncode}")
                return False
        except FileNotFoundError:
            self.log("[VERBOSE] Fastboot not found")
            return False
        except Exception as e:
            self.log(f"[VERBOSE] Fastboot check error: {str(e)}")
            return False
            
    def get_serial(self):
        self.log("[*] Getting device serial number...")
        self.update_status("Getting serial number...")
        self.root.update()
        
        self.log("[VERBOSE] Checking fastboot access...")
        if not self.check_fastboot_access():
            self.log("[!] Fastboot not accessible.")
            if self.os_name == "Linux":
                self.log("[*] Try: sudo python3 valhalla.py")
                self.log("[*] Or set up udev rules and log out/back in.")
            else:
                self.log("[*] Make sure fastboot is installed and in PATH.")
            messagebox.showinfo("Fastboot Error", 
                               "Fastboot is not accessible.\n\n"
                               "On Linux: Try running with sudo\n"
                               "On Windows: Make sure fastboot is in PATH")
            return None
        
        self.log("[VERBOSE] Running: fastboot getvar serialno")
        
        try:
            result = subprocess.run(["fastboot", "getvar", "serialno"], 
                                  capture_output=True, text=True, timeout=5)
            
            self.log(f"[VERBOSE] Return code: {result.returncode}")
            
            if result.returncode != 0:
                self.log("[!] Fastboot returned error")
                self.log(f"[VERBOSE] Error: {result.stderr.strip()}")
                return None
            
            output = result.stdout.strip()
            err_output = result.stderr.strip()
            
            self.log(f"[VERBOSE] stdout: '{output}'")
            if err_output:
                self.log(f"[VERBOSE] stderr: '{err_output}'")
            
            if "serialno:" in output:
                serial = output.split("serialno:")[1].strip()
                if serial:
                    self.log(f"[+] Serial number: {serial}")
                    self.serial_number = serial
                    return serial
                else:
                    self.log("[VERBOSE] serialno: found but value is empty")
            
            if output and len(output) > 5 and " " not in output and ":" not in output:
                self.log(f"[+] Serial number: {output}")
                self.serial_number = output
                return output
            
            if output and " " in output and len(output) > 10:
                serial = output.replace(" ", "")
                if len(serial) > 5:
                    self.log(f"[+] Serial number: {serial}")
                    self.serial_number = serial
                    return serial
                else:
                    self.log("[VERBOSE] Spaced output too short after removing spaces")
            
            if "serialno:" in err_output:
                serial = err_output.split("serialno:")[1].strip()
                if serial:
                    self.log(f"[+] Serial number: {serial}")
                    self.serial_number = serial
                    return serial
                
            self.log("[!] Could not parse serial number.")
            self.log(f"[VERBOSE] Raw output: '{output}'")
            self.log("[*] Make sure your phone is in fastboot mode and connected.")
            self.log("[*] Try: fastboot getvar serialno in a terminal")
            return None
            
        except subprocess.TimeoutExpired:
            self.log("[!] Fastboot timed out. Make sure phone is in fastboot mode.")
            return None
        except Exception as e:
            self.log(f"[!] Error: {str(e)}")
            self.log(f"[VERBOSE] Exception: {type(e).__name__}")
            return None
            
    def download_val_protocol(self):
        self.log("[*] Downloading Val Protocol from GitHub...")
        self.log("[VERBOSE] URL: " + VAL_PROTOCOL_ZIP)
        self.update_status("Downloading Val Protocol...")
        try:
            self.log("[VERBOSE] Sending request...")
            with urllib.request.urlopen(VAL_PROTOCOL_ZIP) as response:
                self.log(f"[VERBOSE] Response code: {response.getcode()}")
                data = response.read()
                self.log(f"[VERBOSE] Downloaded {len(data)} bytes")
            
            self.log("[VERBOSE] Extracting ZIP...")
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                file_list = z.namelist()
                self.log(f"[VERBOSE] ZIP contains {len(file_list)} files")
                root_folder = file_list[0].split('/')[0]
                self.log(f"[VERBOSE] Root folder: {root_folder}")
                for file in file_list:
                    if file.startswith(root_folder + '/'):
                        target = os.path.join("val-protocol", file[len(root_folder)+1:])
                        if file.endswith('/'):
                            os.makedirs(target, exist_ok=True)
                        else:
                            os.makedirs(os.path.dirname(target), exist_ok=True)
                            with open(target, 'wb') as f:
                                f.write(z.read(file))
            
            self.log("[+] Val Protocol downloaded and extracted")
            self.log("[VERBOSE] Val Protocol location: " + os.path.join(self.work_dir, "val-protocol"))
            self.log("🙏 Thanks again to Maikyxd for this exploit!")
            return True
        except Exception as e:
            self.log(f"[!] Failed to download Val Protocol: {e}")
            self.log(f"[VERBOSE] Download error: {type(e).__name__}")
            return False
            
    def ensure_val_protocol(self):
        """Ensure val-protocol folder exists and is complete."""
        val_path = os.path.join(self.work_dir, "val-protocol")
        if os.path.exists(val_path):
            required_files = ["lk_auto_patch.py", "lk_keygen.py", "requirements.txt"]
            missing = [f for f in required_files if not os.path.exists(os.path.join(val_path, f))]
            if missing:
                self.log(f"[VERBOSE] val-protocol exists but missing: {', '.join(missing)}")
                self.log("[*] Deleting incomplete val-protocol folder...")
                try:
                    shutil.rmtree(val_path)
                    self.log("[VERBOSE] Deleted old val-protocol folder")
                except Exception as e:
                    self.log(f"[VERBOSE] Could not delete: {e}")
                    return False
            else:
                self.log("[VERBOSE] val-protocol is complete")
                return True
        
        return self.download_val_protocol()
            
    def install_dependencies(self):
        self.log("[*] Installing dependencies...")
        self.log("[VERBOSE] Starting dependency installation...")
        self.update_status("Installing dependencies...")
        self.update_progress(10)
        
        if not self.ensure_val_protocol():
            self.log("[!] Could not obtain Val Protocol")
            return False
        
        val_protocol_path = os.path.join(self.work_dir, "val-protocol")
        
        self.log("[*] Installing liblk...")
        if not self.install_pip_package("git+https://github.com/R0rt1z2/liblk"):
            self.log("[!] liblk installation failed")
            return False
        self.log("[+] liblk installed")
        
        req_file = os.path.join(val_protocol_path, "requirements.txt")
        if os.path.exists(req_file):
            self.log("[*] Installing requirements...")
            self.log(f"[VERBOSE] Requirements file: {req_file}")
            if not self.install_pip_package("-r", req_file):
                self.log("[!] Failed to install requirements")
                return False
            self.log("[+] Requirements installed")
        else:
            self.log("[!] requirements.txt not found, skipping")
            self.log(f"[VERBOSE] Expected at: {req_file}")
        
        self.update_progress(30)
        self.log("[+] Dependencies installed successfully")
        self.log("[VERBOSE] Dependency installation complete")
        return True
            
    def generate_key(self, serial):
        self.log("[*] Generating unlock key...")
        self.log(f"[VERBOSE] Serial: {serial}")
        self.log(f"[VERBOSE] Secret: {SECRET}")
        self.update_status("Generating key...")
        self.update_progress(70)
        self.root.update()
        
        try:
            os.chdir("val-protocol")
            self.log("[VERBOSE] Working directory: " + os.getcwd())
            cmd = [sys.executable, "lk_keygen.py", "--secret", SECRET, "--serialno", serial, "--count", "1"]
            self.log(f"[VERBOSE] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            os.chdir("..")
            self.log(f"[VERBOSE] Return code: {result.returncode}")
            
            if result.returncode != 0:
                self.log("[!] Key generation failed")
                self.log(f"[VERBOSE] Error: {result.stderr}")
                return None
                
            lines = result.stdout.strip().split("\n")
            self.log(f"[VERBOSE] Output lines: {len(lines)}")
            key = lines[-1].strip()
            self.log(f"[VERBOSE] Extracted key: {key}")
            
            if len(key) > 5:
                self.log(f"[+] Key generated: {key}")
                self.unlock_key = key
                return key
            else:
                self.log("[!] Failed to extract key")
                self.log(f"[VERBOSE] Raw output: {result.stdout}")
                return None
        except Exception as e:
            self.log(f"[!] Key generation error: {str(e)}")
            self.log(f"[VERBOSE] Exception: {type(e).__name__}")
            return None
            
    def patch_lk_frp(self):
        self.log("[*] Patching lk.img for FRP erase...")
        self.log("[VERBOSE] Starting FRP patch...")
        self.root.update()
        
        lk_path = os.path.join(self.work_dir, "lk.img")
        if not os.path.exists(lk_path):
            self.log("[!] lk.img not found. Place it in the tool directory.")
            self.log(f"[VERBOSE] Expected: {lk_path}")
            return False
        else:
            self.log(f"[VERBOSE] Found lk.img at: {lk_path}")
            self.log(f"[VERBOSE] Size: {os.path.getsize(lk_path)} bytes")
            
        try:
            os.chdir("val-protocol")
            self.log("[VERBOSE] Working directory: " + os.getcwd())
            cmd = [sys.executable, "lk_auto_patch.py", "../lk.img", "-o", "../lk.erase-frp.img",
                  "--preset", "erase-serial", "--erase-token-partition", "frp", "--erase-token-secret", SECRET]
            self.log(f"[VERBOSE] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            os.chdir("..")
            self.log(f"[VERBOSE] Return code: {result.returncode}")
            
            if result.returncode == 0:
                self.log("[+] FRP patched lk.img created")
                self.log("[VERBOSE] Output: " + result.stdout.strip())
                return True
            else:
                self.log("[!] Patching failed")
                self.log(f"[VERBOSE] Error: {result.stderr}")
                return False
        except Exception as e:
            self.log(f"[!] Patching error: {str(e)}")
            self.log(f"[VERBOSE] Exception: {type(e).__name__}")
            return False
            
    def patch_lk_unlock(self):
        self.log("[*] Patching lk.img for bootloader unlock...")
        self.log("[VERBOSE] Starting bootloader patch...")
        self.root.update()
        
        lk_path = os.path.join(self.work_dir, "lk.img")
        if not os.path.exists(lk_path):
            self.log("[!] lk.img not found. Place it in the tool directory.")
            self.log(f"[VERBOSE] Expected: {lk_path}")
            return False
        else:
            self.log(f"[VERBOSE] Found lk.img at: {lk_path}")
            self.log(f"[VERBOSE] Size: {os.path.getsize(lk_path)} bytes")
            
        try:
            os.chdir("val-protocol")
            self.log("[VERBOSE] Working directory: " + os.getcwd())
            cmd = [sys.executable, "lk_auto_patch.py", "../lk.img", "-o", "../lk.unlock-serial.img",
                  "--preset", "unlock-serial", "--key-token-secret", SECRET]
            self.log(f"[VERBOSE] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            os.chdir("..")
            self.log(f"[VERBOSE] Return code: {result.returncode}")
            
            if result.returncode == 0:
                self.log("[+] Bootloader patched lk.img created")
                self.log("[VERBOSE] Output: " + result.stdout.strip())
                return True
            else:
                self.log("[!] Patching failed")
                self.log(f"[VERBOSE] Error: {result.stderr}")
                return False
        except Exception as e:
            self.log(f"[!] Patching error: {str(e)}")
            self.log(f"[VERBOSE] Exception: {type(e).__name__}")
            return False
            
    def flash_lk(self, img_name):
        self.log(f"[*] Flashing {img_name}...")
        self.log(f"[VERBOSE] Image: {os.path.join(self.work_dir, img_name)}")
        self.root.update()
        
        img_path = os.path.join(self.work_dir, img_name)
        if not os.path.exists(img_path):
            self.log(f"[!] {img_name} not found!")
            self.log(f"[VERBOSE] Expected: {img_path}")
            return False
        else:
            self.log(f"[VERBOSE] Found {img_name} at: {img_path}")
            self.log(f"[VERBOSE] Size: {os.path.getsize(img_path)} bytes")
            
        try:
            cmd = ["fastboot", "flash", "lk", img_name]
            self.log(f"[VERBOSE] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.log(f"[VERBOSE] Return code: {result.returncode}")
            if result.returncode == 0:
                self.log("[+] Flashed successfully")
                return True
            else:
                self.log(f"[!] Flash failed: {result.stderr}")
                return False
        except Exception as e:
            self.log(f"[!] Flash error: {str(e)}")
            return False
            
    def unlock_bootloader(self, key):
        self.log("[*] Unlocking bootloader...")
        self.update_status("Unlocking bootloader...")
        self.root.update()
        try:
            cmd = ["fastboot", "oem", "unlock", key]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                self.log("[+] Bootloader unlocked successfully!")
                self.log("[!] Phone will factory reset and reboot")
                return True
            else:
                self.log(f"[!] Unlock failed: {result.stderr}")
                return False
        except Exception as e:
            self.log(f"[!] Unlock error: {str(e)}")
            return False
            
    def run_frp_only(self):
        self.log("")
        self.log("=" * 70)
        self.log("[🔑] Starting FRP Bypass Only mode...")
        self.log("[!] This will NOT wipe your data")
        self.log("=" * 70)
        self.root.update()
        if not self.install_dependencies():
            return False
        self.update_progress(40)
        if not self.patch_lk_frp():
            return False
        self.update_progress(60)
        if not self.flash_lk("lk.erase-frp.img"):
            return False
        self.update_progress(80)
        serial = self.get_serial()
        if not serial:
            return False
        key = self.generate_key(serial)
        if not key:
            return False
        self.update_progress(90)
        self.log("[*] Triggering FRP erase...")
        subprocess.run(["fastboot", "oem", "unlock", key], capture_output=True)
        self.update_progress(100)
        self.log("[+] FRP erased successfully!")
        return True
        
    def run_bootloader_unlock(self):
        self.log("")
        self.log("=" * 70)
        self.log("[🔓] Starting Bootloader Unlock mode...")
        self.log("[!] This WILL factory reset your device")
        self.log("=" * 70)
        self.root.update()
        confirm = messagebox.askyesno("⚠️ WARNING", 
                                     "⚠️ THIS CAN PERMANENTLY BRICK YOUR DEVICE!\n\nThis will factory reset your device.\n\nContinue?")
        if not confirm:
            self.log("[!] Operation cancelled")
            return False
        if not self.install_dependencies():
            return False
        self.update_progress(40)
        if not self.patch_lk_unlock():
            return False
        self.update_progress(60)
        if not self.flash_lk("lk.unlock-serial.img"):
            return False
        self.update_progress(80)
        serial = self.get_serial()
        if not serial:
            return False
        key = self.generate_key(serial)
        if not key:
            return False
        self.update_progress(90)
        success = self.unlock_bootloader(key)
        self.update_progress(100)
        return success
            
    def run_both(self):
        self.log("")
        self.log("=" * 70)
        self.log("[⚡] Starting Bootloader Unlock + FRP Bypass mode...")
        self.log("[!] This WILL factory reset your device")
        self.log("=" * 70)
        self.root.update()
        confirm = messagebox.askyesno("⚠️ WARNING", 
                                     "⚠️ THIS CAN PERMANENTLY BRICK YOUR DEVICE!\n\nThis will factory reset your device.\n\nContinue?")
        if not confirm:
            self.log("[!] Operation cancelled")
            return False
        self.log("[*] Step 1: Bypassing FRP...")
        if not self.run_frp_only():
            return False
        self.log("")
        self.log("[*] Step 2: Unlocking bootloader...")
        self.progress['value'] = 0
        return self.run_bootloader_unlock()
        
    def check_device(self):
        self.log("")
        self.log("=" * 70)
        self.log("[🔍] Checking device...")
        self.update_status("Checking device...")
        self.root.update()
        
        if not shutil.which("fastboot"):
            self.log("[!] Fastboot not found")
            if self.os_name == "Windows":
                self.show_windows_fastboot_warning()
            else:
                self.show_linux_fastboot_instructions()
            return
            
        serial = self.get_serial()
        if not serial:
            self.log("[!] No device detected. Make sure:")
            self.log("  1. Phone is in fastboot mode")
            self.log("  2. USB is connected")
            self.log("  3. USB cable is a data cable (not just charging)")
            if self.os_name == "Linux":
                self.log("  4. Try: sudo fastboot getvar serialno")
                self.log("  5. If that works, run this tool with: sudo python3 valhalla.py")
            else:
                self.log("  4. USB drivers are installed")
            messagebox.showinfo("No Device", 
                               "No device detected in fastboot mode.\n\n"
                               "Make sure:\n"
                               "- Phone is in fastboot mode\n"
                               "- USB cable is connected\n"
                               "- USB cable is a data cable\n"
                               "- On Linux: try running with sudo")
            return
            
        self.log(f"[+] Device: Motorola MediaTek (Serial: {serial})")
        self.log(f"[+] Serial: {serial}")
        self.log(f"[+] Mode: {self.selected_mode.get()}")
        self.log("")
        self.log("[*] Device ready")
        self.log("[*] Click 'Run Valhalla' to begin the unlock process")
        self.log("")
        self.log("⚠️ REMEMBER: This can permanently brick your device!")
        self.log("DO NOT flash the original LK back after unlocking!")
        self.log("Use at your own risk. NO responsibility accepted!")
        
        self.unlock_btn.config(state=tk.NORMAL)
        self.update_status("Device ready. Click 'Run Valhalla' (⚠️ BRICK RISK)")
        
    def run_unlock(self):
        mode = self.selected_mode.get()
        self.check_btn.config(state=tk.DISABLED)
        self.unlock_btn.config(state=tk.DISABLED)
        try:
            if mode == "bootloader":
                self.run_bootloader_unlock()
            elif mode == "frp":
                self.run_frp_only()
            elif mode == "both":
                self.run_both()
        except Exception as e:
            self.log(f"[!] Error: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.check_btn.config(state=tk.NORMAL)
            self.unlock_btn.config(state=tk.DISABLED)
            self.update_status("Done")
            
    def reset_tool(self):
        self.log("")
        self.log("[🔄] Resetting tool...")
        self.serial_number = ""
        self.unlock_key = ""
        self.progress['value'] = 0
        self.unlock_btn.config(state=tk.DISABLED)
        self.check_btn.config(state=tk.NORMAL)
        self.update_status("Ready")
        self.log("[*] Tool reset. Connect phone and check again.")
        self.root.update()

def main():
    root = tk.Tk()
    app = ValhallaUnlockTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
