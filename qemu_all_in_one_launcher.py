import json
import os
import platform
import shlex
import shutil
import struct
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

PRESETS_FILE = "qemu_all_in_one_presets.json"

ARCH_DEFAULTS = {
    "x86_64": {"bin": "qemu-system-x86_64", "machine": "q35", "cpu": "max"},
    "i386": {"bin": "qemu-system-i386", "machine": "pc", "cpu": "max"},
    "aarch64": {"bin": "qemu-system-aarch64", "machine": "virt", "cpu": "cortex-a72"},
    "riscv64": {"bin": "qemu-system-riscv64", "machine": "virt", "cpu": "rv64"},
}


def detect_host_os():
    s = platform.system().lower()
    if "windows" in s:
        return "windows"
    if "darwin" in s:
        return "macos"
    return "linux"


def to_83_name(filename):
    base, ext = os.path.splitext(filename.upper())
    b8 = "".join(c for c in base if c.isalnum() or c in "_-")[:8] or "FILE"
    e3 = "".join(c for c in ext.lstrip("."))[:3]
    short_display = f"{b8}.{e3}" if e3 else b8
    return b8.ljust(8, " ").encode("ascii"), e3.ljust(3, " ").encode("ascii"), short_display


def create_fat16_image(img_path, size_mb=32, efi_file_path=None, auto_startup_nsh=False):
    """Creates a FAT16 .img file, optionally injecting an .efi file and startup.nsh."""
    size_mb = max(5, float(size_mb))
    total_sectors = int((size_mb * 1024 * 1024) // 512)
    total_sectors = max(8400, min(total_sectors, 65524))

    bytes_per_sector = 512
    sectors_per_cluster = 4 if total_sectors <= 32768 else 8
    reserved_sectors = 1
    num_fats = 2
    root_entries = 512
    root_dir_sectors = ((root_entries * 32) + (bytes_per_sector - 1)) // bytes_per_sector

    data_sectors_est = total_sectors - (reserved_sectors + root_dir_sectors)
    clusters_est = (data_sectors_est // sectors_per_cluster) + 2
    fat_size = max(1, ((clusters_est * 2) + (bytes_per_sector - 1)) // bytes_per_sector)

    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", boot, 11, bytes_per_sector)
    boot[13] = sectors_per_cluster
    struct.pack_into("<H", boot, 14, reserved_sectors)
    boot[16] = num_fats
    struct.pack_into("<H", boot, 17, root_entries)
    if total_sectors < 65536:
        struct.pack_into("<H", boot, 19, total_sectors)
        struct.pack_into("<I", boot, 32, 0)
    else:
        struct.pack_into("<H", boot, 19, 0)
        struct.pack_into("<I", boot, 32, total_sectors)
    boot[21] = 0xF8
    struct.pack_into("<H", boot, 22, fat_size)
    struct.pack_into("<H", boot, 24, 63)
    struct.pack_into("<H", boot, 26, 255)
    struct.pack_into("<I", boot, 28, 0)
    boot[36] = 0x80
    boot[38] = 0x29
    struct.pack_into("<I", boot, 39, 0x20261121)
    boot[43:54] = b"EFI_TEST   "
    boot[54:62] = b"FAT16   "
    boot[510:512] = b"\x55\xaa"

    fat = bytearray(fat_size * bytes_per_sector)
    struct.pack_into("<H", fat, 0, 0xFFF8)
    struct.pack_into("<H", fat, 2, 0xFFFF)

    root_dir = bytearray(root_dir_sectors * bytes_per_sector)
    data_sectors = total_sectors - reserved_sectors - (num_fats * fat_size) - root_dir_sectors
    if data_sectors <= 0:
        raise ValueError("FAT16 image size is too small.")
    data_area = bytearray(data_sectors * bytes_per_sector)

    cluster_bytes = sectors_per_cluster * bytes_per_sector
    next_free_cluster = 3
    root_idx = 0
    max_clusters = (len(data_area) // cluster_bytes) + 2

    def _add_file(short_name_str, data_bytes):
        nonlocal next_free_cluster, root_idx
        if root_idx >= root_entries:
            raise ValueError("Root directory entry limit reached.")
        need_clusters = max(1, (len(data_bytes) + cluster_bytes - 1) // cluster_bytes)
        if next_free_cluster + need_clusters - 1 >= max_clusters:
            raise ValueError(f"Not enough space in FAT image for {short_name_str}.")

        first_cl = next_free_cluster
        chain = list(range(first_cl, first_cl + need_clusters))
        next_free_cluster += need_clusters

        for i, cl in enumerate(chain):
            nxt = chain[i + 1] if i + 1 < len(chain) else 0xFFFF
            struct.pack_into("<H", fat, cl * 2, nxt)

        for i, cl in enumerate(chain):
            chunk = data_bytes[i * cluster_bytes : (i + 1) * cluster_bytes]
            off = (cl - 2) * cluster_bytes
            data_area[off : off + len(chunk)] = chunk

        n8, e3, _ = to_83_name(short_name_str)
        entry = bytearray(32)
        entry[0:8] = n8
        entry[8:11] = e3
        entry[11] = 0x20
        struct.pack_into("<H", entry, 26, first_cl)
        struct.pack_into("<I", entry, 28, len(data_bytes))
        root_dir[root_idx * 32 : (root_idx + 1) * 32] = entry
        root_idx += 1

    injected_short_name = None
    if efi_file_path:
        if not os.path.exists(efi_file_path):
            raise FileNotFoundError(f"EFI file not found: {efi_file_path}")
        with open(efi_file_path, "rb") as ef:
            efi_bytes = ef.read()
        _, _, injected_short_name = to_83_name(os.path.basename(efi_file_path))
        _add_file(injected_short_name, efi_bytes)

    if auto_startup_nsh and injected_short_name:
        nsh_script = f"fs0:\r\n{injected_short_name}\r\n".encode("ascii")
        _add_file("STARTUP.NSH", nsh_script)

    out_dir = os.path.dirname(os.path.abspath(img_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(img_path, "wb") as f:
        f.write(boot)
        for _ in range(num_fats):
            f.write(fat)
        f.write(root_dir)
        f.write(data_area)

    return injected_short_name


class AllInOneQemuLauncher:
    def __init__(self, root):
        self.root = root
        self.host_os = detect_host_os()
        self.root.title(f"All-in-One QEMU GUI Launcher ({self.host_os.upper()})")
        self.root.geometry("940x830")
        self.proc = None
        self._loading_preset = False
        self._all_log_lines = []

        default_accel = {"linux": "kvm", "macos": "hvf", "windows": "tcg"}.get(self.host_os, "tcg")
        default_disp = {"linux": "gtk", "macos": "cocoa", "windows": "sdl"}.get(self.host_os, "sdl")

        self.vars = {
            "arch": tk.StringVar(value="x86_64"),
            "qemu_bin": tk.StringVar(value=""),
            "machine": tk.StringVar(value="q35"),
            "cpu": tk.StringVar(value="max"),
            "accel": tk.StringVar(value=default_accel),
            "display": tk.StringVar(value=default_disp),
            "ram_mb": tk.StringVar(value="2048"),
            "smp_cores": tk.StringVar(value="2"),
            "code_fd": tk.StringVar(value=""),
            "vars_fd": tk.StringVar(value=""),
            "iso_path": tk.StringVar(value=""),
            "disk_path": tk.StringVar(value=""),
            "disk_fmt": tk.StringVar(value="raw"),
            "efi_inject": tk.StringVar(value=""),
            "fat_size_mb": tk.StringVar(value="32"),
            "auto_startup_nsh": tk.BooleanVar(value=False),
            "qcow2_size": tk.StringVar(value="10G"),
            "serial_stdio": tk.BooleanVar(value=True),
            "monitor_stdio": tk.BooleanVar(value=False),
            "extra_args": tk.StringVar(value="-boot menu=on"),
            "log_filter": tk.StringVar(value=""),
        }

        self.presets = {
            "x86_64 UEFI + ISO": {
                "arch": "x86_64",
                "machine": "q35",
                "cpu": "max",
                "accel": default_accel,
                "display": default_disp,
                "ram_mb": "2048",
                "smp_cores": "2",
                "code_fd": r"D:\Boot_Project\CODE.fd" if self.host_os == "windows" else "",
                "vars_fd": "",
                "iso_path": r"D:\Boot_Project\HBCD.iso" if self.host_os == "windows" else "",
                "disk_path": "",
                "disk_fmt": "raw",
                "efi_inject": "",
                "fat_size_mb": "32",
                "auto_startup_nsh": False,
                "qcow2_size": "10G",
                "serial_stdio": True,
                "monitor_stdio": False,
                "extra_args": "-boot menu=on",
            },
            "x86_64 UEFI Shell FAT Disk": {
                "arch": "x86_64",
                "machine": "q35",
                "cpu": "max",
                "accel": "tcg",
                "display": default_disp,
                "ram_mb": "1024",
                "smp_cores": "1",
                "code_fd": r"D:\Boot_Project\CODE.fd" if self.host_os == "windows" else "",
                "vars_fd": "",
                "iso_path": "",
                "disk_path": r"D:\Boot_Project\efi_test_disk.img" if self.host_os == "windows" else "efi_test_disk.img",
                "disk_fmt": "raw",
                "efi_inject": "",
                "fat_size_mb": "32",
                "auto_startup_nsh": False,
                "qcow2_size": "10G",
                "serial_stdio": True,
                "monitor_stdio": False,
                "extra_args": "-boot menu=on",
            },
            "aarch64 Pi OS / ARM64 Test": {
                "arch": "aarch64",
                "machine": "virt",
                "cpu": "cortex-a72",
                "accel": "tcg",
                "display": default_disp,
                "ram_mb": "2048",
                "smp_cores": "2",
                "code_fd": "",
                "vars_fd": "",
                "iso_path": "",
                "disk_path": "",
                "disk_fmt": "raw",
                "efi_inject": "",
                "fat_size_mb": "32",
                "auto_startup_nsh": False,
                "qcow2_size": "10G",
                "serial_stdio": True,
                "monitor_stdio": False,
                "extra_args": "",
            },
        }
        self.active_preset = tk.StringVar(value="x86_64 UEFI + ISO")

        self._build_ui()
        self._apply_arch_defaults(update_bin=True)
        self._load_presets_file()
        self.load_selected_preset(log_msg=False)
        self._refresh_preview()

        self.vars["arch"].trace_add("write", lambda *_: self._on_arch_change())
        self.vars["log_filter"].trace_add("write", lambda *_: self._render_filtered_log())
        for key, var in self.vars.items():
            if key not in ("arch", "log_filter"):
                var.trace_add("write", lambda *_: self._on_var_change())

    def _on_var_change(self):
        if not self._loading_preset:
            self._refresh_preview()

    def _find_binary(self, bin_name):
        if self.host_os == "windows":
            exe = bin_name if bin_name.endswith(".exe") else bin_name + ".exe"
            found = shutil.which(exe)
            if found:
                return found
            default_win = os.path.join(r"C:\Program Files\qemu", exe)
            if os.path.exists(default_win):
                return default_win
        found = shutil.which(bin_name)
        if found:
            return found
        for prefix in ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"):
            cand = os.path.join(prefix, bin_name)
            if os.path.exists(cand):
                return cand
        return bin_name

    def _apply_arch_defaults(self, update_bin=False):
        arch = self.vars["arch"].get()
        cfg = ARCH_DEFAULTS.get(arch, ARCH_DEFAULTS["x86_64"])
        self.vars["machine"].set(cfg["machine"])
        self.vars["cpu"].set(cfg["cpu"])
        if update_bin:
            self.vars["qemu_bin"].set(self._find_binary(cfg["bin"]))

    def _on_arch_change(self):
        if self._loading_preset:
            return
        self._apply_arch_defaults(update_bin=True)
        self._refresh_preview()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 3}

        # 1. Presets
        f_pre = tk.LabelFrame(self.root, text="Preset Profiles")
        f_pre.pack(fill="x", **pad)
        tk.Label(f_pre, text="Preset:").pack(side="left", padx=(6, 2), pady=3)
        self.cmb_presets = ttk.Combobox(
            f_pre, textvariable=self.active_preset, values=list(self.presets.keys()), width=28, state="readonly"
        )
        self.cmb_presets.pack(side="left", padx=4, pady=3)
        self.cmb_presets.bind("<<ComboboxSelected>>", lambda _e: self.load_selected_preset())

        tk.Label(f_pre, text="Name:").pack(side="left", padx=(10, 2), pady=3)
        self.ent_preset_name = tk.Entry(f_pre, width=22)
        self.ent_preset_name.pack(side="left", padx=4, pady=3)
        tk.Button(f_pre, text="Save / Update", command=self.save_preset).pack(side="left", padx=3, pady=3)
        tk.Button(f_pre, text="Delete", command=self.delete_preset).pack(side="left", padx=3, pady=3)

        # 2. System & Console Flags
        f_sys = tk.LabelFrame(self.root, text="Target Architecture, System & Console")
        f_sys.pack(fill="x", **pad)

        tk.Label(f_sys, text="Arch:").grid(row=0, column=0, padx=6, pady=3, sticky="w")
        tk.OptionMenu(f_sys, self.vars["arch"], *ARCH_DEFAULTS.keys()).grid(row=0, column=1, sticky="w")

        tk.Label(f_sys, text="Machine:").grid(row=0, column=2, padx=6, pady=3, sticky="w")
        tk.Entry(f_sys, textvariable=self.vars["machine"], width=12).grid(row=0, column=3, sticky="w")

        tk.Label(f_sys, text="CPU:").grid(row=0, column=4, padx=6, pady=3, sticky="w")
        tk.Entry(f_sys, textvariable=self.vars["cpu"], width=14).grid(row=0, column=5, sticky="w")

        tk.Label(f_sys, text="Accel:").grid(row=0, column=6, padx=6, pady=3, sticky="w")
        tk.OptionMenu(f_sys, self.vars["accel"], "tcg", "kvm", "hvf", "whpx").grid(row=0, column=7, sticky="w")

        tk.Label(f_sys, text="RAM (MB):").grid(row=1, column=0, padx=6, pady=3, sticky="w")
        tk.Entry(f_sys, textvariable=self.vars["ram_mb"], width=10).grid(row=1, column=1, sticky="w")

        tk.Label(f_sys, text="Cores:").grid(row=1, column=2, padx=6, pady=3, sticky="w")
        tk.Entry(f_sys, textvariable=self.vars["smp_cores"], width=8).grid(row=1, column=3, sticky="w")

        tk.Label(f_sys, text="Display:").grid(row=1, column=4, padx=6, pady=3, sticky="w")
        tk.OptionMenu(f_sys, self.vars["display"], "sdl", "gtk", "cocoa", "none").grid(row=1, column=5, sticky="w")

        tk.Label(f_sys, text="Disk Fmt:").grid(row=1, column=6, padx=6, pady=3, sticky="w")
        tk.OptionMenu(f_sys, self.vars["disk_fmt"], "raw", "qcow2").grid(row=1, column=7, sticky="w")

        tk.Checkbutton(f_sys, text="Serial Stdio (-serial stdio)", variable=self.vars["serial_stdio"]).grid(
            row=2, column=0, columnspan=3, padx=6, pady=3, sticky="w"
        )
        tk.Checkbutton(f_sys, text="Monitor Stdio (-monitor stdio)", variable=self.vars["monitor_stdio"]).grid(
            row=2, column=3, columnspan=3, padx=6, pady=3, sticky="w"
        )

        # 3. Paths
        f_paths = tk.LabelFrame(self.root, text="Binaries, Firmware & Media Paths")
        f_paths.pack(fill="x", **pad)
        self._path_row(f_paths, "QEMU Binary:", "qemu_bin", 0)
        self._path_row(f_paths, "Firmware CODE:", "code_fd", 1)
        self._path_row(f_paths, "Firmware VARS:", "vars_fd", 2)
        self._path_row(f_paths, "ISO (-cdrom):", "iso_path", 3)
        self._path_row(f_paths, "Disk (-drive):", "disk_path", 4)

        # 4. Disk Builders (FAT16 + qcow2)
        f_disk = tk.LabelFrame(self.root, text="Disk Image Tools (FAT16 .efi Builder & qcow2 Helper)")
        f_disk.pack(fill="x", **pad)

        tk.Label(f_disk, text=".EFI File:").grid(row=0, column=0, padx=6, pady=3, sticky="w")
        tk.Entry(f_disk, textvariable=self.vars["efi_inject"]).grid(row=0, column=1, padx=4, pady=3, sticky="we")
        tk.Button(f_disk, text="Browse .efi", command=self._browse_efi).grid(row=0, column=2, padx=3, pady=3)

        tk.Label(f_disk, text="FAT MB:").grid(row=0, column=3, padx=(6, 2), pady=3, sticky="w")
        tk.Entry(f_disk, textvariable=self.vars["fat_size_mb"], width=6).grid(row=0, column=4, padx=2, pady=3, sticky="w")

        tk.Checkbutton(f_disk, text="Auto startup.nsh", variable=self.vars["auto_startup_nsh"]).grid(
            row=0, column=5, padx=4, pady=3, sticky="w"
        )
        tk.Button(f_disk, text="Build FAT .img", command=self.build_fat_disk_action, bg="#1565c0", fg="white").grid(
            row=0, column=6, padx=4, pady=3
        )

        tk.Label(f_disk, text="qcow2 Size:").grid(row=1, column=0, padx=6, pady=3, sticky="w")
        tk.Entry(f_disk, textvariable=self.vars["qcow2_size"], width=10).grid(row=1, column=1, padx=4, pady=3, sticky="w")
        tk.Button(f_disk, text="Create .qcow2", command=self.create_qcow2_action).grid(row=1, column=2, padx=3, pady=3)
        tk.Button(f_disk, text="Disk Info (qemu-img)", command=self.inspect_disk_action).grid(row=1, column=3, columnspan=2, padx=3, pady=3)
        f_disk.columnconfigure(1, weight=1)

        # 5. Extra Args & Preview
        f_extra = tk.LabelFrame(self.root, text="Extra Raw QEMU Flags (-kernel / -dtb / -append / -device / etc.)")
        f_extra.pack(fill="x", **pad)
        tk.Entry(f_extra, textvariable=self.vars["extra_args"]).pack(fill="x", padx=6, pady=2)

        f_prev = tk.LabelFrame(self.root, text="Generated Command Preview")
        f_prev.pack(fill="x", **pad)
        self.txt_cmd = tk.Text(f_prev, height=3, wrap="word")
        self.txt_cmd.pack(fill="x", padx=6, pady=2)

        # 6. Controls & Log
        f_btn = tk.Frame(self.root)
        f_btn.pack(fill="x", **pad)
        tk.Button(f_btn, text="Start QEMU", command=self.start_qemu, bg="#2e7d32", fg="white", width=12).pack(side="left", padx=3)
        tk.Button(f_btn, text="Stop QEMU", command=self.stop_qemu, bg="#c62828", fg="white", width=11).pack(side="left", padx=3)
        tk.Button(f_btn, text="Copy All Log", command=self.copy_all_log).pack(side="left", padx=3)
        tk.Button(f_btn, text="Export Log (.txt)", command=self.export_log).pack(side="left", padx=3)

        tk.Label(f_btn, text="Filter:").pack(side="left", padx=(10, 2))
        tk.Entry(f_btn, textvariable=self.vars["log_filter"], width=15).pack(side="left", padx=2)
        tk.Button(f_btn, text="Clear Log", command=self.clear_log).pack(side="right", padx=3)

        f_log = tk.LabelFrame(self.root, text="Console / Serial / Backend Log")
        f_log.pack(fill="both", expand=True, **pad)
        self.txt_log = scrolledtext.ScrolledText(f_log, height=10, wrap="word")
        self.txt_log.pack(fill="both", expand=True, padx=6, pady=2)

        self.txt_log.bind("<Control-c>", self._on_log_copy_shortcut)
        self.txt_log.bind("<Control-C>", self._on_log_copy_shortcut)

        self._log_menu = tk.Menu(self.txt_log, tearoff=0)
        self._log_menu.add_command(label="Copy Selected", command=self.copy_selected_log)
        self._log_menu.add_command(label="Copy All Log", command=self.copy_all_log)
        self._log_menu.add_command(label="Select All", command=self.select_all_log)
        self._log_menu.add_separator()
        self._log_menu.add_command(label="Clear Log", command=self.clear_log)

        self.txt_log.bind("<Button-3>", self._show_log_context_menu)
        self.txt_log.bind("<Control-Button-1>", self._show_log_context_menu)

    def _set_clipboard(self, text):
        if not text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def copy_selected_log(self):
        try:
            selected = self.txt_log.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            selected = ""
        if selected:
            self._set_clipboard(selected)
            self._append_log(">>> Copied selected log to clipboard.\n")

    def copy_all_log(self):
        content = self.txt_log.get("1.0", tk.END).strip()
        if content:
            self._set_clipboard(content)
            messagebox.showinfo("Copied", "All visible log text copied to clipboard.")

    def select_all_log(self):
        self.txt_log.tag_add(tk.SEL, "1.0", "end-1c")
        self.txt_log.mark_set(tk.INSERT, "1.0")
        self.txt_log.see(tk.INSERT)
        return "break"

    def _on_log_copy_shortcut(self, _event):
        try:
            selected = self.txt_log.get(tk.SEL_FIRST, tk.SEL_LAST)
            if selected:
                self._set_clipboard(selected)
                return "break"
        except tk.TclError:
            pass
        return None

    def _show_log_context_menu(self, event):
        self._log_menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def _path_row(self, parent, label, key, row):
        tk.Label(parent, text=label, width=15, anchor="w").grid(row=row, column=0, padx=6, pady=2, sticky="w")
        tk.Entry(parent, textvariable=self.vars[key]).grid(row=row, column=1, padx=4, pady=2, sticky="we")
        tk.Button(parent, text="Browse", command=lambda k=key: self._browse_file(k)).grid(row=row, column=2, padx=6, pady=2)
        parent.columnconfigure(1, weight=1)

    def _browse_file(self, key):
        p = filedialog.askopenfilename()
        if p:
            self.vars[key].set(os.path.normpath(p))

    def _browse_efi(self):
        p = filedialog.askopenfilename(filetypes=[("EFI Binary", "*.efi"), ("All Files", "*.*")])
        if p:
            self.vars["efi_inject"].set(os.path.normpath(p))

    def build_fat_disk_action(self):
        efi_path = self.vars["efi_inject"].get().strip() or None
        auto_nsh = bool(self.vars["auto_startup_nsh"].get())
        try:
            size_mb = float(self.vars["fat_size_mb"].get().strip() or "32")
        except ValueError:
            messagebox.showerror("Error", "Invalid FAT size in MB.")
            return

        default_img = self.vars["disk_path"].get().strip() or "efi_test_disk.img"
        out_path = filedialog.asksaveasfilename(
            title="Save FAT16 Disk Image As",
            defaultextension=".img",
            initialfile=os.path.basename(default_img),
            filetypes=[("IMG Disk Image", "*.img"), ("All Files", "*.*")],
        )
        if not out_path:
            return

        try:
            out_norm = os.path.normpath(out_path)
            short_efi = create_fat16_image(out_norm, size_mb=size_mb, efi_file_path=efi_path, auto_startup_nsh=auto_nsh)
            self.vars["disk_path"].set(out_norm)
            self.vars["disk_fmt"].set("raw")
            self._refresh_preview()
            msg = f">>> Created FAT16 image: {out_norm}"
            if short_efi:
                msg += f" (injected as {short_efi})"
            if auto_nsh and short_efi:
                msg += " + STARTUP.NSH"
            self._append_log(msg + "\n")
            messagebox.showinfo("Success", f"FAT16 disk image created:\n{out_norm}")
        except Exception as exc:
            messagebox.showerror("Error", f"FAT16 build failed:\n{exc}")

    def _find_qemu_img(self):
        qemu_bin = self.vars["qemu_bin"].get().strip()
        if qemu_bin:
            cand = os.path.join(os.path.dirname(qemu_bin), "qemu-img.exe" if self.host_os == "windows" else "qemu-img")
            if os.path.exists(cand):
                return cand
        return self._find_binary("qemu-img")

    def create_qcow2_action(self):
        size_str = self.vars["qcow2_size"].get().strip() or "10G"
        qemu_img = self._find_qemu_img()
        if not os.path.exists(qemu_img) and not shutil.which(qemu_img):
            messagebox.showerror("Error", f"qemu-img not found:\n{qemu_img}")
            return

        out_path = filedialog.asksaveasfilename(
            title="Create qcow2 Image As",
            defaultextension=".qcow2",
            initialfile="disk_test.qcow2",
            filetypes=[("QCOW2 Image", "*.qcow2"), ("All Files", "*.*")],
        )
        if not out_path:
            return

        try:
            out_norm = os.path.normpath(out_path)
            subprocess.run([qemu_img, "create", "-f", "qcow2", out_norm, size_str], check=True)
            self.vars["disk_path"].set(out_norm)
            self.vars["disk_fmt"].set("qcow2")
            self._refresh_preview()
            self._append_log(f">>> Created qcow2 image ({size_str}): {out_norm}\n")
            messagebox.showinfo("Success", f"qcow2 created:\n{out_norm}")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to create qcow2:\n{exc}")

    def inspect_disk_action(self):
        disk = self.vars["disk_path"].get().strip()
        if not disk or not os.path.exists(disk):
            messagebox.showwarning("Warning", "Select a valid disk image first.")
            return
        qemu_img = self._find_qemu_img()
        try:
            res = subprocess.run([qemu_img, "info", disk], capture_output=True, text=True, errors="replace", check=True)
            self._append_log(f"\n--- qemu-img info ({disk}) ---\n{res.stdout}\n")
        except Exception as exc:
            self._append_log(f">>> qemu-img info error: {exc}\n")

    def _refresh_preset_dropdown(self):
        names = list(self.presets.keys())
        self.cmb_presets["values"] = names
        if self.active_preset.get() not in names and names:
            self.active_preset.set(names[0])

    def load_selected_preset(self, log_msg=True):
        name = self.active_preset.get().strip()
        if name not in self.presets:
            return
        self._loading_preset = True
        try:
            data = self.presets[name]
            for k, val in data.items():
                if k in self.vars:
                    self.vars[k].set(val)
            self.ent_preset_name.delete(0, tk.END)
            self.ent_preset_name.insert(0, name)
        finally:
            self._loading_preset = False
        self._refresh_preview()
        if log_msg:
            self._append_log(f">>> Loaded preset: {name}\n")

    def save_preset(self):
        name = self.ent_preset_name.get().strip()
        if not name:
            messagebox.showwarning("Warning", "Enter a preset name.")
            return
        self.presets[name] = {k: v.get() for k, v in self.vars.items() if k != "log_filter"}
        self.active_preset.set(name)
        self._refresh_preset_dropdown()
        self._write_presets_file()
        self._append_log(f">>> Saved preset: {name}\n")

    def delete_preset(self):
        name = self.active_preset.get().strip()
        if len(self.presets) <= 1:
            messagebox.showwarning("Warning", "At least one preset must remain.")
            return
        if name in self.presets:
            del self.presets[name]
            self.active_preset.set(list(self.presets.keys())[0])
            self._refresh_preset_dropdown()
            self._write_presets_file()
            self.load_selected_preset()
            self._append_log(f">>> Deleted preset: {name}\n")

    def _write_presets_file(self):
        payload = {"active_profile": self.active_preset.get(), "profiles": self.presets}
        with open(PRESETS_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def _load_presets_file(self):
        if not os.path.exists(PRESETS_FILE):
            return
        try:
            with open(PRESETS_FILE, "r", encoding="utf-8") as f:
                payload = json.load(f)
            profiles = payload.get("profiles", {})
            if isinstance(profiles, dict) and profiles:
                self.presets = profiles
                active = payload.get("active_profile")
                self.active_preset.set(active if active in self.presets else list(self.presets.keys())[0])
        except Exception:
            pass

    def build_args(self):
        exe = self.vars["qemu_bin"].get().strip()
        machine = self.vars["machine"].get().strip()
        cpu = self.vars["cpu"].get().strip()
        accel = self.vars["accel"].get().strip()
        ram = self.vars["ram_mb"].get().strip() or "2048"
        smp = self.vars["smp_cores"].get().strip() or "2"
        disp = self.vars["display"].get().strip()

        args = [exe]
        if machine:
            args += ["-M", machine]
        if accel and accel != "tcg":
            args += ["-accel", accel]
        if cpu:
            args += ["-cpu", cpu]
        args += ["-m", ram, "-smp", smp]
        if disp:
            args += ["-display", disp]

        code_fd = self.vars["code_fd"].get().strip()
        vars_fd = self.vars["vars_fd"].get().strip()
        if code_fd:
            args += ["-drive", f"if=pflash,format=raw,readonly=on,file={code_fd}"]
        if vars_fd:
            args += ["-drive", f"if=pflash,format=raw,file={vars_fd}"]

        iso = self.vars["iso_path"].get().strip()
        if iso:
            args += ["-cdrom", iso]

        disk = self.vars["disk_path"].get().strip()
        if disk:
            fmt = self.vars["disk_fmt"].get().strip() or "raw"
            args += ["-drive", f"file={disk},format={fmt}"]

        if self.vars["serial_stdio"].get():
            args += ["-serial", "stdio"]
        if self.vars["monitor_stdio"].get():
            args += ["-monitor", "stdio"]

        extra = self.vars["extra_args"].get().strip()
        if extra:
            args += shlex.split(extra, posix=(self.host_os != "windows"))

        return args

    def _refresh_preview(self):
        args = self.build_args()
        self.txt_cmd.delete("1.0", tk.END)
        self.txt_cmd.insert(tk.END, subprocess.list2cmdline(args))

    def _render_filtered_log(self):
        flt = self.vars["log_filter"].get().strip().lower()
        self.txt_log.delete("1.0", tk.END)
        for line in self._all_log_lines:
            if not flt or flt in line.lower():
                self.txt_log.insert(tk.END, line)
        self.txt_log.see(tk.END)

    def _append_log(self, text):
        def _do():
            self._all_log_lines.append(text)
            flt = self.vars["log_filter"].get().strip().lower()
            if not flt or flt in text.lower():
                self.txt_log.insert(tk.END, text)
                self.txt_log.see(tk.END)

        self.root.after(0, _do)

    def clear_log(self):
        self._all_log_lines.clear()
        self.txt_log.delete("1.0", tk.END)

    def export_log(self):
        out_path = filedialog.asksaveasfilename(
            title="Save Log As",
            defaultextension=".txt",
            initialfile="qemu_session_log.txt",
            filetypes=[("Text File", "*.txt"), ("All Files", "*.*")],
        )
        if not out_path:
            return
        with open(out_path, "w", encoding="utf-8") as f:
            f.writelines(self._all_log_lines)
        self._append_log(f">>> Exported log to {out_path}\n")

    def start_qemu(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("Info", "QEMU is already running.")
            return
        args = self.build_args()
        exe = args[0]
        if not os.path.exists(exe) and not shutil.which(exe):
            messagebox.showerror("Error", f"QEMU binary not found:\n{exe}")
            return

        self._append_log(f"\n>>> Launching: {subprocess.list2cmdline(args)}\n")

        def run_proc():
            try:
                self.proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    errors="replace",
                )
                for line in self.proc.stdout:
                    self._append_log(line)
                rc = self.proc.wait()
                self._append_log(f">>> Exited with code {rc}\n")
            except Exception as exc:
                self._append_log(f">>> Launch error: {exc}\n")

        threading.Thread(target=run_proc, daemon=True).start()

    def stop_qemu(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self._append_log(">>> Terminated QEMU process.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = AllInOneQemuLauncher(root)
    root.mainloop()