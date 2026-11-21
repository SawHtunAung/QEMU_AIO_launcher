# All-in-One QEMU GUI Launcher

A cross-platform Python (`tkinter`) GUI launcher for `qemu-system-*` designed for testing UEFI/OVMF boot environments, bootable ISOs, custom `.efi` binaries on FAT16 disk images, `.qcow2` images, and `aarch64` (such as Raspberry Pi OS 64-bit) test setups without repetitive manual CLI entry.

## Key Features

- **Cross-Platform & Multi-Architecture**: Auto-detects host OS (`Windows`, `Linux`, `macOS`) and supports target architectures including `x86_64`, `i386`, `aarch64`, and `riscv64`.
- **Preset Profiles Manager**: Save, update, load, and delete named configuration presets stored in JSON (`qemu_all_in_one_presets.json`).
- **FAT16 Disk Builder + `.efi` Injection + `startup.nsh`**: Generates a FAT16 `.img` disk image, optionally injects a `.efi` binary (8.3 short name), and optionally writes a `STARTUP.NSH` auto-run script.
- **`.qcow2` Helper (`qemu-img`)**: Create `.qcow2` disk images and inspect disk metadata via `qemu-img info`.
- **Console / Serial Logging & Clipboard Copy**: Live output log with keyword filtering, `.txt` export, `Copy All Log` button, `Ctrl+C` shortcut, and right-click context menu (`Copy Selected`, `Copy All Log`, `Select All`, `Clear Log`).
- **Extra Raw QEMU Flags**: Pass custom flags such as `-kernel`, `-dtb`, `-append`, `-device`, or `-boot` directly.

## Requirements

- **Python 3.8+** with `tkinter` available.
- **QEMU** installed (`qemu-system-x86_64`, `qemu-system-aarch64`, `qemu-img`, etc.) in `PATH` or standard installation directories.

## Quick Start

```bash
python qemu_all_in_one_launcher.py