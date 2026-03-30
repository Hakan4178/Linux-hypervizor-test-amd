# Barmetal

Devlog: Yaşasın Triple fault çözüldü yarı stabil modül yüklendi. Python tarafında analiz ve gizlilik eksikliği var.

Kapatılan açık sayısı:134

Barmetal is a Ring-1 (Hypervisor) level Virtual Machine Introspection (VMI) research engine designed for AMD processors. It operates below the standard operating system layer by utilizing AMD SVM (Secure Virtual Machine) hardware extensions.

## Current Architecture and Phases

This project spans several developmental phases to mature the VMI implementations:
- **Phase 0-2 (Legacy):** Memory snapshotting, basic LBR tracing, and NPF trap handling via global kthreads.
- **Phase 3.3 - Matrix Portal (Current):** A stealthy, `ioctl()`-driven process-level virtualization engine. The target process is injected via Ghost shellcode (`/proc/ntpd_policy`) and safely encapsulated into an isolated VMCB sandbox completely transparent to the host OS.
- **Phase 3.4 (WIP):** Advanced device hiding to mask the `/dev/ntp_sync` portal and other hypervisor artifacts from Userland tools.

## Technical Details (Phase 3.3)
- **CPU MSR Fragmentation Fix:** Strict module initialization pinning to Core 0 to prevent `#UD` Invalid Opcode crashes during CPL transitions.
- **Triple Fault Armor:** Full 64-bit TR base GDT parsing and strict bounds checking.
- **Matrix Escape Hatch:** EFER.SCE masking ensures that any guest `SYSCALL` securely traps to the hypervisor (#UD handler), preventing SMEP/SMAP host panics.
- **Zero-Day Patches:** Precise instruction length bypass validations (`next_rip`), per-process rearm state synchronization, and Ghost DoS starvation lock prevention.

## Installation

### Dependencies
The module requires an AMD processor supporting SVM and is tested on Arch Linux environments.
```bash
sudo pacman -S linux-headers gcc make python python-pip sparse cppcheck
```

### Compile
Clone the repository and run `make`:
```bash
make clean
make C=2 -j$(nproc)
```

### Loading the Module
```bash
sudo insmod ring_minus_one.ko
```
Check kernel logs (`dmesg | tail`) to verify successful engine deployment and zero-day patch applications.

## Usage

Interaction is handled via the stealth Ghost Injection workflow and the Python daemon:

1. **Target Selection:**
Arm the Ghost injection engine by specifying the target process name via the unified policy port.
```bash
echo "sleep" | sudo tee /proc/ntpd_policy
```

2. **Start Monitoring Daemon:**
Run the CLI to intercept real-time VMI data from the Ring Buffer.
```bash
sudo python3 tools/svm_cli.py live --out-dir ./mutations --log live_trace_report.txt
```

3. **Execute Target:**
Run the target application. It will be seamlessly trapped into the Matrix sandbox without any userland footprint (No `ptrace`).
```bash
sleep 1000
```

## Unloading
```bash
sudo rmmod ring_minus_one
```

Özgürlük için...  Made by "Türk Gençliği" <3 <3 <3