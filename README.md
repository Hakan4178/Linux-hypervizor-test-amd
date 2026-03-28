# Barmetal

Barmetal is a Ring-1 (Hypervisor) level Virtual Machine Introspection (VMI) research engine designed for AMD processors. It operates below the standard operating system layer by utilizing AMD SVM (Secure Virtual Machine) hardware extensions.

## Current Architecture and Phases

This project spans several developmental phases to mature the VMI implementations:
- **Phase 0 - Freeze & Dump:** Memory snapshotting by intercepting and copying processes at the NPT boundary.
- **Phase 1 - LBR Tracing:** Hardware-assisted indirect control-flow tracking (via Last Branch Record MSRs).
- **Phase 2 - Fault & Trap Handling:** Catching memory modifications using Nested Page Faults (NPF) alongside Monitor Trap Flag (MTF).
- **Phase 3 - Matrix Portal (WIP):** Moving from global persistent kthreads to a dynamic, on-demand `ioctl()` portal mechanism for precise process virtualization.

## Technical Details
- Implements lockless Ring Buffer IPC using hardware memory barriers (`smp_wmb`, `smp_rmb`).
- Handles timing measurement offsets by manipulating the TSC (Time-Stamp Counter) mathematically during VMEXIT processing.
- Strictly bounds memory limits and validations for User/Kernel transitions.

## Installation

### Dependencies
The module requires an AMD processor supporting SVM and is tested on Arch Linux environments.
```bash
sudo pacman -S linux-headers gcc make python python-pip
```

### Compile
Clone the repository and run `make`:
```bash
make clean
make -j$(nproc)
```

### Loading the Module
```bash
sudo insmod ring_minus_one.ko
```
Check kernel logs (`dmesg | tail`) to verify successful engine deployment.

## Usage

Interaction is handled via the Python daemon/CLI tool:
```bash
# Start dynamic execution tracing
sudo python3 tools/svm_cli.py live --out-dir ./mutations --log live_trace_report.txt

# Extract memory snapshots target by PID
sudo python3 tools/svm_cli.py list
sudo python3 tools/svm_cli.py dump --pid <target_pid> -o snapshot.bin
```

## Unloading
```bash
sudo rmmod ring_minus_one
```
