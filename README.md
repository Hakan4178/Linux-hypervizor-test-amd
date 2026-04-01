# Barmetal

Devlog: Yaşasın Triple fault çözüldü yarı stabil modül yüklendi. Python tarafında analiz ve gizlilik eksikliği var.

Kapatılan açık sayısı:134

Barmetal is a Ring-1 (Hypervisor) level Virtual Machine Introspection (VMI) research engine designed for AMD processors. It operates below the standard operating system layer by utilizing AMD SVM (Secure Virtual Machine) hardware extensions.

## Current Architecture (V2.0 — Hardened)

This project has evolved into a "Silicon Watchtower" class bare-metal hypervisor, defeating advanced Anti-Cheat timing attacks and escaping OS-level hooks.

NOT: CLI Stealth Kamuflajı
Tüm kullanıcıya görünür stringler masum NTP Saat Senkronizasyonu temasına büründürüldü:

Eski (Şüpheli)	Yeni (Masum)
SVM RING -1 MATRIX DASHBOARD -> NTP CLOCK DRIFT ANALYZER
EXECUTION FLOW (RIP Trace) -> CLOCK DRIFT TRACE
PAGE HEATMAP (Top Mutated) -> FREQUENCY ANALYSIS
NPF DIRTY -> PAGES TIMER EVENTS (Decoded)
[DIRTY!] -> [ANOMALY]
Ring -1 Snapshot yakalandı -> Kalibrasyon tamamlandı
Kernel hipervizörü ->Saat senkronizasyonu
live_trace_report.txt -> ntp_sync_report.txt

- **Phase 15 (Clean State):** `LD_PRELOAD` stealth ghosting. No `ptrace` anomalies.
- **Phase 16 (Timing Armor):** Pure native execution via `EFER.SCE=1` passthrough, with zero `#VMEXIT` overhead.
- **Phase 17 (LBR Illusion):** LBR Virtualization enabled; Branch tracing isolated per-ASID.
- **Phase 18 (Surgical NPT):** Precision TLB manipulation via `INVLPGA`. Includes **Per-NPF TSC Compensation** and Drift Guards to flawlessly hide hypervisor presence and neutralize timing attacks.
- **Phase 19 (Pure VMI):** Sandbox escape prevention moved from generic kernel Kprobes to direct silicon interception (`MSR_FS_BASE` / `MSR_GS_BASE` write trapping for thread birth and SWAPGS).

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

Interaction is handled via the stealth `svm_run` launcher and the Python daemon:

1. **Build Tools:**
Make sure you compile the Userland Loader.
```bash
cd tools && make && cd ..
```

2. **Start Monitoring Daemon:**
Run the CLI to intercept real-time VMI data from the Ring Buffer.
```bash
sudo python3 tools/svm_cli.py live --out-dir ./mutations --log live_trace_report.txt
```

3. **Execute Target:**
Run the target application through the Stealth Launcher. It uses `LD_PRELOAD` to silently bootstrap the Matrix environment right before `main()` executes.
```bash
./tools/svm_run /usr/bin/sleep 1000
```

## Unloading
```bash
sudo rmmod ring_minus_one
```

Özgürlük için...  Made by "Türk Gençliği" <3 <3 <3