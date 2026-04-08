# Barmetal

Devlog: İmkansız ya İmkansız 7 farklı mimari düşündüm olmuyor tam trace gizli kalarak imkansız LBR bile yük ve karışık çıldırcam off ne yapsak ya takıldım burda kendime 4 gün mola verdim. İzahi hayli zor tanımsız bi vaziyet 

Python tarafını sallamıyorum.

Kapatılan açık sayısı:146

Barmetal is a Ring-1 (Hypervisor) level Virtual Machine Introspection (VMI) research engine designed for AMD processors. It operates below the standard operating system layer by utilizing AMD SVM hardware extensions.


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