# Barmetal

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Arch Linux](https://img.shields.io/badge/OS-Arch%20Linux-1793d1.svg)](https://archlinux.org/)
[![Status](https://img.shields.io/badge/Status-Production%20NOT%20Ready-success.svg)]()

Kapatılan açık sayısı:88

Dikkat BETA Oldukça fazla açık olabilir. Hay apoyu s...... sorunu çözedim ama ilerleme var blue pill olmayacagız hybrid bir çözum gelıstırdım kerneli adeta sarhoş edeceğiz ama öldürmeyeceğiz. Bilerek güncellemedim kodları.

Barmetal, modern **Endpoint Detection and Response (EDR)**, **Anti-Cheat** ve karmaşık **Custom VM (Packer, Obfuscator)** mimarilerini sıfır gecikme (zero-overhead) ve mutlak görünmezlikle (stealth) analiz etmek için baştan aşağı donanım yetenekleri kullanılarak geliştirilmiş *Ring -1* (Hypervisor) seviyesi bir "Virtual Machine Introspection" (VMI) motorudur.

Eski usül "Kernel Hooking" veya "Debugging" yaklaşımlarını çöpe atar. Doğrudan AMD SVM (Secure Virtual Machine) komut setleri içine yerleşerek işletim sisteminin altından çalışır. 

---

## 🔥 Neden Üretim (Production) Kalitesi?
Bu yazılım akademik bir PoC'a yakın daha tam bitmedi.
- **Lockless 64MB Ring Buffer IPC**: Hipervizör ve kullanıcı alanı (User-space Python daemon) arasındaki veri kopyalama işlemlerinde Mutex (kilit) kullanılmaz. Bellek bariyerleri (`smp_wmb`/`smp_rmb`) sayesinde saniyede milyonlarca event %0 işlemci darboğazı ile çekilir.
- **Sıfır TOCTOU ve Integer Overflow**: Kernel - User space geçişleri (copy_to_user, copy_from_user) ve snapshot boyut hesaplamaları pointer aritmetiği taşmalarına (Zero-Day) karşı yamalanmıştır.
- **Kesintisiz TSC Telafisi (Soft-Lockup Koruması)**: Zararlı yazılım hipervizörün varlığını RDTSC (`Read Time-Stamp Counter`) ile tespit edemez; tüm analiz zaman gecikmeleri donanımdan matematiksel olarak çıkarılır (Stealth Offset). (Abart GPT)

---

## 🚀 Özellikler (Features)
- 🔴 **Phase 0 - Freeze & Dump:** İstediğiniz PID'yi veya ismi (çift tıklanmadan önce) beklemenizi sağlar. Kod ilk byteda dondurulur ve NPT haritası üzerinden saniyeler içinde kopyalanarak .bin çıktısı alinir.
- 🔴 **Phase 1 - LBR Code Tracing:** AMD'nin donanımsal Last Branch Record (LBR) MSR'lerini kullanarak, çalışan Guest'in yaptığı tüm zıplamaları (Indirect JMP/CALL) sıfır yavaşlama ile çeker. Custom VM Dispatcher analizinde haftalar harcamak yerine, program akış ağacını saniyeler içinde verir.
- 🔴 **Phase 2 - MTF & NPF Dirty Page Data Tracing:** NPT yazma izinleri özel sayfalar için kaldırılır. Zararlı `pack` edildiği şifreyi çözmeye çalıştığında (Unpacking / Decryption) oluşan `#NPF` (Nested Page Fault) exceptionu saniyesinde yakalanır, o sayfa temiz `.bin` olarak dosyaya atılır. Ardından **MTF (Monitor Trap Flag)** kurularak iz silinir.
- 🔴 **Phase 3 - Live Dashboard & Shannon Entropy:** Sürekli Ring -1'den gelen LBR geçmişi ile Mutasyonları (Memory Writes) kronolojik olarak birleştirir. Bir dosya yazıldığında anında %0-100 arası Entropi hesabı yapar. `7.5` değerinin üzerindeyse otomatik olarak `AES/RSA Key veya Şifreli Payload` olarak işaretler. Dilerseniz son LBR adımlarıyla beraber detaylı offline-analiz text raporu oluşturur.
- Phase 4 Video kaydı gibi olacak tam entegrasyon grafikler vb frontend gelişecek.

---

## ⚙️ Kurulum (Installation)

1. **Bağımlılıklar (Dependencies):**
Sistemin **Arch Linux** veya modern bir Kernel tabanlı Linux olması ve **AMD-V/SVM** desteğine sahip olması şarttır (Intel VMX desteği şimdilik yoktur).
```bash
sudo pacman -S linux-headers gcc make python python-pip
```

2. **Derleme (Building Kernel Module):**
Depoyu klonlayın ve kök dizinde `make` çalıştırın.
```bash
git clone https://github.com/Hakan4178/Barmetal.git
cd Barmetal
make clean && make -j$(nproc)
```
*(Güvenlik denetimi yapılmış derleme ortamında "0 Warning, 0 Error" olarak çıkar).*

3. **Modülü Yükleme (Loading):**
Derleme sonrası hipervizörü sisteme yerleştirin.
```bash
sudo insmod ring_minus_one.ko
```
Dmesg'i kontrol edebilirsiniz: `dmesg | tail -n 10` (Hipervizörün aktifleştiğini göreceksiniz).

---

## 💻 Kullanım Kılavuzu (Usage)

Hipervizör komutları, Python tabanlı bir "Front-end" aracı olan `svm_cli.py` üzerinden yönetilir. 

*(**Not:** `/proc/svm_*` iletişim kanalı nedeniyle tüm komutlar `sudo` ile çalıştırılmalıdır).*

### 1. Canlı Malware Unpacking & LBR Kök Bulucu (En Gelişmiş Mod)
Zararlı analizcilerinin en çok kullanacağı bölümdür. Hedefi canlı izler, mutasyonları klasöre çıkartır ve `live_trace_report.txt` olarak tüm akışı kaydeder.
```bash
# Canlı analiz ekranını başlat
sudo python3 tools/svm_cli.py live --out-dir ./mutations --log live_trace_report.txt

# (Ayrı bir terminalde hedefinizi/malware'i çalıştırın, ekran LBR ve RAM raporlarıyla alev alacaktır)
# Bitince `Ctrl+C` yapmanız yeterli, tüm bellek değişim raporu txt'ye otomatik kaydedilir.
```

### 2. Sadece İz Bırakan Mutasyon Kaydedici (Sade Trace)
LBR'ın devasa akışını ekranda görmek istemiyorsanız, arka planda sadece entropili mutasyonları `.bin` olarak döker.
```bash
# Ekranda LBR loglarını kapatarak sadece #NPF (Ram değişim) loglarına odaklanmak
sudo python3 tools/svm_cli.py trace --out-dir ./mutations --quiet
```

### 3. Hedef Anında Uygulama Yakalama (Watch Mode)
Malware çalıştığında anti-debug hooklarını daha işletim sistemine yüklemeye vakit bulamadan (İlk Instruction pointer'da) dondurulup belleği tam snapshot alınır.
```bash
sudo python3 tools/svm_cli.py watch --name "virus.exe" -o initial_dump.bin
```

### 4. Anlık Bellek Snapshot Alma (Dump Mode)
Mevcutta çalışan ve yakalamak istediğiniz bir PID mi var? Direkt PID'si ile tüm NPT haritası dahil belleği çıkartabilirsiniz.
```bash
sudo python3 tools/svm_cli.py list
sudo python3 tools/svm_cli.py dump --pid 1337 -o snapshot.bin
```

---

## 🔒 Kaldırma (Unloading)
Eğer analizinizi bitirdiyseniz hipervizörü OS'un bellek tablosundan söküp atabilirsiniz:
```bash
sudo rmmod ring_minus_one
```
Not: Bunu unutmayın 10 dakikadan uzun bırakmayın (Memory leak ve atak yuzeyı yuzunde)
