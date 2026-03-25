# SVM CLI User Manual (V6.0)

**NAME**  
[svm_cli.py](file:///home/hakan/kernel/tools/svm_cli.py) — Gelişmiş Ring -1 Malware Analiz ve Bellek Snapshot Arayüzü

**SYNOPSIS**  
`sudo python3 svm_cli.py <COMMAND> [OPTIONS]`

**DESCRIPTION**  
[svm_cli.py](file:///home/hakan/kernel/tools/svm_cli.py), AMD SVM (Secure Virtual Machine) teknolojisi kullanılarak geliştirilmiş *Ring -1* "stealth" (gizli) hipervizör ([ring_minus_one.ko](file:///home/hakan/kernel/ring_minus_one.ko)) için kullanıcı dostu bir komut satırı aracıdır. Bu araç sayesinde işletim sistemi ve anti-hile/anti-analiz korumaları (Obfuscator, Packer) tarafından **asla tespit edilemeyen** donanım destekli bellek dökümleri (snapshot) alabilir ve çalışan kodun anlık izlemesini (Trace) yapabilirsiniz.

Araç modüler bir yapıya sahiptir ve V6.0 sürümü itibarıyla klasik "Snapshot" (Phase 0) yeteneklerinin yanında donanım destekli **Sürekli İzleme (Continuous Trace)** yeteneği kazanmıştır.

> [!IMPORTANT]
> Bu araç, donanım katmanıyla (`/proc/svm_dump` ve `/proc/svm_trace`) doğrudan iletişim kurduğu için mutlaka `root` yetkileri (`sudo`) ile çalıştırılmalıdır.

---

## 🛠️ COMMANDS (Komutlar)

Araç dört temel alt komuta ayrılmıştır: `dump`, `watch`, `list` ve `trace`.

### 1. `dump` Modu (Anlık Snapshot)
Çalışan aktif bir işlemin (Process) o anki belleğinin (RAM) donanımsal düzeyde dondurulup tam bir kopyasını almanızı sağlar. Hedef işlemin CR3 bağlamını bulup tüm NPT (Nested Page Table) haritasını ve fiziksel belleği kopyalar.

**Kullanım:**
```bash
sudo python3 svm_cli.py dump --pid <PID> --out <DOSYA.bin>
```

**Örnek:**
```bash
sudo python3 svm_cli.py dump --pid 1337 -o malware_dump.bin
```
*Açıklama:* 1337 numaralı işlemin tam bellek dökümünü alır ve `malware_dump.bin` dosyasına yazar.

---

### 2. `watch` Modu (Otomatik Yakalama)
Bir uygulamanın çalışmasını **başladığı ilk milisaniyede** (henüz anti-debug korumaları devreye girmeden) yakalamak için kullanılır. Belirttiğiniz isimde bir uygulama çalıştığı an, hipervizör işlemi dondurur ve ilk bayttan snapshot alır.

**Kullanım:**
```bash
sudo python3 svm_cli.py watch --name <UYGULAMA_ADI> --out <DOSYA.bin>
```

**Örnek:**
```bash
sudo python3 svm_cli.py watch --name "packed_malware.exe" -o unpacked.bin
```
*Açıklama:* `packed_malware.exe` başlatılana kadar dinler, açıldığı an çalışmasını durdurur ve belleğini döküp `unpacked.bin` olarak kaydeder.

---

### 3. `list` Modu (Süreç Görüntüleme)
Hipervizörün erişebildiği (sistemde çalışan) tüm Linux / Wine işlemlerini PID ve isimleriyle beraber listeler.

**Kullanım:**
```bash
sudo python3 svm_cli.py list
```

---

### 4. `trace` Modu (✨ V6.0 Continuous Malware Trace)
Aracın en gelişmiş, Ring Buffer destekli izleme motorudur. Geleneksel EDR/VMI araçlarının aksine, hedef performansı **sıfır maliyetle** izlerken eşzamanlı olarak hedefin ne yaptığını takip eder. Kernel modülü içerisindeki 64 MB Lockless Ring Buffer'dan sürekli ve kesintisiz veri çeker.

Bu mod aşağıdakileri gerçek zamanlı yakalar:
- **[LBR] Code Tracing:** AMD LBR (Last Branch Record) donanım yığınını kullanarak hedefin en sık kullandığı işlemci dallanmalarını ve atlama (JMP/CALL) adreslerini çıkartır. 
- **[DIRTY] Data Tracing:** Hedefin bellek sayfalarına yazma yaptığı anları **#NPF (Nested Page Fault)** ve **MTF (Monitor Trap Flag)** kullanarak saniye saniye yakalar. Değiştirilen (mutasyona uğrayan) fiziksel 4KB'lık sayfayı doğrudan dosyaya `.bin` olarak çıkartır. Tamamen "Stealth"tir.

**Kullanım:**
```bash
sudo python3 svm_cli.py trace [--out-dir <KLASOR>]
```

**Örnek:**
```bash
sudo python3 svm_cli.py trace --out-dir ./mutations/
```
*Açıklama:* Ring Buffer dinlemeye başlanır. 
- Ekranda "Hot Code" hedefleri için dallanma adresleri dökülür:
  `[LBR] TSC: 123456789 | CR3: 0x1a2b3c | RIP: 0xfffff... | Branches: 16`
  `      ├─ 00: 0x100000 -> 0x100050`
- Hedef belleğinde değişiklik (unpacking, decryption) yaptığında konsola yazdırılır ve `dirty_0xGPA_TSC.bin` adıyla `mutations/` klasörüne sayfadaki yeni kodlar yedeklenir.
Çıkmak için `Ctrl+C` kullanılır ve motor kilitlenmeden kapanır.

---

## 🔍 İLERİ DÜZEY WORKFLOW (Malware Analizi için Önerilen Adımlar)

Bilinmeyen bir zararlıyı (veya güçlü bir anti-hile sistemini) analiz etmek için bu sistemi şu şekilde entegre kullanabilirsiniz:

1. **Hazırlık (Daemon Başlatma):**  
   Terminallerin birinde trace motorunu başlatarak bellek üzerindeki tüm dinamik değişiklikleri kaydetmek için ortamı hazırlayın.
   ```bash
   sudo python3 svm_cli.py trace --out-dir /tmp/malware_traces
   ```

2. **Yakalama (Watch):**  
   Diğer bir terminalden hedef çalıştırılabilir dosyayı `watch` moduna geçirin. 
   ```bash
   sudo python3 svm_cli.py watch --name "virus.exe" -o initial_dump.bin
   ```
   *Zararlıyı çalıştırdığınız anda `initial_dump.bin` oluşur.*

3. **Veri Toplama & Reverse Engineering:**  
   Zararlı yazılım unpacking yapıp kendi gövdesini çözmeye başladığında, **Trace Daemon** ekranınızda `[DIRTY]` loglarını göreceksiniz. Zararlı çözülen kodlarını (örneğin `.text` section) hafızaya yazdıkça bu bloklar `/tmp/malware_traces` klasörüne `dirty_*.bin` adıyla düşer.
   
   Aynı anda `[LBR]` logları uygulamanın sıkışıp kaldığı OEP (Original Entry Point) veya ana Decryption Loop adreslerini açıkça gösterecektir. LBR kayıtlarını izleyerek ida/ghidra kullanarak doğrudan `dirty.bin` dökümlerine reverse engineering yapabilirsiniz.
