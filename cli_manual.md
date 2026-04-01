# NTP Sync CLI Manual (V7.0)

**NAME**  
[svm_cli.py](file:///home/hakan/kernel/tools/svm_cli.py) — Network Time Protocol Synchronization & Diagnostics Utility

**SYNOPSIS**  
`sudo python3 tools/svm_cli.py <COMMAND> [OPTIONS]`

**DESCRIPTION**  
NTP Sync Diagnostics, donanım tabanlı saat sapması analizi ve zamanlayıcı kalibrasyon aracıdır. Sistem çekirdeğindeki telemetri modülü (`/proc/svm_dump`, `/proc/svm_trace`) ile doğrudan iletişim kurarak gerçek zamanlı veri toplar ve analiz eder.

V7.0 sürümü ile 3-Panel Curses Dashboard, Fiziksel Sayfa Frekans Analizi (Heatmap), Intel Syntax Assembly Çözümleme, interaktif kontroller ve JSON oturum dışa aktarımı desteklenmektedir.

> [!IMPORTANT]
> Bu araç, donanım katmanıyla doğrudan iletişim kurduğu için mutlaka yönetici yetkileri (`sudo`) ile çalıştırılmalıdır.

---

## 🛠️ COMMANDS (Komutlar)

Araç dört temel alt komuta ayrılmıştır: `dump`, `watch`, `list` ve `live`.

### 1. `dump` Modu (Kalibrasyon Verisi Toplama)
Belirtilen kaynaktan donanımsal düzeyde kalibrasyon verisini alır.

**Kullanım:**
```bash
sudo python3 tools/svm_cli.py dump --pid <KAYNAK_ID> --out <DOSYA.bin>
```

**Örnek:**
```bash
sudo python3 tools/svm_cli.py dump --pid 1337 -o calibration.bin
```
*Açıklama:* 1337 numaralı kaynağın kalibrasyon verisini toplar ve `calibration.bin` dosyasına yazar.

---

### 2. `watch` Modu (Otomatik Yakalama)
Belirtilen kaynağın aktif olmasını bekler ve aktif olduğu anda otomatik kalibrasyon yapar.

**Kullanım:**
```bash
sudo python3 tools/svm_cli.py watch --name <KAYNAK_ADI> --out <DOSYA.bin>
```

**Örnek:**
```bash
sudo python3 tools/svm_cli.py watch --name "target_app" -o captured.bin
```
*Açıklama:* `target_app` kaynağı aktif olana kadar bekler, aktif olduğu an veriyi yakalar.

---

### 3. `list` Modu (Aktif Kaynaklar)
Sistemdeki aktif senkronizasyon kaynaklarını listeler.

**Kullanım:**
```bash
sudo python3 tools/svm_cli.py list
```

---

### 4. `live` Modu (✨ V7.0 Diagnostics Dashboard)

Aracın en gelişmiş, 3-Panel Curses tabanlı canlı izleme arayüzüdür. 64 MB Ring Buffer'dan sürekli ve kesintisiz telemetri verisi çeker.

**Ekran Düzeni:**

```
╔══════════════════════════════════════════════════════╗
║  ◉ NTP CLOCK DRIFT ANALYZER v7.0          ⏱ 42s    ║
║  Events: 156 │ Mutations: 23 │ Drops: 0 │ HiEnt: 2 ║
╠══════════════════════╤═══════════════════════════════╣
║  CLOCK DRIFT TRACE   │  FREQUENCY ANALYSIS           ║
║  ├─ 0x7f4a21030  →   │  0x7f4a21000 ████████░░ (89x) ║
║  ├─ 0x7f4a21045  →   │  0x7f4a22000 ███░░░░░░░ (12x) ║
║  └─ 0x7f4a21060      │───────────────────────────────║
║                      │  TIMER EVENTS (Decoded)        ║
║                      │  ● 7f4a21000 │ mov rax, 1     ║
╠══════════════════════╧═══════════════════════════════╣
║  Q:Quit │ P:Pause │ S:Save │ D:DeepDive             ║
╚══════════════════════════════════════════════════════╝
```

**Panel Açıklamaları:**

| Panel | Konum | İçerik |
|-------|-------|--------|
| Stats Bar | Üst | Toplam event sayısı, kayıp paket (drop), yüksek entropili anomali sayısı |
| Clock Drift Trace | Sol | RIP/LBR izleri. Ağaç görünümünde (├─ / └─) akan adres akışı |
| Frequency Analysis | Sağ-üst | En çok tetiklenen fiziksel sayfaların sıcaklık haritası (`████░░░░` barlar) |
| Timer Events | Sağ-alt | Intel Syntax Assembly çözümlemesiyle birlikte gösterilen zamanlayıcı olayları |

**Klavye Kontrolleri:**

| Tuş | İşlev |
|-----|-------|
| `Q` | Güvenli çıkış |
| `P` | Duraklatma / Devam ettirme (arka planda veri toplanmaya devam eder) |
| `S` | Oturumu JSON + TXT olarak dışa aktar (heatmap top-20, branch'ler, anomaliler dahil) |
| `D` | Deep Dive (Derin Dalış) modunu aç/kapat |

**Kullanım:**
```bash
sudo python3 tools/svm_cli.py live [--out-dir <KLASÖR>] [--log <RAPOR.txt>]
```

**Örnek:**
```bash
sudo python3 tools/svm_cli.py live --out-dir ./captures -l ntp_sync_report.txt
```
*Açıklama:* Canlı dashboard başlatılır. Anomali verilen `./captures` klasörüne, oturum raporu `ntp_sync_report.txt` dosyasına kaydedilir.

---

## 🔍 FREQUENCY ANALYSIS (Sıcaklık Haritası)

Dashboard'un sağ üst panelinde yer alan Frequency Analysis, hangi fiziksel sayfaların en sık tetiklendiğini görsel olarak gösterir:

```
0x7f4a21000000 ██████████ (  127x)    ← RED: Kritik Hotspot
0x7f4a22000000 █████░░░░░ (   45x)    ← YELLOW: Ilık
0x7f4a23000000 ██░░░░░░░░ (    8x)    ← GREEN: Soğuk
```

**Renk Kodları:**
- 🔴 **Kırmızı** (>%75): Sürekli mutasyona uğrayan sayfa — potansiyel JIT, dinamik kod veya anti-tamper taraması
- 🟡 **Sarı** (>%35): Orta sıklıkta erişilen sayfa
- 🟢 **Yeşil** (<=%35): Nadir erişilen sayfa

---

## 📋 JSON EXPORT FORMATI

`S` tuşuna basıldığında veya çıkışta oluşturulan JSON dosyası şu yapıdadır:

```json
{
  "tool": "ntp_sync_diag",
  "version": "7.0",
  "timestamp": 1711929600,
  "elapsed_seconds": 42,
  "stats": {
    "lbr": 156, "dirty": 23, "drops": 0, "high_ent": 2
  },
  "heatmap_top20": [
    {"gpa": "0x00007f4a21000000", "count": 127}
  ],
  "recent_branches": [
    {"from": "0x...", "to": "0x...", "dirty": false, "source": "RIP"}
  ],
  "recent_mutations": [
    {"gpa": "0x...", "entropy": 7.82, "asm": "mov rax, 1"}
  ]
}
```

---

## 🔧 GEREKSİNİMLER

| Bağımlılık | Zorunlu | Açıklama |
|-----------|---------|----------|
| Python 3.8+ | ✅ | Standart kütüphane (curses, struct, json) |
| capstone | ❌ (Opsiyonel) | Intel Syntax Assembly çözümleme. Yoksa `[NO_CAPSTONE]` gösterilir |
| Kernel Modülü | ✅ | `/proc/svm_dump` ve `/proc/svm_trace` arayüzleri aktif olmalı |

**Capstone Kurulumu:**
```bash
pip install capstone
```

---

## ⚡ HIZLI BAŞLANGIÇ

```bash
# Terminal 1: Diagnostics Dashboard'u başlat
sudo python3 tools/svm_cli.py live --out-dir ./captures

# Terminal 2: Hedefi Matrix'e fırlat
./svm_run /usr/bin/sleep 3

# Dashboard'da canlı telemetri verilerini izle
# S tuşuyla oturumu kaydet, Q tuşuyla çık
```
