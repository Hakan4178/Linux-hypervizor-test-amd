#!/usr/bin/env python3
"""
SVM CLI - Unified Ring-1 Snapshot Tool (V6.6)
Production-grade Curses Dashboard and Trace Reader.
"""

import sys
import os
import time
import struct
import argparse
import math
import collections
import curses
import fcntl
from multiprocessing import Process, Queue
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

PROC_DIR = "/proc/svm_dump"

# Extraction definitions
HEADER_FMT = "<4sIiQQQQQQI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# struct svm_trace_entry alignment matching C ABI
ENTRY_FMT = "<QQIIQQQII32Q"
ENTRY_SIZE = struct.calcsize(ENTRY_FMT)
MAGIC_EXPECTED = 0x5356545200000000

def xor_checksum(data):
    seed = 0x5356444D48414B41
    cksum = seed
    for i in range(0, len(data) - 7, 8):
        word = struct.unpack_from("<Q", data, i)[0]
        cksum ^= word
    return cksum & 0xFFFFFFFFFFFFFFFF

def verify_checksum(raw_data, total_size, stored_checksum):
    cksum_offset = 52
    modified = bytearray(raw_data[:total_size])
    if len(modified) < cksum_offset + 8: return False, 0
    for i in range(8): modified[cksum_offset + i] = 0
    computed = xor_checksum(bytes(modified))
    return computed == stored_checksum, computed

def extract_dump(output_file):
    input_file = f"{PROC_DIR}/output"
    print("[*] RAM okunuyor (Ring -1 Belleği)...")
    try:
        with open(input_file, "rb") as f:
            raw_data = f.read()
    except Exception as e:
        print(f"[!] Veri okunamadı: {e}")
        return

    if len(raw_data) < HEADER_SIZE:
        print("[!] Geçersiz snapshot boyutu.")
        return

    magic, version, pid, flags, ts, cr3, vma_count, map_count, total_size, checksum = struct.unpack_from(HEADER_FMT, raw_data, 0)
    
    if magic != b'SVMD':
        print("[!] HATA: Büyülü imza bulunamadı (SVMD).")
        return

    print(f"\n[+] Snapshot Bilgileri:")
    print(f"    - Modül Versiyon: {version}")
    print(f"    - Hedef PID     : {pid}")
    print(f"    - Kernel CR3    : 0x{cr3:016x}")
    print(f"    - VMA Sayısı    : {vma_count}")
    print(f"    - Toplam Alan   : {total_size / (1024*1024):.2f} MB")

    ok, comp = verify_checksum(raw_data, total_size, checksum)
    if ok:
        print("    - Integrity   : [OK] Sağlam")
    else:
        print(f"    - Integrity   : [FAIL] Checksum Uyuşmazlığı! Istenen: {checksum:x}, Hesaplanan: {comp:x}")

    try:
        with open(output_file, "wb") as f:
            f.write(raw_data[:total_size])
        print(f"\n[+] Snapshot başarıyla diske kaydedildi: {output_file}")
    except Exception as e:
        print(f"[!] Dosya yazılamadı: {e}")

def write_proc(name, val):
    try:
        with open(os.path.join(PROC_DIR, name), "w") as f:
            f.write(str(val))
    except Exception as e:
        print(f"[!] {name} dosyasına yazılamadı: {e}")
        sys.exit(1)

def read_proc(name):
    try:
        with open(os.path.join(PROC_DIR, name), "r") as f:
            return f.read().strip()
    except Exception as e:
        return ""

def is_ready():
    status = read_proc("status")
    for line in status.split("\n"):
        if line.startswith("Ready:"):
            return "YES" in line
    return False

def cmd_dump(args):
    print(f"[*] Hedef PID {args.pid} için Snapshot tetikleniyor...")
    write_proc("target_pid", args.pid)
    write_proc("full_dump", "1")
    
    print("[*] Kernel hipervizörünün hafızayı dondurup kopyalaması bekleniyor", end="")
    sys.stdout.flush()
    for _ in range(30):
        if is_ready():
            print("\n")
            extract_dump(args.out)
            return
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
    print("\n[!] İşlem 30 saniye içinde tamamlanamadı (Zaman Aşımı veya Kernel reddetti).")

def cmd_watch(args):
    print(f"[*] İzleniyor: '{args.name}'\n[*] Kernel Auto-Watch modu aktif edildi, uygulama bekleniyor...")
    write_proc("target_pid", "0")
    write_proc("watch_name", args.name)
    write_proc("full_dump", "1")
    write_proc("auto_watch", "1")
    
    try:
        while True:
            if is_ready():
                print("\n[+] Süreç tespit edildi, Ring -1 Snapshot başarıyla yakalandı!")
                extract_dump(args.out)
                write_proc("auto_watch", "0")
                break
            time.sleep(0.5)
            sys.stdout.write(".")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[*] İptal edildi. Auto-Watch kapatılıyor...")
        write_proc("auto_watch", "0")

def cmd_list(args):
    print("\n=== SVM DUMP AKTİF SÜREÇ LİSTESİ ===")
    print(read_proc("process_list"))
    print("===================================\n")

def calculate_entropy(data):
    if not data: return 0.0
    # O(N) single-pass frequency count instead of O(256*N)
    counts = collections.Counter(data)
    entropy = 0
    total = len(data)
    for count in counts.values():
        p_x = count / total
        entropy -= p_x * math.log2(p_x)
    return entropy

def set_nonblocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

def trace_reader_proc(trace_file, q_out):
    """Sürekli /proc/svm_trace okuyan ve paketleyen Producer süreci."""
    try:
        with open(trace_file, "rb") as f:
            fd = f.fileno()
            # O_NONBLOCK kullanarak beklemeyi Python tarafında yönetiyoruz
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            buf = bytearray()
            while True:
                try:
                    # En fazla 64KB oku (performans için)
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        # EOF: Kernel modülü kapandı veya Matrix sona erdi + tampon boş.
                        # 100ms bekle ve tekrar dene (belki yeni bir seans başlar)
                        time.sleep(0.1)
                        continue
                    buf.extend(chunk)
                except BlockingIOError:
                    # Okunacak veri yok, CPU'yu yorma
                    time.sleep(0.01)
                except Exception as e:
                    # Ciddi bir hata (ör. modül rmmod edildi)
                    break
                
                # Tamponu erit
                while len(buf) >= ENTRY_SIZE:
                    # 1. Header'ı kontrol et
                    header_raw = buf[:ENTRY_SIZE]
                    magic = struct.unpack("<Q", header_raw[:8])[0]
                    
                    if magic != MAGIC_EXPECTED:
                        # Senkronizasyon kaybı! Bir sonraki byte'a geç ve senkron ara.
                        del buf[0]
                        q_out.put(('DROP',))
                        continue
                        
                    # 2. Header'ı tamamen aç (ENTRY_FMT: <QQIIQQQII32Q)
                    unpacked = struct.unpack(ENTRY_FMT, header_raw)
                    
                    tsc       = unpacked[1]
                    ev_type   = unpacked[2]
                    lbr_count = unpacked[3]
                    cr3       = unpacked[4]
                    rip       = unpacked[5]
                    gpa       = unpacked[6]
                    data_size = unpacked[7]
                    # unpacked[8] is _pad
                    lbr_raw   = unpacked[9:] # All 32 elements
                    
                    # 3. Senkronizasyon ve Boyut Kontrolü (Sanity Guard)
                    if ev_type == 1: # LBR
                        total_expected = ENTRY_SIZE
                    elif ev_type == 2: # MUT (DIRTY PAGE)
                        # Sanity: Sayfa verisi 4KB olmalı, ama esneklik için 16KB limit koyuyoruz.
                        if data_size > 16384:
                            # Tehlili paket veya senkron kaybı.
                            del buf[0]
                            q_out.put(('DROP',))
                            continue
                            
                        total_expected = ENTRY_SIZE + data_size
                    else:
                        # Bilinmeyen event type. Senkronu bozmamak için sadece header'ı atla.
                        total_expected = ENTRY_SIZE

                    if len(buf) < total_expected:
                        # Payload henüz gelmemiş, döngüden çıkıp daha fazla veri bekle
                        break
                        
                    # 4. Veriyi işle
                    if ev_type == 1: # LBR
                        branches = []
                        # Güvenlik: lbr_count max 16 çift (32 Q) olmalı
                        safe_count = min(lbr_count, 16)
                        for i in range(safe_count):
                            frm, to = lbr_raw[i*2], lbr_raw[i*2 + 1]
                            if frm and to:
                                branches.append((frm, to))
                        
                        # Resiliency: If no branches, send the RIP itself as a progress point
                        q_out.put(('LBR', tsc, branches, rip))
                    
                    elif ev_type == 2: # DIRTY PAGE
                        payload = bytes(buf[ENTRY_SIZE:total_expected])
                        q_out.put(('MUT', tsc, cr3, rip, gpa, payload))
                    
                    # İşlenen veriyi tampondan sil
                    del buf[:total_expected]
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[READER_ERROR] {e}")

class LiveDashboard:
    def __init__(self, stdscr, out_dir, log_file):
        self.stdscr = stdscr
        self.out_dir = out_dir
        self.log_file = log_file
        self.trace_file = "/proc/svm_trace"
        
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)

        self.stats = {"lbr": 0, "dirty": 0, "high_ent": 0, "drops": 0}
        self.recent_branches = collections.deque(maxlen=30)
        self.recent_mutations = collections.deque(maxlen=30)
        self.session_log = []
        
        self.disasm_cache = {}
        if CAPSTONE_AVAILABLE:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            self.md = None
            
        self.dirty_pages = set()
        self.q = Queue(maxsize=100000)
        self.reader = Process(target=trace_reader_proc, args=(self.trace_file, self.q))
        self.reader.daemon = True

    def process_queue(self):
        while not self.q.empty():
            try:
                msg = self.q.get_nowait()
            except Exception:
                break
                
            if msg[0] == 'DROP':
                self.stats["drops"] += 1
            elif msg[0] == 'LBR':
                _, tsc, branches, rip = msg
                self.stats["lbr"] += max(1, len(branches))
                
                if not branches:
                    # RIP point tracing
                    self.recent_branches.append((rip, rip, False))
                else:
                    for frm, to in branches:
                        to_page = to & 0xFFFFFFFFFFFFF000
                        is_dirty = to_page in self.dirty_pages
                        self.recent_branches.append((frm, to, is_dirty))
                        if self.log_file:
                            dirty_str = " [DIRTY EXEC!]" if is_dirty else ""
                            self.session_log.append(f"[LBR] TSC: {tsc} | 0x{frm:016x} -> 0x{to:016x}{dirty_str}")
            elif msg[0] == 'MUT':
                _, tsc, cr3, rip, gpa, data = msg
                self.stats["dirty"] += 1
                
                self.dirty_pages.add(gpa & 0xFFFFFFFFFFFFF000)
                ent = calculate_entropy(data)
                if ent > 7.5:
                    self.stats["high_ent"] += 1
                    if self.out_dir:
                        try:
                            with open(os.path.join(self.out_dir, f"sys_cache_{gpa:x}_{tsc}.dat"), "wb") as f:
                                f.write(data)
                        except: pass
                
                asm_str = ""
                if self.md:
                    if gpa in self.disasm_cache:
                        asm_str = self.disasm_cache[gpa]
                    else:
                        for i in self.md.disasm(data[:15], gpa):
                            asm_str = f"{i.mnemonic} {i.op_str}"
                            break
                        if not asm_str: asm_str = "[DATA/INVALID_OP]"
                        self.disasm_cache[gpa] = asm_str
                else:
                    asm_str = "[CAPS_MISSING]"
                
                self.recent_mutations.appendleft({
                    'gpa': gpa,
                    'rip': rip,
                    'ent': ent,
                    'asm': asm_str
                })
                
                if self.log_file:
                    self.session_log.append(f"\n[MUTATION] TSC: {tsc} | CR3: 0x{cr3:016x} | Fault RIP: 0x{rip:016x} | GPA: 0x{gpa:016x} | ASM: {asm_str}")

    def draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        
        title = " SVM RING -1 LIVE MALWARE MATRIX DASHBOARD (v7.0) "
        self.stdscr.addstr(0, max(0, (w - len(title)) // 2), title, curses.color_pair(1) | curses.A_BOLD)
        
        stat_line = f" Drops: {self.stats['drops']} | LBR: {self.stats['lbr']} | Mutations: {self.stats['dirty']} | High-Ent: {self.stats['high_ent']} | Tracked Pages: {len(self.dirty_pages)} "
        self.stdscr.addstr(2, 2, stat_line, curses.color_pair(3) | curses.A_BOLD)
        
        mid_x = w // 2
        
        self.stdscr.addstr(4, 2, "=== LBR MATRIX EXECUTION FLOW ===", curses.color_pair(2) | curses.A_BOLD)
        max_lbr_rows = h - 8
        
        # Akışın aşağı doğru akması için listeyi ters çeviriyoruz (en yeni en üstte)
        recent_list = list(self.recent_branches)
        recent_list.reverse()
        
        for i, branch in enumerate(recent_list[:max_lbr_rows]):
            frm, to, is_dirty = branch
            row = 5 + i
            
            self.stdscr.addstr(row, 2, "├─ ", curses.A_DIM)
            # From: Cyan, To: Yellow
            self.stdscr.addstr(row, 5, f"0x{frm:012x}", curses.color_pair(1))
            self.stdscr.addstr(row, 18, " -> ", curses.A_DIM)
            self.stdscr.addstr(row, 22, f"0x{to:012x}", curses.color_pair(2))
            
            if is_dirty:
                self.stdscr.addstr(row, 36, " [MATRIX EXECUTE] (DIRTY)", curses.color_pair(5) | curses.A_BOLD)
            elif frm == to:
                self.stdscr.addstr(row, 36, " [EXEC POINT]", curses.color_pair(3) | curses.A_DIM)
            
        self.stdscr.addstr(4, mid_x, "=== NPF DIRTY PAGES (ASM CACHE) ===", curses.color_pair(2) | curses.A_BOLD)
        max_mut_rows = h - 8
        for i, mut in enumerate(list(self.recent_mutations)[:max_mut_rows]):
            prefix = "[!!!] HIGH ENT " if mut['ent'] > 7.5 else "[*] PAGE WRITE "
            cp = curses.color_pair(4) | curses.A_BOLD if mut['ent'] > 7.5 else curses.color_pair(3)
            line = f"{prefix} GPA: {mut['gpa']:012x} | {mut['asm']}"
            self.stdscr.addstr(5 + i, mid_x + 2, line[:w - mid_x - 3], cp)
                
        self.stdscr.addstr(h - 1, 2, "Press 'q' or Ctrl+C to exit.", curses.A_DIM)
        self.stdscr.noutrefresh()
        curses.doupdate()

    def run(self):
        if not os.path.exists(self.trace_file):
            raise RuntimeError(f"{self.trace_file} not found. Is the module loaded?")
            
        self.reader.start()
        
        last_draw = 0
        while True:
            ch = self.stdscr.getch()
            if ch == ord('q'): break
            
            self.process_queue()
            
            now = time.time()
            if now - last_draw > 0.05:
                self.draw()
                last_draw = now
                
            time.sleep(0.005)
            
        self.reader.terminate()
        self.reader.join()

def cmd_live_curses(args):
    if args.out_dir and not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)
        
    try:
        dashboard = None
        def curses_wrapper(stdscr):
            nonlocal dashboard
            dashboard = LiveDashboard(stdscr, args.out_dir, args.log)
            dashboard.run()
        curses.wrapper(curses_wrapper)
        
        print("\n[*] Live Dashboard başarıyla kapatıldı.")
        if dashboard and dashboard.log_file and dashboard.session_log:
            print(f"[*] Tam kronolojik rapor {dashboard.log_file} dosyasına yazılıyor...")
            try:
                with open(dashboard.log_file, "w", encoding="utf-8") as lf:
                    lf.write("\n".join(dashboard.session_log))
                print(f"[+] Toplam {len(dashboard.session_log)} kayıt {dashboard.log_file} dosyasına kaydedildi!")
            except Exception as le:
                print(f"[!] Log yazma hatası: {le}")
            
    except Exception as e:
        print(f"\n[!] HATA: {e}")
        sys.exit(1)

def check_env():
    if os.geteuid() != 0:
        print("[!] Lütfen root yetkileriyle çalıştırın (sudo).")
        sys.exit(1)
    if not os.path.exists(PROC_DIR):
        print(f"[!] HATA: Kernel modülü {PROC_DIR} devrede değil.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="SVM CLI - Ring -1 RAM Snapshot & Trace UI (V6.6)")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    p_dump = subparsers.add_parser("dump", help="Aktif PID'ye göre RAM snapshot al (Phase 0)")
    p_dump.add_argument("--pid", type=int, required=True, help="Hedefin PID'si")
    p_dump.add_argument("--out", "-o", type=str, required=True, help="Çıktı .bin dosyası")
    
    p_watch = subparsers.add_parser("watch", help="Uygulama açılana kadar bekle (Phase 0)")
    p_watch.add_argument("--name", type=str, required=True, help="Programın adı")
    p_watch.add_argument("--out", "-o", type=str, required=True, help="Çıktı .bin dosyası")
    
    p_list = subparsers.add_parser("list", help="Mümkün süreçleri (process) listele")
    
    p_live = subparsers.add_parser("live", help="V6.6 Curses Live Trace Dashboard")
    p_live.add_argument("--out-dir", type=str, help="Mutasyona uğramış sayfalar için klasör")
    p_live.add_argument("--log", "-l", type=str, default="live_trace_report.txt", help="Çıkışta kayıtların dökümü")
    
    args = parser.parse_args()
    check_env()
    
    if args.command == "dump": cmd_dump(args)
    elif args.command == "watch": cmd_watch(args)
    elif args.command == "list": cmd_list(args)
    elif args.command == "live": cmd_live_curses(args)
    elif args.command == "trace":
        print("[*] 'trace' komutu geçersiz, yeni Curses arayüzü için 'live' komutunu kullanın.")

if __name__ == "__main__":
    main()

