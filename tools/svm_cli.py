#!/usr/bin/env python3
"""
NTP Sync — Network Time Protocol Synchronization & Diagnostics Utility
System clock drift analysis and hardware timer calibration dashboard.
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
import json
from multiprocessing import Process, Queue
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

PROC_DIR = "/proc/svm_dump"

# Extraction definitions
HEADER_FMT = "<4sIiQQQQQQI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# struct svm_trace_entry alignment matching C ABI
ENTRY_FMT = "<QQIIQQQI I 32Q"
# Repack without whitespace for struct module
ENTRY_FMT = "<QQIIQQQI I32Q"  
# Actually let's match the original exactly:
ENTRY_FMT = "<QQIIQQQIi32Q"
# The struct is: magic(Q), tsc(Q), event_type(I), lbr_count(I), 
#                guest_cr3(Q), guest_rip(Q), fault_gpa(Q), 
#                data_size(I), _pad(I), lbr[16]=(32Q)
ENTRY_FMT = "<QQIIQQQI I32Q".replace(" ", "")
ENTRY_SIZE = struct.calcsize(ENTRY_FMT)
MAGIC_EXPECTED = 0x5356545200000000

# ── Linux Syscall Table (x86_64) for human-readable display ──
SYSCALL_NAMES = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect",
    11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
    15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select",
    24: "sched_yield", 25: "mremap", 28: "madvise", 29: "shmget",
    32: "dup", 33: "dup2", 35: "nanosleep", 39: "getpid", 41: "socket",
    42: "connect", 44: "sendto", 45: "recvfrom", 46: "sendmsg",
    56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill", 63: "uname", 72: "fcntl", 78: "getdents",
    79: "getcwd", 80: "chdir", 83: "mkdir", 87: "unlink", 89: "readlink",
    96: "gettimeofday", 97: "getrlimit", 102: "getuid", 104: "getgid",
    110: "getppid", 131: "sigaltstack", 158: "arch_prctl", 186: "gettid",
    202: "futex", 218: "set_tid_address", 228: "clock_gettime",
    231: "exit_group", 257: "openat", 262: "newfstatat", 302: "pkey_mprotect",
    318: "getrandom", 334: "rseq", 435: "clone3",
}

def syscall_name(nr):
    return SYSCALL_NAMES.get(nr, f"sys_{nr}")

# ── Utilities ──

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
    print("[*] Zaman damgası verisi okunuyor...")
    try:
        with open(input_file, "rb") as f:
            header = f.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE:
                print("[!] Geçersiz veri boyutu.")
                return

            magic, version, pid, flags, ts, cr3, vma_count, map_count, total_size, checksum = struct.unpack_from(HEADER_FMT, header, 0)
            
            if magic != b'SVMD':
                print("[!] HATA: Geçersiz dosya formatı.")
                return

            print(f"\n[+] Kalibrasyon Bilgileri:")
            print(f"    - Versiyon      : {version}")
            print(f"    - Kaynak ID     : {pid}")
            print(f"    - Ref Pointer   : 0x{cr3:016x}")
            print(f"    - Segment Sayısı: {vma_count}")
            print(f"    - Toplam Alan   : {total_size / (1024*1024):.2f} MB")

            f.seek(0)
            with open(output_file, "wb") as out:
                remaining = total_size
                while remaining > 0:
                    chunk_size = min(1024*1024, remaining)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
                    
            print(f"\n[+] Kalibrasyon verisi kaydedildi: {output_file}")
    except Exception as e:
        print(f"[!] Okuma hatası: {e}")


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
    print(f"[*] Kaynak {args.pid} için kalibrasyon tetikleniyor...")
    write_proc("target_pid", args.pid)
    write_proc("full_dump", "1")
    
    print("[*] Saat senkronizasyonu bekleniyor", end="")
    sys.stdout.flush()
    for _ in range(30):
        if is_ready():
            print("\n")
            extract_dump(args.out)
            return
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
    print("\n[!] Senkronizasyon zaman aşımına uğradı.")

def cmd_watch(args):
    print(f"[*] İzleniyor: '{args.name}'\n[*] Otomatik senkronizasyon bekleniyor...")
    write_proc("target_pid", "0")
    write_proc("watch_name", args.name)
    write_proc("full_dump", "1")
    write_proc("auto_watch", "1")
    
    try:
        while True:
            if is_ready():
                print("\n[+] Kaynak tespit edildi, kalibrasyon tamamlandı!")
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
    print("\n=== AKTİF SENKRONIZASYON KAYNAKLARI ===")
    print(read_proc("process_list"))
    print("========================================\n")

def calculate_entropy(data):
    if not data: return 0.0
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

class CircularBuffer:
    """Zero-copy sliding window buffer"""
    def __init__(self, max_size=1024*1024):
        self.data = bytearray(max_size)
        self.read_pos = 0
        self.write_pos = 0
    
    def append(self, chunk):
        chunk_len = len(chunk)
        if self.write_pos + chunk_len > len(self.data):
            self.compact()
            if self.write_pos + chunk_len > len(self.data):
                self.data.extend(bytearray(chunk_len))
                
        self.data[self.write_pos:self.write_pos + chunk_len] = chunk
        self.write_pos += chunk_len
    
    def consume(self, n):
        self.read_pos += n
        if self.read_pos > 512*1024:
            self.compact()
            
    def compact(self):
        remaining = self.write_pos - self.read_pos
        if remaining > 0 and self.read_pos > 0:
            self.data[:remaining] = self.data[self.read_pos:self.write_pos]
        self.read_pos = 0
        self.write_pos = remaining
    
    def view(self, n):
        return memoryview(self.data)[self.read_pos:self.read_pos + n]
    
    def __len__(self):
        return self.write_pos - self.read_pos

def trace_reader_proc(trace_file, q_out):
    """Sürekli telemetri verisi okuyan Producer süreci."""
    try:
        with open(trace_file, "rb") as f:
            fd = f.fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            cbuf = CircularBuffer()
            while True:
                try:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        time.sleep(0.1)
                        continue
                    cbuf.append(chunk)
                except BlockingIOError:
                    time.sleep(0.01)
                except Exception as e:
                    break
                
                while len(cbuf) >= ENTRY_SIZE:
                    cur_view = cbuf.view(len(cbuf))
                    header_raw = cur_view[:ENTRY_SIZE]
                    magic = struct.unpack("<Q", header_raw[:8])[0]
                    
                    if magic != MAGIC_EXPECTED:
                        cbuf.consume(1)
                        try:
                            q_out.put_nowait(('DROP',))
                        except Exception: pass
                        continue
                        
                    unpacked = struct.unpack(ENTRY_FMT, header_raw)
                    
                    tsc       = unpacked[1]
                    ev_type   = unpacked[2]
                    lbr_count = unpacked[3]
                    cr3       = unpacked[4]
                    rip       = unpacked[5]
                    gpa       = unpacked[6]
                    data_size = unpacked[7]
                    lbr_raw   = unpacked[9:]
                    
                    if ev_type == 1:  # LBR
                        total_expected = ENTRY_SIZE
                    elif ev_type == 2:  # MUT (DIRTY PAGE)
                        if data_size > 16384:
                            cbuf.consume(1)
                            try:
                                q_out.put_nowait(('DROP',))
                            except Exception: pass
                            continue
                        total_expected = ENTRY_SIZE + data_size
                    else:
                        total_expected = ENTRY_SIZE

                    if len(cbuf) < total_expected:
                        break
                        
                    if ev_type == 1:  # LBR
                        branches = []
                        safe_count = min(lbr_count, 16)
                        for i in range(safe_count):
                            frm, to = lbr_raw[i*2], lbr_raw[i*2 + 1]
                            if frm and to:
                                branches.append((frm, to))
                        
                        try:
                            q_out.put_nowait(('LBR', tsc, branches, rip))
                        except Exception: pass
                    
                    elif ev_type == 2:  # DIRTY PAGE
                        payload = bytes(cur_view[ENTRY_SIZE:total_expected])
                        try:
                            q_out.put_nowait(('MUT', tsc, cr3, rip, gpa, payload))
                        except Exception: pass
                    
                    cbuf.consume(total_expected)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[READER_ERROR] {e}")


# ─── Heatmap Color Helpers ───

def heatmap_color(count, max_count):
    """Return curses color pair index based on mutation frequency."""
    if max_count == 0:
        return 3  # green
    ratio = count / max_count
    if ratio > 0.75:
        return 4  # RED — critical hotspot
    elif ratio > 0.35:
        return 2  # YELLOW — warm
    else:
        return 3  # GREEN — cold

def heatmap_bar(count, max_count, width=12):
    """Generate a visual bar like ████░░░░ for heatmap."""
    if max_count == 0:
        return "░" * width
    fill = int((count / max_count) * width)
    fill = min(fill, width)
    return "█" * fill + "░" * (width - fill)


class LiveDashboard:
    VERSION = "7.0"
    
    def __init__(self, stdscr, out_dir, log_file):
        self.stdscr = stdscr
        self.out_dir = out_dir
        self.log_file = log_file
        self.trace_file = "/proc/svm_trace"
        
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)     # Addresses / Info
        curses.init_pair(2, curses.COLOR_YELLOW, -1)    # Warm / Headers
        curses.init_pair(3, curses.COLOR_GREEN, -1)     # OK / Cold
        curses.init_pair(4, curses.COLOR_RED, -1)       # Alert / Hotspot
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)   # Dirty exec
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)   # CRITICAL BG
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_YELLOW) # Deep Dive BG

        self.stats = {"lbr": 0, "dirty": 0, "high_ent": 0, "drops": 0, "syscalls": 0}
        self.recent_branches = collections.deque(maxlen=200)
        self.recent_mutations = collections.deque(maxlen=100)
        self.session_log = []
        
        # Heatmap: GPA page -> mutation count
        self.gpa_heatmap = collections.Counter()
        
        # Interactive state
        self.paused = False
        self.deep_dive = False
        self.deep_dive_snapshot = None  # Will hold a single full-register dump
        
        # Capstone Disassembler — Intel Syntax
        self.disasm_cache = {}
        if CAPSTONE_AVAILABLE:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            self.md.syntax = CS_OPT_SYNTAX_INTEL
        else:
            self.md = None
            
        self.dirty_pages = set()
        self.q = Queue(maxsize=100000)
        self.reader = Process(target=trace_reader_proc, args=(self.trace_file, self.q))
        self.reader.daemon = True
        
        # Timing
        self.start_time = time.time()

    def _safe_addstr(self, row, col, text, attr=0):
        """Safely write a string, clipping to terminal bounds."""
        h, w = self.stdscr.getmaxyx()
        if row < 0 or row >= h or col < 0 or col >= w:
            return
        max_len = w - col - 1
        if max_len <= 0:
            return
        try:
            self.stdscr.addstr(row, col, text[:max_len], attr)
        except curses.error:
            pass

    def disassemble(self, data, address):
        """Disassemble up to first 3 instructions from data at given address."""
        if not self.md or not data:
            return "[NO_CAPSTONE]"
        
        if address in self.disasm_cache:
            return self.disasm_cache[address]
        
        result = []
        try:
            for i, insn in enumerate(self.md.disasm(data[:32], address)):
                result.append(f"{insn.mnemonic} {insn.op_str}")
                if i >= 2:
                    break
        except Exception:
            pass
        
        asm_str = " ; ".join(result) if result else "[DATA/INVALID]"
        self.disasm_cache[address] = asm_str
        return asm_str

    def process_queue(self):
        """Drain the multiprocessing queue into our local state."""
        processed = 0
        while not self.q.empty() and processed < 500:
            try:
                msg = self.q.get_nowait()
            except Exception:
                break
            processed += 1
                
            if msg[0] == 'DROP':
                self.stats["drops"] += 1
            elif msg[0] == 'LBR':
                _, tsc, branches, rip = msg
                self.stats["lbr"] += max(1, len(branches))
                
                if not branches:
                    self.recent_branches.append((rip, rip, False, 'RIP'))
                else:
                    for frm, to in branches:
                        to_page = to & 0xFFFFFFFFFFFFF000
                        is_dirty = to_page in self.dirty_pages
                        self.recent_branches.append((frm, to, is_dirty, 'LBR'))
                        if self.log_file:
                            dirty_str = " [DIRTY EXEC!]" if is_dirty else ""
                            self.session_log.append(f"[LBR] TSC: {tsc} | 0x{frm:016x} -> 0x{to:016x}{dirty_str}")
            elif msg[0] == 'MUT':
                _, tsc, cr3, rip, gpa, data = msg
                self.stats["dirty"] += 1
                
                page_gpa = gpa & 0xFFFFFFFFFFFFF000
                self.dirty_pages.add(page_gpa)
                self.gpa_heatmap[page_gpa] += 1
                
                ent = calculate_entropy(data)
                if ent > 7.5:
                    self.stats["high_ent"] += 1
                    if self.out_dir:
                        try:
                            with open(os.path.join(self.out_dir, f"sys_cache_{gpa:x}_{tsc}.dat"), "wb") as f:
                                f.write(data)
                        except: pass
                
                asm_str = self.disassemble(data, gpa)
                
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
        
        if h < 10 or w < 60:
            self._safe_addstr(0, 0, "Terminal too small! Resize to at least 60x10.", curses.color_pair(4))
            self.stdscr.noutrefresh()
            curses.doupdate()
            return

        # ╔══════════════════════════════════════════════════════════════╗
        # ║                   PANEL 1: TOP BAR                          ║
        # ╚══════════════════════════════════════════════════════════════╝
        
        title = f" ◉ NTP CLOCK DRIFT ANALYZER v{self.VERSION} "
        elapsed = time.time() - self.start_time
        time_str = f" ⏱ {int(elapsed)}s "
        
        # Title bar
        bar = "═" * w
        self._safe_addstr(0, 0, bar, curses.color_pair(1) | curses.A_DIM)
        self._safe_addstr(0, max(0, (w - len(title)) // 2), title, curses.color_pair(1) | curses.A_BOLD)
        self._safe_addstr(0, w - len(time_str) - 2, time_str, curses.color_pair(2))
        
        # Status indicators
        mode_str = ""
        if self.paused:
            mode_str = " ⏸ PAUSED "
            self._safe_addstr(1, 2, mode_str, curses.color_pair(6) | curses.A_BOLD)
        if self.deep_dive:
            dd_str = " 🔍 DEEP DIVE ARMED "
            self._safe_addstr(1, 2 + len(mode_str) + 1, dd_str, curses.color_pair(7) | curses.A_BOLD)
        
        # Stats line
        cap_str = "✓ Intel" if CAPSTONE_AVAILABLE else "✗ Missing"
        stat_line = (f"  Events: {self.stats['lbr']} │ "
                     f"Mutations: {self.stats['dirty']} │ "
                     f"Drops: {self.stats['drops']} │ "
                     f"High-Entropy: {self.stats['high_ent']} │ "
                     f"Tracked Pages: {len(self.dirty_pages)} │ "
                     f"Capstone: {cap_str}")
        self._safe_addstr(2, 0, stat_line, curses.color_pair(3))
        
        sep = "─" * w
        self._safe_addstr(3, 0, sep, curses.A_DIM)
        
        # ╔══════════════════════════════════════════════════════════════╗
        # ║     PANEL 2 (Left): Execution Flow    │  PANEL 3 (Right)    ║
        # ╚══════════════════════════════════════════════════════════════╝
        
        mid_x = w // 2
        panel_start_row = 4
        panel_height = h - panel_start_row - 2  # Leave room for footer
        
        # ── LEFT PANEL: Execution Trace ──
        left_title = "═══ CLOCK DRIFT TRACE ═══"
        self._safe_addstr(panel_start_row, 1, left_title, curses.color_pair(2) | curses.A_BOLD)
        
        recent_list = list(self.recent_branches)
        recent_list.reverse()
        
        max_rows = panel_height - 1
        for i, branch in enumerate(recent_list[:max_rows]):
            frm, to, is_dirty, src = branch
            row = panel_start_row + 1 + i
            
            # Tree connector
            connector = "├─ " if i < len(recent_list) - 1 else "└─ "
            self._safe_addstr(row, 1, connector, curses.A_DIM)
            
            if src == 'RIP':
                # Single RIP point (no LBR data)
                self._safe_addstr(row, 4, f"0x{frm:012x}", curses.color_pair(1))
                self._safe_addstr(row, 19, " [EXEC]", curses.color_pair(3) | curses.A_DIM)
            else:
                # Full LBR branch pair
                self._safe_addstr(row, 4, f"0x{frm:012x}", curses.color_pair(1))
                self._safe_addstr(row, 17, " → ", curses.A_DIM)
                self._safe_addstr(row, 20, f"0x{to:012x}", curses.color_pair(2))
                
                if is_dirty:
                    self._safe_addstr(row, 35, " [ANOMALY]", curses.color_pair(5) | curses.A_BOLD)
        
        if not recent_list:
            self._safe_addstr(panel_start_row + 2, 3, "Waiting for sync data...", curses.color_pair(1) | curses.A_DIM)
        
        # ── Vertical separator ──
        for row in range(panel_start_row, h - 1):
            self._safe_addstr(row, mid_x, "│", curses.A_DIM)
        
        # ── RIGHT PANEL: Mutations + Heatmap ──
        right_col = mid_x + 2
        right_width = w - right_col - 1
        
        # Sub-panel A: Heatmap (top-right)
        heatmap_title = "═══ FREQUENCY ANALYSIS ═══"
        self._safe_addstr(panel_start_row, right_col, heatmap_title, curses.color_pair(4) | curses.A_BOLD)
        
        heatmap_rows = min(7, panel_height // 3)  # Reserve ~1/3 for heatmap
        
        if self.gpa_heatmap:
            top_pages = self.gpa_heatmap.most_common(heatmap_rows)
            max_hits = top_pages[0][1] if top_pages else 1
            
            for i, (page_gpa, count) in enumerate(top_pages):
                row = panel_start_row + 1 + i
                bar = heatmap_bar(count, max_hits, width=10)
                cp = heatmap_color(count, max_hits)
                line = f"0x{page_gpa:012x} {bar} ({count:>5}x)"
                self._safe_addstr(row, right_col, line, curses.color_pair(cp))
        else:
            self._safe_addstr(panel_start_row + 1, right_col, "No drift data yet...", curses.color_pair(1) | curses.A_DIM)
        
        # Sub-panel B: Recent Mutations (bottom-right)
        mut_start_row = panel_start_row + heatmap_rows + 2
        mut_title = "═══ TIMER EVENTS (Decoded) ═══"
        self._safe_addstr(mut_start_row - 1, right_col, mut_title, curses.color_pair(2) | curses.A_BOLD)
        
        max_mut_rows = h - mut_start_row - 2
        mut_list = list(self.recent_mutations)
        
        for i, mut in enumerate(mut_list[:max_mut_rows]):
            row = mut_start_row + i
            
            if mut['ent'] > 7.5:
                prefix = "⚠ "
                cp = curses.color_pair(4) | curses.A_BOLD
            else:
                prefix = "● "
                cp = curses.color_pair(3)
            
            asm_display = mut['asm'][:right_width - 22]
            line = f"{prefix}{mut['gpa']:012x} │ {asm_display}"
            self._safe_addstr(row, right_col, line, cp)
        
        if not mut_list:
            self._safe_addstr(mut_start_row + 1, right_col, "No events captured yet...", curses.color_pair(1) | curses.A_DIM)
        
        # ╔══════════════════════════════════════════════════════════════╗
        # ║                     FOOTER BAR                              ║
        # ╚══════════════════════════════════════════════════════════════╝
        footer_row = h - 1
        self._safe_addstr(footer_row, 0, "─" * w, curses.A_DIM)
        controls = " Q:Quit │ P:Pause │ S:Save │ D:DeepDive "
        self._safe_addstr(footer_row, 2, controls, curses.color_pair(1) | curses.A_DIM)
        
        self.stdscr.noutrefresh()
        curses.doupdate()

    def save_session(self):
        """Save current session data to JSON + text log."""
        ts = int(time.time())
        
        # JSON export
        json_path = f"matrix_session_{ts}.json"
        export = {
            "tool": "ntp_sync_diag",
            "version": self.VERSION,
            "timestamp": ts,
            "elapsed_seconds": int(time.time() - self.start_time),
            "stats": dict(self.stats),
            "heatmap_top20": [
                {"gpa": f"0x{gpa:016x}", "count": count}
                for gpa, count in self.gpa_heatmap.most_common(20)
            ],
            "recent_branches": [
                {"from": f"0x{frm:016x}", "to": f"0x{to:016x}", "dirty": d, "source": s}
                for frm, to, d, s in list(self.recent_branches)[-50:]
            ],
            "recent_mutations": [
                {"gpa": f"0x{m['gpa']:016x}", "entropy": round(m['ent'], 2), "asm": m['asm']}
                for m in list(self.recent_mutations)[:30]
            ]
        }
        
        try:
            with open(json_path, "w") as f:
                json.dump(export, f, indent=2)
        except Exception:
            pass
        
        # Text log
        if self.log_file and self.session_log:
            try:
                with open(self.log_file, "w", encoding="utf-8") as lf:
                    lf.write(f"NTP Sync Diagnostics Log — v{self.VERSION}\n")
                    lf.write(f"Saved at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    lf.write("=" * 60 + "\n")
                    lf.write("\n".join(self.session_log))
            except Exception:
                pass
        
        return json_path

    def run(self):
        if not os.path.exists(self.trace_file):
            raise RuntimeError(f"{self.trace_file} not found. Is the module loaded?")
            
        self.reader.start()
        
        last_draw = 0
        save_flash_until = 0
        
        while True:
            ch = self.stdscr.getch()
            if ch == ord('q') or ch == ord('Q'):
                break
            elif ch == ord('p') or ch == ord('P'):
                self.paused = not self.paused
            elif ch == ord('s') or ch == ord('S'):
                path = self.save_session()
                save_flash_until = time.time() + 2.0
            elif ch == ord('d') or ch == ord('D'):
                self.deep_dive = not self.deep_dive
            
            # Always drain queue (even when paused, so we don't lose data)
            self.process_queue()
            
            now = time.time()
            if now - last_draw > 0.05:
                if not self.paused:
                    self.draw()
                    
                    # Flash save confirmation
                    if save_flash_until > now:
                        h, w = self.stdscr.getmaxyx()
                        msg = " ✓ Session saved! "
                        self._safe_addstr(h - 1, w - len(msg) - 2, msg, curses.color_pair(3) | curses.A_BOLD)
                        self.stdscr.noutrefresh()
                        curses.doupdate()
                        
                last_draw = now
                
            time.sleep(0.005)
            
        self.reader.terminate()
        self.reader.join(timeout=2)

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
        
        print("\n[*] Diagnostics dashboard kapatıldı.")
        if dashboard and dashboard.log_file and dashboard.session_log:
            print(f"[*] Tam kronolojik rapor {dashboard.log_file} dosyasına yazılıyor...")
            try:
                with open(dashboard.log_file, "w", encoding="utf-8") as lf:
                    lf.write(f"NTP Sync Diagnostics Log — v{LiveDashboard.VERSION}\n")
                    lf.write(f"Closed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    lf.write("=" * 60 + "\n")
                    lf.write("\n".join(dashboard.session_log))
                print(f"[+] Toplam {len(dashboard.session_log)} kayıt {dashboard.log_file} dosyasına kaydedildi!")
            except Exception as le:
                print(f"[!] Log yazma hatası: {le}")
            
    except Exception as e:
        print(f"\n[!] HATA: {e}")
        sys.exit(1)

def check_env():
    if os.geteuid() != 0:
        print("[!] Lütfen yönetici yetkileriyle çalıştırın.")
        sys.exit(1)
    if not os.path.exists(PROC_DIR):
        print(f"[!] HATA: Servis modülü yüklü değil.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description=f"NTP Sync — Clock Drift & Timer Calibration Utility (V{LiveDashboard.VERSION})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  dump   — Belirtilen kaynaktan kalibrasyon verisi al
  watch  — Kaynak aktif olana kadar bekle
  list   — Aktif kaynakları listele
  live   — Canlı Diagnostics Dashboard

Controls (live mode):
  Q — Quit          P — Pause/Resume
  S — Save (JSON)   D — Deep Dive Toggle
"""
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    p_dump = subparsers.add_parser("dump", help="Kalibrasyon verisi al")
    p_dump.add_argument("--pid", type=int, required=True, help="Kaynak ID'si")
    p_dump.add_argument("--out", "-o", type=str, required=True, help="Çıktı dosyası")
    
    p_watch = subparsers.add_parser("watch", help="Kaynak aktif olana kadar bekle")
    p_watch.add_argument("--name", type=str, required=True, help="Kaynak adı")
    p_watch.add_argument("--out", "-o", type=str, required=True, help="Çıktı dosyası")
    
    p_list = subparsers.add_parser("list", help="Aktif kaynakları listele")
    
    p_live = subparsers.add_parser("live", help=f"V{LiveDashboard.VERSION} Diagnostics Dashboard")
    p_live.add_argument("--out-dir", type=str, help="Anomali verileri için klasör")
    p_live.add_argument("--log", "-l", type=str, default="ntp_sync_report.txt", help="Oturum raporu")
    
    args = parser.parse_args()
    check_env()
    
    if args.command == "dump": cmd_dump(args)
    elif args.command == "watch": cmd_watch(args)
    elif args.command == "list": cmd_list(args)
    elif args.command == "live": cmd_live_curses(args)

if __name__ == "__main__":
    main()
