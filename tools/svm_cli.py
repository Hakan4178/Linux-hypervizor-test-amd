#!/usr/bin/env python3
"""
SVM CLI - Unified Ring-1 Snapshot Tool (V5.0)
Replaces manual /proc/echo interactions with a single clean interface.
"""

import sys
import os
import time
import struct
import argparse

PROC_DIR = "/proc/svm_dump"

# Extraction definitions
HEADER_FMT = "<4sIiQQQQQQI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

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
    print(f"    - Kernel CR3    : 0x{cr3:x}")
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
    
    print("[*] Kernel hipervizörünün hafızayı dondurması bekleniyor...")
    time.sleep(1)
    
    if is_ready():
        extract_dump(args.out)
    else:
        print("[!] İşlem başarısız veya kernel reddetti.")

def cmd_watch(args):
    print(f"[*] İzleniyor: '{args.name}'\n[*] Kernel Auto-Watch modu aktif edildi, uygulama bekleniyor...")
    
    # Eskiyi temizle
    write_proc("target_pid", "0")
    write_proc("watch_name", args.name)
    write_proc("full_dump", "1")
    write_proc("auto_watch", "1")
    
    try:
        while True:
            if is_ready():
                print("\n[+] Süreç tespit edildi, Ring -1 Snapshot başarıyla yakalandı!")
                extract_dump(args.out)
                write_proc("auto_watch", "0") # Oto modu kapat
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

def check_env():
    if os.geteuid() != 0:
        print("[!] Lütfen root yetkileriyle çalıştırın (sudo).")
        sys.exit(1)
    if not os.path.exists(PROC_DIR):
        print(f"[!] HATA: Kernel modülü yüklü değil! {PROC_DIR} bulunamadı.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="SVM CLI - Ring -1 RAM Snapshot Aracı", epilog="Mükemmel Gnu-Tarzı Gizli Hipervizör Yönetimi")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    p_dump = subparsers.add_parser("dump", help="Aktif PID'ye göre RAM snapshot al")
    p_dump.add_argument("--pid", type=int, required=True, help="Hedefin PID'si")
    p_dump.add_argument("--out", "-o", type=str, required=True, help="Çıktı .bin dosyasının yolu")
    
    p_watch = subparsers.add_parser("watch", help="Uygulama açılana kadar bekle ve ilk baytta dondur")
    p_watch.add_argument("--name", type=str, required=True, help="Programın tam adı (Örn: game.exe)")
    p_watch.add_argument("--out", "-o", type=str, required=True, help="Çıktı .bin dosyasının yolu")
    
    p_list = subparsers.add_parser("list", help="Mümkün süreçleri (process) listele")
    
    args = parser.parse_args()
    check_env()
    
    if args.command == "dump": cmd_dump(args)
    elif args.command == "watch": cmd_watch(args)
    elif args.command == "list": cmd_list(args)

if __name__ == "__main__":
    main()
