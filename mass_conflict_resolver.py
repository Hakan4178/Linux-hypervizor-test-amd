import os

def resolve_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return False
        
    out_lines = []
    in_head = False
    in_incoming = False
    modified = False
    
    for line in lines:
        if line.startswith('<<<<<<< HEAD'):
            in_head = True
            modified = True
        elif line.startswith('======='):
            in_head = False
            in_incoming = True
        elif line.startswith('>>>>>>>'):
            in_incoming = False
        else:
            if in_head:
                pass # Kötü/Eski kodu çöpe at
            elif in_incoming:
                out_lines.append(line) # Yeni (V6.7) kodu tut
            else:
                out_lines.append(line) # Normal satırları tut
                
    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(out_lines)
        print(f"FIXED: {filepath}")
        return True
    return False

print("Git çakışmaları temizleniyor...")
count = 0
for root, dirs, files in os.walk('/home/hakan/kernel'):
    if '.git' in root or '.gemini' in root:
        continue
    for file in files:
        if file.endswith(('.c', '.h', '.md', '.py', 'Makefile')):
            if resolve_file(os.path.join(root, file)):
                count += 1
print(f"Toplam {count} dosya başarıyla kurtarıldı!")
