# SVM Dump V3.1 — Hardened Makefile
# Derleme zamanında maximum hata yakalama

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m += ring_minus_one.o hakan_shield.o
ring_minus_one-objs := svm_engine.o tsc_stealth.o npt_map.o snapshot.o procfs_iface.o vmexit.o main.o

# ─── Sertleştirilmiş Derleyici Bayrakları ───
# -Werror           : Tüm uyarılar hata olarak ele alınır
# -Wall             : Tüm standart uyarılar (zaten kernel default)
# -Wextra           : Ekstra uyarılar
# -Wno-unused-parameter : Kernel callback'leri kullanılmayan parametre alabilir
# -Wimplicit-fallthrough : switch-case'de break eksikliği
# -Wformat=2        : printf format string güvenliği
# -Wcast-align      : Hizalama uyumsuz cast'ler
# -Wpointer-arith   : void* aritmetiği (undefined behavior)
# -Wshadow          : İç scope'da dış değişken gölgeleme
# -Wstack-usage=1024: Fonksiyon başına max stack kullanımı (triple fault önleme)
# -Wframe-larger-than=768 : Stack frame boyutu limiti
# -Wvla             : Variable-Length Array yasağı (stack taşması riski)
# -Wundef           : Tanımsız makro kullanımı uyarısı
# -Wstrict-prototypes : Prototipsiz fonksiyon yasağı
# -Wmissing-prototypes : Eksik prototip uyarısı
# -Wredundant-decls : Gereksiz tekrar deklarasyon
# -Wnull-dereference : NULL pointer dereference tespiti (GCC 12+)
# -Warray-bounds=2  : Dizi sınırları kontrolü (buffer overflow tespiti)
# -Wshift-overflow=2: Bit shift taşması kontrolü
# -Wlogical-op      : Şüpheli mantıksal operatör kullanımı
# -Wduplicated-cond : Tekrarlanan if koşulları
# -Wjump-misses-init: goto'nun değişken init'ini atlaması

ccflags-y += -Werror
ccflags-y += -Wextra -Wno-unused-parameter
ccflags-y += -Wformat=2
ccflags-y += -Wcast-align
ccflags-y += -Wstack-usage=1024
ccflags-y += -Wframe-larger-than=768
ccflags-y += -Wvla
ccflags-y += -Wundef
ccflags-y += -Wstrict-prototypes
ccflags-y += -Wmissing-prototypes
ccflags-y += -Warray-bounds=2
ccflags-y += -Wshift-overflow=2
ccflags-y += -Wimplicit-fallthrough

# GCC 12+ only flags (harmlessly ignored on older)
ccflags-y += $(call cc-option,-Wnull-dereference)
ccflags-y += $(call cc-option,-Wlogical-op)
ccflags-y += $(call cc-option,-Wduplicated-cond)
ccflags-y += $(call cc-option,-Wjump-misses-init)

# ─── Stack Protector (buffer overflow runtime guard) ───
ccflags-y += -fstack-protector-strong

# ─── Hedefler ───
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Hızlı syntax check (derleme yok, sadece uyarılar)
check:
	$(MAKE) -C $(KDIR) M=$(PWD) C=1 modules

# Sparse static analysis
sparse:
	$(MAKE) -C $(KDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN__" modules

.PHONY: all clean check sparse
