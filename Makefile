obj-m += ring_minus_one.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ccflags-y += -Wall \
             -Wextra \
             -Werror \
             -Wshadow \
             -Wundef \
             -Wstrict-prototypes \
             -Wmissing-prototypes \
             -Wmissing-declarations \
             -Wcast-align \
             -Wwrite-strings \
             -Wconversion \
             -Wsign-conversion \
             -Wnull-dereference \
             -Wdouble-promotion \
             -Wformat=2 \
             -Wimplicit-fallthrough \
             -Wvla \
             -Wpointer-arith \
             -Wstack-usage=1024 \
             -Wframe-larger-than=2048 \
             -DDEBUG \
             -O2 \
             -g

# Kernel config sanity check
check-config:
	@echo "[*] Kernel config kontrol ediliyor..."
	@grep CONFIG_KVM /boot/config-$(shell uname -r) || echo "KVM yok"
	@grep CONFIG_KVM_AMD /boot/config-$(shell uname -r) || echo "KVM_AMD yok"
	@grep CONFIG_AMD_SVM /boot/config-$(shell uname -r) || echo "SVM yok"
	@grep CONFIG_X86_SMAP /boot/config-$(shell uname -r) || echo "SMAP yok"
	@grep CONFIG_X86_SMEP /boot/config-$(shell uname -r) || echo "SMEP yok"

# Build
all: check-config
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Install + dmesg live
load:
	sudo insmod ring_minus_one.ko || true
	dmesg | tail -n 50

# Remove
unload:
	sudo rmmod ring_minus_one || true
	dmesg | tail -n 50

# Debug: symbol ve relocation kontrolü
inspect:
	@echo "[*] nm:"
	nm -C ring_minus_one.ko || true
	@echo "[*] objdump:"
	objdump -d ring_minus_one.ko | less

# Runtime risk check (çok önemli)
runtime-check:
	@echo "[*] CPU flags:"
	grep svm /proc/cpuinfo || echo "SVM YOK"
	@echo "[*] MSR erişim:"
	sudo modprobe msr || true
	@echo "[*] KVM modülleri:"
	lsmod | grep kvm || echo "KVM yüklenmemiş"
	@echo "[*] NX durumu:"
	dmesg | grep NX || true

# Full clean
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
