#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> // PRIx64 kullanımı için (isteğe bağlı)

#define SVM_IOCTL_ENTER_MATRIX _IO('S', 0x01)

static inline long native_syscall(long number, long arg1, long arg2, long arg3) {
    long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void inject_chaos(unsigned char *buffer, size_t size) {
    static uint64_t seed = 0;
    if (seed == 0) seed = (uint64_t)time(NULL) ^ (uint64_t)getpid();

    for (size_t i = 0; i < size; ++i) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        buffer[i] = (unsigned char)(seed >> 32);
        buffer[i] ^= (unsigned char)(i * 0x9E3779B9U);
        buffer[i] = (buffer[i] << 5) | (buffer[i] >> 3);
    }
}

int main() {
    printf("\033[31m[MATRIX] Red Pill Alındı. Gerçek Dünyadan Çıkış Yapılıyor...\033[0m\n");
    printf("\033[33m[PROGRAM] Saf syscall modunda çalışıyor. Glibc bypass aktif.\033[0m\n\n");

    int fd = open("/dev/ntp_sync", O_RDWR);
    if (fd < 0) {
        printf("\033[31m[!] UYARI: /dev/ntp_sync bulunamadı. Simülasyon modunda devam ediliyor...\033[0m\n");
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    printf("\033[32m[+] RING-1 MATRIX SEANSI BAŞLADI — KAOS ENJEKSİYONU AKTİF\033[0m\n\n");

    int chaos_counter = 0;
    unsigned char payload[4096];

    while (1) {
        if (fd >= 0) {
            if (ioctl(fd, SVM_IOCTL_ENTER_MATRIX, 0) < 0) break;
        }

        if (rand() % 5 == 0) {
            // Uyarıyı önlemek için formatı %016llx yaptık
            uint64_t fake_lbr_from = (uint64_t)getpid() * 4096ULL + (rand() % 0x100000);
            uint64_t fake_lbr_to = 0x400000000000ULL + (uint64_t)rand() * 0x100ULL;
            printf("\033[36m[LBR] 0x%016llx → 0x%016llx  [GHOST BRANCH]\033[0m\n", 
                   (unsigned long long)fake_lbr_from, 
                   (unsigned long long)fake_lbr_to);
        }

        if ((rand() % 6 == 0) || chaos_counter >= 8) {
            inject_chaos(payload, sizeof(payload));

            for (int i = 0; i < 32; i++) {
                payload[rand() % sizeof(payload)] ^= (unsigned char)rand();
            }

            chaos_counter = 0;
            printf("\033[35m[!!! CHAOS INJECTION] MUTATION DETECTED (~7.93 bits/byte)\033[0m\n");
            // BURASI: %llx kullanarak uyarının geldiği satırı düzelttik
            printf("\033[31m      → GPA: 0x%016llx | RIP: 0x%016llx | TYPE: CHA-CHA\033[0m\n\n",
                   (unsigned long long)(uint64_t)rand() * 0x1000000ULL,
                   (unsigned long long)(uintptr_t)native_syscall(SYS_getpid, 0, 0, 0));
        } else {
            chaos_counter++;
        }

        native_syscall(SYS_getpid, 0, 0, 0);

        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 50000000 + (rand() % 50000000);
        // Syscall'da üçüncü parametreyi de 0 geçmek daha güvenlidir
        native_syscall(SYS_nanosleep, (long)&ts, 0, 0);

        if (rand() % 20 == 0) {
            printf("\033[93m[ALERT] RING-1 SELF-MODIFYING CODE ANOMALY\033[0m\n");
        }
    }

    if (fd >= 0) close(fd);
    return 0;
}
