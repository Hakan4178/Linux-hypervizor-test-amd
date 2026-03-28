#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>

/* Glibc'yi tamamen atlatmak için Saf Inline Assembly Syscall fonksiyonu */
static inline long native_syscall(long number, long arg1, long arg2, long arg3) {
    long ret;
    asm volatile (
        "syscall"
        : "=a"(ret)
        : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

#define SVM_IOCTL_ENTER_MATRIX _IO('S', 0x01)

int main() {
    printf("[PROGRAM] Gercek Dunyadayim. Glibc (ld.so) basariyla yuklendi!\n");
    
    int fd = open("/dev/ntp_sync", O_RDWR);
    if (fd < 0) {
        printf("[PROGRAM] HATA: /dev/ntp_sync (Portal) acilamadi!\n");
        return 1;
    }
    
    printf("[PROGRAM] Kirmizi hapi (ioctl) yutuyorum. 1000 saniye uykudayim...\n");
    
    if (ioctl(fd, SVM_IOCTL_ENTER_MATRIX, 0) < 0) {
        printf("[PROGRAM] HATA: ioctl cagirisi reddedildi!\n");
        return 1;
    }
    
    /* ==========================================================
     * BURADAN ITIBAREN HICBIR KOD GERCEK DUNYADA CALISMIYOR! 
     * HEDEF, HIPERVIZORUN (VMCB) ICINDEDIR.
     * ==========================================================
     * Glibc wrapper'i bile kullanmiyoruz cunku arkaplanda gizlice
     * sys_write veya thread-tracking yapabiliyor! %100 Saf Assembly.
     */
    
    native_syscall(SYS_close, fd, 0, 0); /* NR = 3 */
    
    struct timespec ts = {1000, 0};
    native_syscall(SYS_nanosleep, (long)&ts, 0, 0); /* NR = 35 */

    native_syscall(SYS_exit_group, 0, 0, 0); /* NR = 231 */
    return 0; 
}
