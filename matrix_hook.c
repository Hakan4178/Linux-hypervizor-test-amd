#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#define SVM_IOCTL_ENTER_MATRIX _IO('S', 0x01)

/* Syscall exit parameters as defined in the hypervisor */
struct matrix_exit_info {
    unsigned long long exit_reason;
    unsigned long long guest_rip;
    unsigned long long rax, rbx, rcx, rdx, rsi, rdi;
    unsigned long long r8, r9, r10, r11, r12, r13, r14, r15;
    unsigned long long xmm[16][2];
};

/* 
 * 1. NATIVE SYSCALL BYPASS
 * Glibc'nin syscall wrapper'larını (open, ioctl, close) kullanmıyoruz. 
 * VMP veya anti-cheat'ler libc hook atarak izleme yaparsa, bizim çağrılarımızı 
 * asla göremezler. Doğrudan donanım kesmesi atıyoruz.
 */
static inline long native_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long ret;
    register long r10 asm("r10") = arg4;
    register long r8 asm("r8") = arg5;
    register long r9 asm("r9") = arg6;

    asm volatile(
        "syscall"
        : "=a"(ret)
        : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/*
 * 2. EARLY EXECUTION (CONSTRUCTOR)
 * Hedef yazılımın main() veya OEP (_start) işlemleri başlamadan hemen önce çalışır.
 */
static void __attribute__((constructor)) init_matrix(void) {
    /*
     * 3. STRING OBFUSCATION
     * "/dev/ntp_sync" string'inin .rodata section'da kabak gibi görünmesini engelliyoruz.
     * VMP static analizi veya signature taramaları bu string'i bulamaz.
     * Stack üzerinde karakter karakter inşa edilir.
     */
    volatile char dev_path[] = {'/', 'd', 'e', 'v', '/', 'n', 't', 'p', '_', 's', 'y', 'n', 'c', '\0'};

    // sys_open
    long fd = native_syscall(2, (long)dev_path, 2 /* O_RDWR */, 0, 0, 0, 0);
    
    if (fd >= 0) {
        struct matrix_exit_info exit_info;
        
        while (1) {
            // sys_ioctl -> MATRIX'E GİRİŞ YAPILDI / VEYA DEVAM EDİLDİ
            long ret = native_syscall(16, fd, SVM_IOCTL_ENTER_MATRIX, (long)&exit_info, 0, 0, 0);

            if (ret == 2) {
                // SYSCALL PASSTHROUGH TRAMPOLINE
                // The VM exited because the guest executed a syscall. We must run it for the guest natively!
                long sys_nr = exit_info.rax;
                
                // Exclude dangerous syscalls that might kill our trampoline thread
                if (sys_nr == 60 || sys_nr == 231) { // exit or exit_group
                    // Matrix naturally ends with the program!
                    break;
                }

                // Execute the syscall natively on the host!
                exit_info.rax = native_syscall(sys_nr, exit_info.rdi, exit_info.rsi, exit_info.rdx, exit_info.r10, exit_info.r8, exit_info.r9);
                
                // Do NOT close FD, loop back and re-enter the VMRUN with the syscall result!
            } else if (ret < 0) {
                // Hypervisor Fatal Error or Kill switch triggered. Eject Matrix!
                break;
            } else {
                // Matrix gracefully finished? (Shouldn't happen unless specifically requested)
                break; 
            }
        }
        
        /* 
         * 4. STEALTH FILE DESCRIPTOR
         * Hemen açtığımız dosya tanımlayıcısını (fd) kapatıyoruz.
         */
        native_syscall(3, fd, 0, 0, 0, 0, 0);
    }
}
