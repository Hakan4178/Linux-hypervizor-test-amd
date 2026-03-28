.global _start
.text
_start:
    # 1. open("/dev/ntp_sync", O_RDWR)
    mov $2, %rax        # sys_open
    lea path(%rip), %rdi
    mov $2, %rsi        # O_RDWR
    mov $0, %rdx
    syscall

    mov %rax, %r12      # r12 = fd (dosya tanimlaticisi)
    cmp $0, %rax
    jl  error_exit

    # 2. ioctl(fd, 0x5301, 0)
    mov $16, %rax       # sys_ioctl
    mov %r12, %rdi
    mov $0x5301, %rsi
    mov $0, %rdx
    syscall

    # === BURADAN İTİBAREN KESİNLİKLE MATRIX (VMCB) İÇİNDEYİZ ===
    
    # Biz artik glibc/libc KULLANMIYORUZ!
    # Ote yandan printf v.b. yapmiyoruz. 

    # 3. close(fd) -> Proxy yakalayacak (NR = 3)
    mov $3, %rax        # sys_close
    mov %r12, %rdi
    syscall

    # 4. nanosleep(&ts, NULL) -> Proxy yakalayacak (NR = 35)
    mov $35, %rax       # sys_nanosleep
    lea ts(%rip), %rdi
    mov $0, %rsi
    syscall

    # 5. exit_group(0) -> Proxy yakalayacak (NR = 231)
    mov $231, %rax
    mov $0, %rdi
    syscall

error_exit:
    mov $231, %rax
    mov $1, %rdi
    syscall

.data
path: .asciz "/dev/ntp_sync"
ts:   .quad 1000      # 1000 saniye
      .quad 0         # 0 nanosaniye
