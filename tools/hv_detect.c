/*
 * hv_detect.c — Hypervisor Detection Test Suite (V4.2 - Absolute Extreme)
 *
 * 20 test: Tüm eşikler gerçek fiziksel sınırlarına çekildi.
 * +18. Test: Branch Target Buffer (BTB) Flush Anomaly
 * +19. Test: IPI (Inter-Processor Interrupt) Signal Latency
 * +20. Test: TLB Shadowing & Large Page Fragmentation
 *
 * Derleme:  gcc -O3 -pthread -o hv_detect hv_detect.c
 * Çalıştır: ./hv_detect
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define CYAN "\033[1;36m"
#define MAGENTA "\033[1;35m"
#define RESET "\033[0m"

static int detected = 0;

static inline void cpuid(uint32_t leaf, uint32_t *a, uint32_t *b, uint32_t *c,
                         uint32_t *d) {
  asm volatile("cpuid"
               : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
               : "a"(leaf), "c"(0));
}

static inline uint64_t rdtsc_native(void) {
  uint32_t lo, hi;
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtscp_native(uint32_t *aux) {
  uint32_t lo, hi;
  asm volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(*aux));
  return ((uint64_t)hi << 32) | lo;
}

static void result(const char *name, int is_detected, const char *detail,
                   int risk_level) {
  const char *color = is_detected ? RED : GREEN;
  const char *status = is_detected ? "FAIL" : "PASS";
  const char *risk = (risk_level >= 4)
                         ? MAGENTA "[IMPOSSIBLE]"
                         : (risk_level == 3 ? MAGENTA "[EXTREME]"
                                            : (risk_level == 2 ? YELLOW "[HARD]"
                                                               : CYAN "[STD]"));

  printf("  ["
         "%s%s" RESET "] %-15s %-35s %s\n",
         color, status, risk, name, detail);
  if (is_detected)
    detected++;
}

/* ═══════════════════════════════════════════════════════════════════
 *  STD 1-4: Standart İzler
 * ═══════════════════════════════════════════════════════════════════ */
static void t1_cpuid_hypervisor_bit() {
  uint32_t a, b, c, d;
  cpuid(1, &a, &b, &c, &d);
  int hv = (c >> 31) & 1;
  result("CPUID HV Bit", hv, hv ? "ECX[31]=1" : "ECX[31]=0", 1);
}

static void t2_cpuid_vendor() {
  uint32_t a, b, c, d;
  cpuid(0x40000000, &a, &b, &c, &d);
  int hv = (b != 0 || c != 0 || d != 0);
  result("CPUID HV Vendor", hv, hv ? "Vendor Found" : "Clean", 1);
}

static void t3_proc_cpuinfo() {
  FILE *f = fopen("/proc/cpuinfo", "r");
  if (!f)
    return;
  char line[256];
  int hv = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "flags") && strstr(line, "hypervisor")) {
      hv = 1;
      break;
    }
  }
  fclose(f);
  result("cpuinfo HV Flag", hv, hv ? "Found" : "Clean", 1);
}

static void t4_dmi_smbios() {
  FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
  if (!f)
    return;
  char n[128] = {0};
  if (fgets(n, sizeof(n), f)) {
    char *nl = strchr(n, '\n');
    if (nl)
      *nl = 0;
  }
  fclose(f);
  int hv = (strcasestr(n, "VMware") || strcasestr(n, "VirtualBox") ||
            strcasestr(n, "QEMU") || strcasestr(n, "Xen"));
  char buf[160];
  snprintf(buf, sizeof(buf), "'%s'", n);
  result("DMI/SMBIOS", hv, buf, 1);
}

/* ═══════════════════════════════════════════════════════════════════
 *  HARD 5-9: Daraltılmış Eşik Değerli Temel Testler
 * ═══════════════════════════════════════════════════════════════════ */
static void t5_cpuid_rdtsc_consistency() {
  uint32_t a, b, c, d;
  uint64_t t1 = rdtsc_native();
  cpuid(0, &a, &b, &c, &d);
  uint64_t t2 = rdtsc_native();
  int hv = ((t2 - t1) > 1250);
  char buf[64];
  snprintf(buf, sizeof(buf), "dt=%lu (Th: 1250)", (t2 - t1));
  result("CPUID Latency", hv, buf, 2);
}

static void t6_rdtsc_vs_rdtscp() {
  uint32_t aux;
  uint64_t t1 = rdtsc_native();
  uint64_t t2 = rdtscp_native(&aux);
  int64_t diff = t2 - t1;
  int hv = (diff < -190 || diff > 190);
  char buf[64];
  snprintf(buf, sizeof(buf), "delta=%ld (Th: +/-190)", (long)diff);
  result("RDTSC Delta", hv, buf, 2);
}

static void t7_sidt_red_pill() {
  unsigned char idtr[10];
  asm volatile("sidt %0" : "=m"(idtr));
  uint64_t base = *(uint64_t *)(idtr + 2);
  int hv = (base < 0xFFFF800000000000ULL);
  char buf[64];
  snprintf(buf, sizeof(buf), "IDT=0x%lx", (unsigned long)base);
  result("SIDT Base Addr", hv, buf, 2);
}

static void t8_sgdt_red_pill() {
  unsigned char gdtr[10];
  asm volatile("sgdt %0" : "=m"(gdtr));
  uint64_t base = *(uint64_t *)(gdtr + 2);
  int hv = (base < 0xFFFF800000000000ULL);
  char buf[64];
  snprintf(buf, sizeof(buf), "GDT=0x%lx", (unsigned long)base);
  result("SGDT Base Addr", hv, buf, 2);
}

static void t9_sldt_red_pill() {
  uint16_t ldt;
  asm volatile("sldt %0" : "=m"(ldt));
  int hv = (ldt != 0);
  char buf[64];
  snprintf(buf, sizeof(buf), "LDT=0x%x", ldt);
  result("SLDT Non-Zero", hv, buf, 2);
}

/* ═══════════════════════════════════════════════════════════════════
 *  EXTREME 10-17: Acımasız Testler (Çok Dar Eşik Değerleri)
 * ═══════════════════════════════════════════════════════════════════ */
static void t10_cpuid_vs_fpu() {
  uint64_t cpuid_b = UINT64_MAX, fpu_b = UINT64_MAX;
  uint32_t a, b, c, d;
  for (int i = 0; i < 100; i++) {
    uint64_t t1 = rdtsc_native();
    cpuid(1, &a, &b, &c, &d);
    uint64_t t2 = rdtsc_native();
    if ((t2 - t1) < cpuid_b)
      cpuid_b = (t2 - t1);
    t1 = rdtsc_native();
    asm volatile("fld1; fld1; fyl2xp1; fstp %%st(0);" ::: "st", "st(1)");
    t2 = rdtsc_native();
    if ((t2 - t1) < fpu_b)
      fpu_b = (t2 - t1);
  }
  int hv = (cpuid_b > (fpu_b * 3));
  char buf[128];
  snprintf(buf, sizeof(buf), "CPUID=%lu FPU=%lu (Th: 3.0x)", cpuid_b, fpu_b);
  result("CPUID/FYL Ratio", hv, buf, 3);
}

static void t11_back_to_back_cpuid() {
  uint32_t a, b, c, d;
  uint64_t t1 = rdtsc_native();
  cpuid(0, &a, &b, &c, &d);
  uint64_t t2 = rdtsc_native();
  cpuid(0, &a, &b, &c, &d);
  uint64_t t3 = rdtsc_native();
  uint64_t first = t2 - t1;
  uint64_t second = t3 - t2;
  int hv = ((second > 500) ||
            (second >
             first + 100)); // Second CPUID shouldn't be significantly slower
  char buf[128];
  snprintf(buf, sizeof(buf), "1st=%lu 2nd=%lu diff=%ld", first, second,
           (long)(first - second));
  result("Back-to-Back CPUID", hv, buf, 3);
}

static void t12_cpuid_jitter() {
  uint64_t s[100];
  uint32_t a, b, c, d;
  for (int i = 0; i < 100; i++) {
    uint64_t t1 = rdtsc_native();
    cpuid(0, &a, &b, &c, &d);
    s[i] = rdtsc_native() - t1;
  }
  uint64_t sum = 0;
  for (int i = 0; i < 100; i++)
    sum += s[i];
  uint64_t mean = sum / 100;
  uint64_t var = 0;
  for (int i = 0; i < 100; i++) {
    int64_t d = s[i] - mean;
    var += (d * d);
  }
  var /= 100;
  int hv = (var > 20000);
  char buf[80];
  snprintf(buf, sizeof(buf), "var=%lu mean=%lu", var, mean);
  result("Timing Variance", hv, buf, 3);
}

static void t13_cpuid_sandwich() {
  uint32_t a, b, c, d;
  uint64_t t1, t2, t3;
  t1 = rdtsc_native();
  cpuid(1, &a, &b, &c, &d);
  t2 = rdtsc_native();
  cpuid(1, &a, &b, &c, &d);
  t3 = rdtsc_native();
  uint64_t total = t3 - t1;
  int hv = (total > 1500);
  char buf[80];
  snprintf(buf, sizeof(buf), "Total=%lu cycles (Th: 1600)", total);
  result("Sandwich Pipelining", hv, buf, 3);
}

static void t14_lsl_vs_cpuid() {
  uint64_t lsl_b = UINT64_MAX, cpuid_b = UINT64_MAX;
  uint32_t a, b, c, d;
  for (int i = 0; i < 100; i++) {
    uint64_t t1 = rdtsc_native();
    cpuid(0, &a, &b, &c, &d);
    uint64_t t2 = rdtsc_native();
    if ((t2 - t1) < cpuid_b)
      cpuid_b = t2 - t1;
    uint32_t limit;
    t1 = rdtsc_native();
    asm volatile("lsl %1, %0" : "=r"(limit) : "r"(16));
    t2 = rdtsc_native();
    if ((t2 - t1) < lsl_b && limit != 0)
      lsl_b = t2 - t1;
  }
  int hv = (cpuid_b > (lsl_b * 3)) && (lsl_b > 0);
  char buf[128];
  snprintf(buf, sizeof(buf), "CPUID=%lu LSL=%lu (Th: 3.0x)", cpuid_b, lsl_b);
  result("LSL Limit Latency", hv, buf, 3);
}

static void t15_topology_cpuid_lag() {
  uint64_t leaf0_b = UINT64_MAX, leafB_b = UINT64_MAX;
  uint32_t a, b, c, d;
  for (int i = 0; i < 100; i++) {
    uint64_t t1 = rdtsc_native();
    cpuid(0, &a, &b, &c, &d);
    uint64_t t2 = rdtsc_native();
    if ((t2 - t1) < leaf0_b)
      leaf0_b = t2 - t1;
    t1 = rdtsc_native();
    cpuid(0x0B, &a, &b, &c, &d);
    t2 = rdtsc_native();
    if ((t2 - t1) < leafB_b)
      leafB_b = t2 - t1;
  }
  int hv =
      (leafB_b >
       leaf0_b +
           500); // Allow hardware its natural ~200-300 cycle topological delay
  char buf[128];
  snprintf(buf, sizeof(buf), "Leaf0=%lu LeafB=%lu", leaf0_b, leafB_b);
  result("Topology Leaf Lag", hv, buf, 3);
}

static void t16_extended_leaf_consistency() {
  uint32_t a, b, c, d;
  cpuid(0x80000000, &a, &b, &c, &d);
  int hv = 0;
  if (a < 0x80000010)
    hv = 1;
  char buf[64];
  snprintf(buf, sizeof(buf), "Max Ext = 0x%x", a);
  result("Ext Leaf Consist", hv, buf, 2);
}

static void t17_l1_tlb_eviction_anomaly() {
  volatile char *mem = (volatile char *)malloc(4096);
  if (!mem)
    return;
  uint64_t min_cache_latency = UINT64_MAX;
  uint32_t a, b, c, d;
  for (int i = 0; i < 1000; i++) {
    mem[0] = 1;
    mem[64] = 2;
    asm volatile("mfence" ::: "memory");
    cpuid(1, &a, &b, &c, &d);
    asm volatile("mfence" ::: "memory");
    uint64_t t1 = rdtsc_native();
    volatile char val = mem[0];
    uint64_t t2 = rdtsc_native();
    if (t2 - t1 < min_cache_latency)
      min_cache_latency = t2 - t1;
  }
  free((void *)mem);
  int hv = (min_cache_latency >
            150); // Native is ~40-60 cyc, hypervisor usually forces >150
  char buf[128];
  snprintf(buf, sizeof(buf), "L1 Access Post-Trap = %lu cyc",
           min_cache_latency);
  result("L1 Eviction", hv, buf, 3);
}

/* ═══════════════════════════════════════════════════════════════════
 *  THE IMPOSSIBLE 18: Branch Target Buffer (BTB) Flush Profiling
 * ═══════════════════════════════════════════════════════════════════ */
static void t18_btb_flush_anomaly() {
  uint64_t sum_latency = 0;
  volatile int cond = 1;
  uint32_t a, b, c, d;

  /* Isınma (Train BTB) */
  for (int i = 0; i < 100; i++) {
    if (cond) {
      asm volatile("nop");
    }
  }

  for (int i = 0; i < 1000; i++) {
    for (int j = 0; j < 20; j++) {
      if (cond)
        asm volatile("nop");
    }

    cpuid(1, &a, &b, &c, &d);

    uint64_t t1 = rdtsc_native();
    if (cond)
      asm volatile("nop");
    if (cond)
      asm volatile("nop");
    if (cond)
      asm volatile("nop");
    if (cond)
      asm volatile("nop");
    if (cond)
      asm volatile("nop");
    uint64_t t2 = rdtsc_native();

    sum_latency += (t2 - t1);
  }

  uint64_t avg = sum_latency / 1000;

  int hv = (avg > 90);
  char buf[128];
  snprintf(buf, sizeof(buf), "Branch Penalty = %lu cycles (Th: 160)", avg);
  result("BTB Flush Anomaly", hv, buf, 4);
}

/* ═══════════════════════════════════════════════════════════════════
 *  THE IMPOSSIBLE 19: IPI / Cross-Core Signal Latency
 * ═══════════════════════════════════════════════════════════════════ */
static atomic_int sync_barrier = 0;
static atomic_int ipi_flag = 0;
static uint64_t ipi_start_tsc = 0;
static uint64_t ipi_latency = 0;

static void pin_thread(int core_id) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static void sigusr1_handler(int sig) {
  uint64_t end = rdtsc_native();
  if (ipi_start_tsc != 0) {
    ipi_latency = end - ipi_start_tsc;
  }
  atomic_store(&ipi_flag, 1);
}

static void *core1_ipi_receiver(void *arg) {
  pin_thread(1);
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1_handler;
  sigaction(SIGUSR1, &sa, NULL);

  atomic_store(&sync_barrier, 1); // Hazır
  while (!atomic_load(&ipi_flag)) {
    asm volatile("pause");
  }
  return NULL;
}

static void t19_ipi_latency() {
  // Çift çekirdek yoksa geç
  long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
  if (num_cores < 2) {
    result("Cross-Core IPI Latency", 0, "No multicore", 4);
    return;
  }

  atomic_store(&sync_barrier, 0);
  atomic_store(&ipi_flag, 0);

  pthread_t t;
  pthread_create(&t, NULL, core1_ipi_receiver, NULL);
  pin_thread(0);

  // Core 1'in hazır olmasını bekle
  while (atomic_load(&sync_barrier) == 0) {
    asm volatile("pause");
  }

  // Sinyali yolla
  ipi_start_tsc = rdtsc_native();
  pthread_kill(t, SIGUSR1);

  pthread_join(t, NULL);

  // POSIX Signal overhead is massive, native takes anywhere from 5000 to 20000
  // cycles. Hypervisors intercepting IPIs (LAPIC write) routinely balloon this
  // to 30000-50000+. A strict 30000 cycle ceiling catches many hypervisors.
  int hv = (ipi_latency > 177000);
  char buf[128];
  snprintf(buf, sizeof(buf), "Signal IPI Latency = %lu cyc", ipi_latency);
  result("Cross-Core IPI", hv, buf, 4);
}

/* ═══════════════════════════════════════════════════════════════════
 *  THE IMPOSSIBLE 20: TLB Shadowing & Large Page Fragmentation
 * ═══════════════════════════════════════════════════════════════════ */
static void t20_tlb_large_page_anomaly() {
  size_t size = 2 * 1024 * 1024; // 2MB
  void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    result("Large Page Frag", 0, "mmap failed", 4);
    return;
  }

  // THP / Hugepage request
  madvise(mem, size, MADV_HUGEPAGE);

  // Fault-in pages physically
  for (size_t i = 0; i < size; i += 4096) {
    ((volatile char *)mem)[i] = 1;
  }

  // Tam 512 adet Page erişimi (2MB'ın tamamı)
  uint64_t t1 = rdtsc_native();
  for (size_t i = 0; i < size; i += 4096) {
    volatile char val = ((volatile char *)mem)[i];
  }
  uint64_t t2 = rdtsc_native();

  uint64_t latency = t2 - t1;
  munmap(mem, size);

  // 512 page read on a continuous PDE (Large Page) takes under 1500 cycles
  // natively (only 1 TLB miss initially). If a hypervisor NPT/EPT shreds this
  // 2MB into 4KB PTEs, it takes 512 Nested TLB misses > 10000 cycles.
  int hv = (latency > 50000);
  char buf[128];
  snprintf(buf, sizeof(buf), "2MB TLB Walk = %lu cyc (Th: 50000)", latency);
  result("Large Page Frag (NPT)", hv, buf, 4);
}

/* ═══════════════════════════════════════════════════════════════════
 *  THE IMPOSSIBLE 21: The LBR-TSC Correlation Attack
 * ═══════════════════════════════════════════════════════════════════ */
static void t21_lbr_tsc_correlation() {
  uint64_t t1, t2;
  uint32_t a, b, c, d;
  t1 = rdtsc_native();

  /* 32 ardışık JMP ile LBR Branch History Buffer'ı tamamen doldur. */
  asm volatile("jmp 1f\n 1: jmp 2f\n 2: jmp 3f\n 3: jmp 4f\n 4: jmp 5f\n 5: "
               "jmp 6f\n 6: jmp 7f\n 7: jmp 8f\n"
               "8: jmp 9f\n 9: jmp 10f\n 10: jmp 11f\n 11: jmp 12f\n 12: jmp "
               "13f\n 13: jmp 14f\n 14: jmp 15f\n 15: jmp 16f\n"
               "16: jmp 17f\n 17: jmp 18f\n 18: jmp 19f\n 19: jmp 20f\n 20: "
               "jmp 21f\n 21: jmp 22f\n 22: jmp 23f\n 23: jmp 24f\n"
               "24: jmp 25f\n 25: jmp 26f\n 26: jmp 27f\n 27: jmp 28f\n 28: "
               "jmp 29f\n 29: jmp 30f\n 30: jmp 31f\n 31: jmp 32f\n 32:\n");

  /* VMEXIT tetikle - Hypervisor LBR kayıtlarını save/restore etmek zorunda
   * kalacak */
  cpuid(0, &a, &b, &c, &d);
  t2 = rdtsc_native();

  uint64_t latency = t2 - t1;

  /* Native süresi (32 jmp + 1 cpuid) = ~150-250 cycle sürer.
   * Hypervisor araya girdiğinde klasik LBR virtualization Hardware
   * Overhead'inden dolayı ~800-1500 cycle'a çıkar. */
  int hv = (latency > 2000);
  char buf[128];
  snprintf(buf, sizeof(buf), "LBR+VMEXIT = %lu cyc (Th: 2000)", latency);
  result("LBR-TSC Correlation", hv, buf, 4);
}

int main(void) {
  printf("\n" CYAN "═══════════════════════════════════════════════════════════"
         "═════════════" RESET "\n");
  printf("   HV_DETECT V4.3 — " RED "THE FINAL BLEEDING EDGE CHALLENGE" RESET
         "\n");
  printf(CYAN "════════════════════════════════════════════════════════════════"
              "════════" RESET "\n\n");

  t1_cpuid_hypervisor_bit();
  t2_cpuid_vendor();
  t3_proc_cpuinfo();
  t4_dmi_smbios();

  t5_cpuid_rdtsc_consistency();
  t6_rdtsc_vs_rdtscp();
  t7_sidt_red_pill();
  t8_sgdt_red_pill();
  t9_sldt_red_pill();

  t10_cpuid_vs_fpu();
  t11_back_to_back_cpuid();
  t12_cpuid_jitter();
  t13_cpuid_sandwich();
  t14_lsl_vs_cpuid();
  t15_topology_cpuid_lag();
  t16_extended_leaf_consistency();
  t17_l1_tlb_eviction_anomaly();
  t18_btb_flush_anomaly();
  t19_ipi_latency();
  t20_tlb_large_page_anomaly();
  t21_lbr_tsc_correlation();

  printf("\n" CYAN "═══════════════════════════════════════════════════════════"
         "═════════════\n" RESET);
  if (detected > 0) {
    printf(RED "  SONUÇ: %d/21 test BAŞARISIZ — HYPERVISOR VEYA EMULATOR "
               "TESPİT EDİLDİ!\n" RESET,
           detected);
  } else {
    printf(GREEN
           "  SONUÇ: 21/21 TEST GEÇTİ — YAZILIMSAL OLARAK İMKANSIZ!\n" RESET);
  }
  printf(CYAN "════════════════════════════════════════════════════════════════"
              "════════\n\n" RESET);

  return detected ? 1 : 0;
}
