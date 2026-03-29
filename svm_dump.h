#ifndef SVM_DUMP_H
#define SVM_DUMP_H

#include <linux/types.h>

#define SVM_MAGIC "SVMD"
#define PAGE_SIZE_4K 4096

/* Header: Döküm dosyasının en başında yer alır (v3.0) */
struct svm_dump_header {
  char magic[4];  /* "SVMD" */
  u32 version;    /* Snapshot versiyonu (v2) */
  s32 pid;        /* Hedef Proses PID */
  u64 timestamp;  /* Döküm zamanı (Unix Epoch) */
  u64 cr3_phys;   /* CR3 fiziksel adres */
  u64 vma_count;  /* Toplam VMA sayısı */
  u64 map_count;  /* Toplam Map sayısı */
  u64 total_size; /* Döküm toplam boyut */
  u64 checksum;   /* XOR checksum */
  u32 flags;      /* Bit 0: Raw Data Present */
} __attribute__((packed));

#define SVM_FLAG_RAW_DATA (1 << 0)
#define SVM_FLAG_NPT_MODE (1 << 1)
#define SVM_FLAG_TRUNCATED (1 << 2)

/* VMA Entry */
struct svm_vma_entry {
  u64 vma_start;
  u64 vma_end;
  u64 flags;
  u64 pgoff;
} __attribute__((packed));

/* Page Map Entry */
struct svm_page_map_entry {
  u64 addr;
  u64 size;
  u64 entry;
  u64 pfn;
  u64 kind;
  u64 data_offset;
} __attribute__((packed));

#endif
