#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HUGEPAGE_SIZE (2 * 1024 * 1024)

int main() {
  size_t size = HUGEPAGE_SIZE * 10; // 20 MB

  // Force explicit Huge TLB mapping to dodge THP failures
  void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

  if (ptr == MAP_FAILED) {
    perror("mmap MAP_HUGETLB");
    printf("Trying transparent hugepages fallback...\n");

    if (posix_memalign(&ptr, HUGEPAGE_SIZE, size) != 0) {
      perror("posix_memalign");
      return 1;
    }
    madvise(ptr, size, MADV_HUGEPAGE);
  }

  memset(ptr, 'H', size);

  printf("HugePage Test Running...\n");
  printf("PID: %d\n", getpid());
  printf("Allocated 20MB at %p\n", ptr);

  sleep(600);

  if (ptr != MAP_FAILED) {
    // cleanup depending on allocation type isn't strictly necessary for exit
  }
  return 0;
}
