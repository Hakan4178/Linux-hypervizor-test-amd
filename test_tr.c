#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t low = 0x1234FFFF; // base_low = 0x1234
    uint32_t high = 0x90ABCDEF; // base_mid = 0xEF, base_high = 0x90
    
    // Correct logic
    uint64_t base_correct = ((low >> 16) & 0xFFFF) | ((high & 0xFF) << 16) | (high & 0xFF000000);
    
    // My previous logic
    uint64_t base_wrong = ((low >> 16) & 0xFFFFFF) | ((high & 0xFF000000) >> 0);
    
    printf("Correct: %llx\n", base_correct);
    printf("Wrong  : %llx\n", base_wrong);
    return 0;
}
