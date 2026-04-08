#include <linux/module.h>
#include "ring_minus_one.h"

int init_module(void) {
    printk("OFFSET save.cr2: 0x%lx\n", offsetof(struct vmcb, save) + offsetof(struct vmcb_save_area, cr2));
    printk("OFFSET exit_info_2: 0x%lx\n", offsetof(struct vmcb_control_area, exit_info_2));
    return -1;
}
void cleanup_module(void) {}
MODULE_LICENSE("GPL");
