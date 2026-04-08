#include <linux/module.h>
#include "ring_minus_one.h"

int init_module(void) {
    printk("OFFSET exit_code: 0x%lx\n", offsetof(struct vmcb_control_area, exit_code));
    printk("OFFSET next_rip: 0x%lx\n", offsetof(struct vmcb_control_area, next_rip));
    printk("OFFSET save.rip: 0x%lx\n", offsetof(struct vmcb, save) + offsetof(struct vmcb_save_area, rip));
    printk("OFFSET save.rax: 0x%lx\n", offsetof(struct vmcb, save) + offsetof(struct vmcb_save_area, rax));
    printk("OFFSET event_inj: 0x%lx\n", offsetof(struct vmcb_control_area, event_inj));
    printk("OFFSET event_inj_err: 0x%lx\n", offsetof(struct vmcb_control_area, event_inj_err));
    return -1;
}
void cleanup_module(void) {}
MODULE_LICENSE("GPL");
