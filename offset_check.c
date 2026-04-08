#include <linux/module.h>
#include <asm/svm.h>
void dump(void) {
    long ev_inj = offsetof(struct vmcb_control_area, event_inj);
    long rip = offsetof(struct vmcb_save_area, rip);
    printk("EV_INJ: %ld, RIP: %ld\n", ev_inj, rip);
}
