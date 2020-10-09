from __future__ import print_function
from bcc import BPF
from time import sleep
from sys import argv

interval = 99999999
# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct key_t {
   char faylady[15];
};
BPF_HASH(counts, struct key_t, u64, 256);
int do_count(struct pt_regs *ctx, struct vm_area_struct *vma) {
    struct key_t key = {};
    struct file *file = vma->vm_file;
    if (file == 0) {return 0;}
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name; 
    bpf_probe_read(&key.faylady,sizeof(key.faylady),d_name.name);
    counts.increment(key);
    return 0;
}
""")
b.attach_kprobe(event="handle_mm_fault", fn_name="do_count")

# header
print("Tracing... Ctrl-C to end.")

# output
try:
    sleep(interval)
except KeyboardInterrupt:
    pass

print("\n%-26s %8s" % ("Filename", "COUNT"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%-26s %8d" % (k.faylady, v.value))
