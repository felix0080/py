from bcc import BPF
prog = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};
BPF_PERF_OUTPUT(events);

// define the handler for do_sys_open.
// ctx is required, while other params depends on traced function.
int hello(struct pt_regs *ctx, int dfd, const char __user *filename, int flags){
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        bpf_probe_read(&data.fname, sizeof(data.fname), (void *)filename);
    }
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
b = BPF(text=prog)
b.attach_kprobe(event="do_sys_open", fn_name="hello")
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %-16s" % (time_s, event.comm, event.pid, event.fname))
b["events"].open_perf_buffer(print_event)
print("%-18s %-16s %-6s %-16s" % ("TIME(s)", "COMM", "PID", "FILE"))
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

