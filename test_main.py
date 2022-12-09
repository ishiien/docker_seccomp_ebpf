import sys
from bcc import BPF
from bcc.utils import printb
import subprocess
import json

bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>

    struct data_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(sched,sched_process_exit){
        struct data_t data = {0};
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm,sizeof(data.comm));
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

        events.perf_submit(args,&data,sizeof(data));
        return 0;
    }

"""


def get_print_event(b: BPF):
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        print("%6d %-16s" % (event.pid, event.comm))

    return print_event


def execve_syscall_trace():
    b = BPF(text=bpf_text)
    b["events"].open_perf_buffer(get_print_event(b))

    print("process exit trace start!!")

    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

execve_syscall_trace()

