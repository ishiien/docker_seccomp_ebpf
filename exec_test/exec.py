import sys
import proc
from bcc import BPF
from bcc.utils import printb




def get_print_event(b: BPF, container_name):
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        printb(b"%6d %-16s %-16s" % (event.pid, event.comm, event.argv))
        flag = proc.proc_syscall_trace(container_name,event.pid)
        if flag == False:
            exit(1)
            return 0

    return print_event


def execve_syscall_trace(container_name):
    target = container_name
    b = BPF(text=bpf_text.replace("TARGET", target))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

    b["events"].open_perf_buffer(get_print_event(b, container_name))

    print("execve syscal trace start")

    while 1:
        b.perf_buffer_poll()


container = "93089fe59db2"
execve_syscall_trace(container)

