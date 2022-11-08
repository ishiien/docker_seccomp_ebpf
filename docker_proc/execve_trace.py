import sys

from bcc import BPF
from bcc.utils import printb
#import process_trace


#if len(sys.argv) == 2:
#    target = sys.argv[1]
#else :
#    print("container id is not set")
#    exit(1)


bpf_text = """

    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>
    
    #define ARGSIZE 128
    
    struct key_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
        char argv[ARGSIZE];
    };
    
    BPF_PERF_OUTPUT(events);
    
    static inline bool filter(char *str){
        char needle[] = "TARGET";
        char target[sizeof(needle)];
        bpf_probe_read_kernel(&target,sizeof(needle),str);
        
        for (int i = 0; i < sizeof(needle); ++i){
            if (target[i] != needle[i])
                return false;
        }
        return true;
    }
    
    int syscall__execve(struct pt_regs *ctx,
        const char __user *filename,
        const char __user *const __user *__argv,
        const char __user *const __user *__envp)
    {
    
        struct key_t key = {0};
        key.pid = bpf_get_current_pid_tgid();
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        bpf_get_current_comm(&key.comm,sizeof(key.comm));
        bpf_probe_read_user(key.argv,sizeof(key.argv),(void *)filename);
        
        if(!filter(uns->name.nodename)){
            return 0;
        }
        
        events.perf_submit(ctx,&key,sizeof(struct key_t));
        
        return 0;   
    }

"""

def  get_print_event(b: BPF,container_name):
    def print_event(cpu,data,size):
        event = b["events"].event(data)
        printb(b"%6d %-16s %-16s" % (event.pid,event.comm,event.argv))
        #process_trace.proc_syscall_trace(container_name,event.pid)

    return print_event


def execve_syscall_trace(container_name):
    target = container_name
    b = BPF(text=bpf_text.replace("TARGET",target))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name="syscall__execve")

    b["events"].open_perf_buffer(get_print_event(b,container_name))

    print("execve syscal trace start")
    print("%-6s %-16s %-16s" % ("PID","COMM","ARG"))


    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            # You should decide the finish
            exit()
            break





