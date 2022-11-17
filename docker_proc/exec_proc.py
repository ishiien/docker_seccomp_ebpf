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
        u32 syscall_number;
    };

    struct exec_t{
        u32 pid;
    };

    struct comm_t{
        char comm[TASK_COMM_LEN];    
    };


    BPF_PERF_OUTPUT(events);
    BPF_HASH(exec_table,struct exec_t,struct comm_t);

    static inline bool filter(char *str){
        char judge[] = "TARGET";
        char target[sizeof(judge)];
        bpf_probe_read_kernel(&target,sizeof(judge),str);

        for (int i = 0; i < sizeof(judge); ++i){
            if (target[i] != judge[i])
                return false;
        } 
        return true;
    }

    int syscall__execve(struct pt_regs *ctx,
        const char __user *filename,
        const char __user *const __user *__argv,
        const char __user *const __user *__envp)
    {
        struct exec_t exec = {0};
        struct comm_t comm = {0},*com_;
        exec.pid = bpf_get_current_pid_tgid();
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

        if(!filter(uns->name.nodename)){
            return 0;
        }

        com_ = exec_table.lookup_or_try_init(&exec,&comm);
        if(com_){
            struct comm_t com = *com_;
            exec_table.update(&exec,&com);
        }
        return 0;  
    } 

    TRACEPOINT_PROBE(raw_syscalls,sys_enter){
        struct data_t data = {0};
        struct exec_t exec  = {0};
        struct comm_t com = {0},*com_;
        exec.pid = bpf_get_current_pid_tgid();

        com_ = exec_table.lookup(&exec);
        if(com_){
            data.pid = bpf_get_current_pid_tgid(); 
            data.syscall_number = args->id;
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
            if(!filter(uns->name.nodename)){
                return 0;
            }
            events.perf_submit(args,&data,sizeof(data));
        }
        return 0;
    }

"""


def out_name(number):
    try:
        s = subprocess.run(['ausyscall', str(number)], stdout=subprocess.PIPE).stdout
        return s.decode('UTF-8').rstrip()
    except:
        return str(number)


syscall_list = []


def get_print_event(b: BPF):
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        print("%6d %-16s" % (event.pid, out_name(event.syscall_number)))
        # syscall_judged = out_name(event.syscall_number)
        # if syscall_judged not in syscall_list:
        # syscall_list.append(syscall_judged)

    return print_event


# def make_json():
#    write_seccomp = \
#        {
#            "defaultAction": "SCMP_ACT_ERRNO",
#            "syscalls": [
#                {
#                    "names":
#                        syscall_list,
#                    "action": "SCMP_ACT_ALLOW"
#                }
#            ]
#
#        }
#
#    with open("./seccomp.json","w") as file:
#        json.dump(write_seccomp,file,indent=4)
#
#    file.close()
#    return 0

def execve_syscall_trace(container_name):
    target = container_name
    b = BPF(text=bpf_text.replace("TARGET", target))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
    b["events"].open_perf_buffer(get_print_event(b))

    print("execve syscal trace start")

    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            # make_json()
            exit()


container = "93089fe59db2"
execve_syscall_trace(container)

