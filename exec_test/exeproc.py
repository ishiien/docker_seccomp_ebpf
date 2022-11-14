from bcc import BPF
from time import sleep
import sys
import subprocess
import json

bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>
    
    #define ARGSIZE 128

    struct data_t {
        u32 pid;
        u32 syscall_number;
    };
    
    struct key_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
        char argv[ARGSIZE];
    }

    # map makeing
    BPF_PERF_OUTPUT(events);

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
    

    TRACEPOINT_PROBE(raw_syscalls,sys_enter){
        struct data_t data = {0};
        data.pid = bpf_get_current_pid_tgid();
        data.syscall_number = args->id;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        if(!filter(uns->name.nodename)){
            return 0;
        }

        events.perf_submit(args, &data,sizeof(data));

        return 0;
    }

"""

syscall_list = []


def out_name(number):
    try:
        s = subprocess.run(['ausyscall', str(number)], stdout=subprocess.PIPE).stdout
        return s.decode('UTF-8').rstrip()
    except:
        return str(number)


def call_event(b: BPF, proc_id):
    def get_event(cpu, data, size):
        event = b["events"].event(data)
        if proc_id == event.pid:
            syscall_judged = out_name(event.syscall_number)
            if syscall_judged not in syscall_list:
                syscall_list.append(syscall_judged)

    return get_event


def make_json():
    write_seccomp = \
        {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names":
                        syscall_list,
                    "action": "SCMP_ACT_ALLOW"
                }
            ]

        }

    with open("./process.json", "w") as proc_file:
        json.dump(write_seccomp, proc_file, indent=4)

    proc_file.close()
    return 0


def proc_syscall_trace(container_name, proc_id):
    target = container_name
    b = BPF(text=bpf_text.replace("TARGET", target))
    b["events"].open_perf_buffer(call_event(b, proc_id))

    print("docker process syscall trace now")

    while 1:
        try:
            b.perf_buffer_poll()
            return True
        except KeyboardInterrupt:
            make_json()
            return False

