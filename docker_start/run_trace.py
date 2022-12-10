from bcc import BPF
from time import sleep
import time
import subprocess
import sys
import json
from dock import dockerfile,docker_sdk
from concurrent.futures import ProcessPoolExecutor
from docker_proc, import exec_proc


bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>    

    struct key_t {
        u32 pid;
        u64 syscall_number;
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

    TRACEPOINT_PROBE(raw_syscalls,sys_enter){
        struct key_t key = {0};
        key.pid = bpf_get_current_pid_tgid();
        key.syscall_number = args->id;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        if(!filter(uns->name.nodename)){
            return 0;
        }

        events.perf_submit(args, &key, sizeof(key));
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

def call_event(b: BPF):
    def get_event(cpu, data, size):
        event = b["events"].event(data)
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

    with open("./seccomp.json","w") as file:
        json.dump(write_seccomp,file,indent=4)

    file.close()
    return 0

def perf_buffer(b,container_id):
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            make_json()
            print(len(syscall_list))
            exit()
        if docker_sdk.Container_Running_Inform(container_id) == True:
            make_json()
            print(len(syscall_list))
            return 0

def run_tracer(container_id,command_list):
    target = container_id
    b = BPF(text=bpf_text.replace("TARGET", target))
    b["events"].open_perf_buffer(call_event(b))
    print("start container syscall trace now")
    with ProcessPoolExecutor(3) as execer:
        execer.submit(dockerfile.Start_Container_Test())
        execer.submit(perf_buffer(b,container_id))
        exec_proc.execve_syscall_tracer(target,command_list)


