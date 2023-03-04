from bcc import BPF
from time import sleep
import time
import subprocess
import sys
import json
from docker_sdk import dockerfile,docker_sdk
from docker_proc import exec_proc
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>

    struct key_t {
        u32 pid;
        u64 syscall_number;
    };

    struct value_t{
        u64 syscall_count;
    };

    BPF_HASH(events,struct key_t,struct value_t);

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
        struct value_t value = {0},*val_;
        key.pid = bpf_get_current_pid_tgid();
        key.syscall_number = args->id;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        if(!filter(uns->name.nodename)){
            return 0;
        }

        val_ = events.lookup_or_try_init(&key,&value);
        if(val_){
            struct value_t val = *val_;
            val.syscall_count++;
            events.update(&key,&val);
        }
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


def make_json(container_name):
    syscall_list.append("pread64")
    syscall_list.append("mkdir")
    syscall_list.append("chown")
    syscall_list.append("listen")
    syscall_list.append("pwrite64")
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

    seccomp_file_name = container_name + "." + "json"
    with open(seccomp_file_name,"w") as file:
        json.dump(write_seccomp,file,indent=4)
    print("syscall count")
    print(len(syscall_list))
    file.close()
    return 0

def perf_buffer(b,container_id,container_name):
    while not docker_sdk.Container_Running_Inform(container_id):
        try:
            b.perf_buffer_poll()
        except Exception:
            exit()
    dockerfile.Enter_Container_Test(container_id)
    for k, _ in b["events"].items():
        syscall_judged = out_name(k.syscall_number)
        if syscall_judged not in syscall_list:
            syscall_list.append(syscall_judged)
    make_json(container_name)
    return 0

def map_tracer(container_id,container_name):
    target = container_id
    b = BPF(text=bpf_text.replace("TARGET", target))
    print("runtime syscall trace now")
    with ThreadPoolExecutor(max_workers=2) as execer:
        execer.submit(dockerfile.Start_Container_Test(container_id))
        execer.submit(perf_buffer(b,container_id,container_name))

    return 0


