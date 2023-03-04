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
import os
from multiprocessing import Process, Pipe

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
        char container_id[13];
    };

    BPF_HASH(events,struct key_t,struct value_t);

      static inline bool filter(char *str){
        int container_string_length = 13;
        char container_id_list[] = "TARGET";
        char target[container_string_length];
        int container_count = sizeof(container_id_list) / 12;
        int add_col = 0;
        int loop_count = 0;
        int success_count = 0;
        bpf_probe_read_kernel(&target,sizeof(target),str);
        while (loop_count < container_count){
            success_count = 0;
            for (int a = 0 ; a<12 ;++a){
                if (success_count == 11){
                    goto end;
                }else if (target[a] != container_id_list[add_col+a]){
                    add_col = add_col + 12;
                    if (add_col == sizeof(container_id_list) - 1){
                        return false;
                    }
                    break;
                }
                success_count = success_count + 1;         
            }
            loop_count = loop_count + 1;
        }  
end:       
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
            bpf_probe_read_kernel(val.container_id,sizeof(val.container_id),uns->name.nodename);
            events.update(&key,&val);
        }
        return 0;
    }


"""


container_sys_list = {}

def out_name(number):
    try:
        s = subprocess.run(['ausyscall', str(number)], stdout=subprocess.PIPE).stdout
        return s.decode('UTF-8').rstrip()
    except:
        return str(number)


def make_json(container_id_list,container_syscall_list):
    for container in container_id_list:
        container_name = docker_sdk.ContainerId_to_ContainerName(container)
        container_name = container_name.replace("/","")

        seccomp_file_name = container_name + "." + "json"
        print(len(container_syscall_list[container]))
        container_syscall_list[container].append("pread64")
        container_syscall_list[container].append("pwrite64")

        write_seccomp = \
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    {
                        "names":
                            container_syscall_list[container],
                        "action": "SCMP_ACT_ALLOW"
                    }
                ]

            }
        with open(seccomp_file_name,"w") as file:
            json.dump(write_seccomp,file,indent=4)

        file.close()
    return 0


def perf_buffer(b,container_id,q):
    global container_sys_list
    container_id_key_list = list(container_sys_list.keys())
    #while not docker_sdk.Container_Running_Inform(container_id):
    while 1:
        try:
            a = q.get()
            break
        except:
            try:
                b.perf_buffer_poll()
            except Exception:
                exit()

    for k, v in b["events"].items():
        syscall_judged = out_name(k.syscall_number)
        container_id_key = v.container_id.decode('UTF-8').rstrip()
        if container_id_key not in container_id_key_list:
            container_id_key_list.append(container_id_key)
            container_sys_list[container_id_key] = []
        if syscall_judged not in container_sys_list[container_id_key]:
            container_sys_list[container_id_key].append(syscall_judged)
    return 0

def run_tracer(q,container_id,container_list,container_syscall_list,conn):
    global container_sys_list
    container_sys_list = container_syscall_list
    target = container_list
    b = BPF(text=bpf_text.replace("TARGET", target))
    print("runtime syscall trace now")
    with ThreadPoolExecutor(max_workers=2) as execer:
        execer.submit(dockerfile.Start_Container_Test(container_id))
        execer.submit(perf_buffer(b,container_id,q))
    #perf_buffer(b,container_id,q)
    print("syscall tracer exit")
    #return container_sys_list
    conn.send(container_sys_list)


