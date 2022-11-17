# -*- coding: utf-8 -*-
from bcc import BPF
from bcc.utils import printb
import json


# このファイルは，権限についての情報収集を行うためのものである．

bpf_text = """

#include<linux/sched.h>
#include<linux/nsproxy.h>
#include<linux/ns_common.h>
#include<linux/utsname.h>
#include<linux/cred.h>
#include<linux/uidgid.h>
#include<linux/types.h>
#include<linux/user_namespace.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);


int syscall__execve(struct pt_regs *ctx,
        const char __user *filename,
        const char __user *const __user *__argv,
        const char __user *const __user *__envp)
    {
    
        struct data_t data = {0};
        data.pid = bpf_get_current_pid_tgid();
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        struct user_namespace *user_ns = (struct user_namespace *)task->ptracer_cred->user_ns;
        struct cred *credp = (struct cred *)task->cred;
        
        bpf_get_current_comm(&data.comm,sizeof(data.comm));
        
        uid_t euid_v = credp->euid.val;
        u32 value = user_ns->uid_map.reverse->count;
        
        bpf_trace_printk("%ld %ld",euid_v,value);
        
        events.perf_submit(ctx,&data,sizeof(struct data_t));
        
        return 0;
    }

"""

#def get_print_event(b:BPF):
#    def print_event(cpu,data,size):
#        event = b["events"].event(data)
#        #make_json(event.uid)
#
#    return print_event

#def make_json(data):
#    write_seccomp = \
#        {
#            "defaultAction": "SCMP_ACT_ERRNO",
#            "syscalls": [
#                {
#                    "data":
#                        data,
#                    "action": "SCMP_ACT_ALLOW"
#                }
#            ]
#
#        }
#
#    with open("./authority.json","w") as file:
#        json.dump(write_seccomp,file,indent=4)
#
#    file.close()
#    return 0
#




def authoric_struct_trace():
    b = BPF(text = bpf_text)
    b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name="syscall__execve")

    #b["events"].open_perf_buffer(get_print_event(b))

    print("print authoric information")


    while 1:
        try:
            #b.perf_buffer_poll()
            b.trace_print()
        except:
            exit()

authoric_struct_trace()