# -*- coding: utf-8 -*-
import ctypes

from bcc import BPF
from bcc.utils import printb
import json
from ctypes import *

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
    u32 first;
    u32 end;
    unsigned int owner;
    char comm[TASK_COMM_LEN];
    unsigned int uid;
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
        struct uid_gid_extent *uid_forward = (struct uid_gid_extent *)user_ns->parent->projid_map.forward;
        struct uid_gid_extent *uid_end = (struct uid_gid_extent *)user_ns->parent->projid_map.reverse;
        
        bpf_get_current_comm(&data.comm,sizeof(data.comm));
        
        data.uid = credp->euid.val;        
        data.first = uid_forward->first;
        data.end = uid_end->lower_first;
        data.owner = user_ns->owner.val;
        events.perf_submit(ctx,&data,sizeof(struct data_t));
        
        return 0;
    }
    
    int kretprobe_execve(struct pt_regs *ctx)
    {
        struct data_t data = {0};
        struct task_struct *task;

        data.pid = bpf_get_current_pid_tgid();
        task = (struct task_struct *)bpf_get_current_task();

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        struct user_namespace *user_ns = (struct user_namespace *)task->ptracer_cred->user_ns;
        struct cred *credp = (struct cred *)task->cred;
        struct uid_gid_extent *uid_forward = (struct uid_gid_extent *)user_ns->parent->projid_map.forward;
        struct uid_gid_extent *uid_end = (struct uid_gid_extent *)user_ns->parent->projid_map.reverse;
        
        bpf_get_current_comm(&data.comm,sizeof(data.comm));
    
        data.uid = credp->euid.val;
        data.first = uid_forward->first;
        data.end = uid_end->lower_first;  
        data.owner = user_ns->owner.val;      
        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

"""
ct_mapping = {
        'uid_t' : ctypes.c_uint,
        'kuid_t' : ctypes.c_uint,
    }

def get_print_event(b:BPF):
    def print_event(cpu,data,size):
        event = b["events"].event(data)
        print("%d %d %d %d %d" % (event.pid,event.first,event.end,event.owner,event.uid))
    return print_event

def authoric_struct_trace():
    #target = container_id
    #b = BPF(text = bpf_text.replace("TARGET",target))
    b = BPF(text = bpf_text)
    b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name="syscall__execve")
    b.attach_kretprobe(event=b.get_syscall_fnname("execve"),fn_name="kretprobe_execve")

    b["events"].open_perf_buffer(get_print_event(b))

    print("print authoric information")

    while 1:
        try:
            b.perf_buffer_poll()
        except:
            exit()

authoric_struct_trace()

#static inline bool filter(char *str){
#   char judge[] = "TARGET";
#   char target[sizeof(judge)];
#   bpf_probe_read_kernel(&target,sizeof(judge),str);

#   for (int i = 0; i < sizeof(judge); ++i){
#       if (target[i] != judge[i])
#           return false;
#   }
#   return true;
#}
