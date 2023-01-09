import sys
from bcc import BPF
from bcc.utils import printb
import subprocess
import json
from collections import defaultdict
from docker_sdk import docker_sdk
from concurrent.futures import ProcessPoolExecutor

bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>
    #include<linux/cred.h>
    #include<linux/uidgid.h>
    #include<linux/types.h>
    #include<linux/user_namespace.h>
    #define ARGSIZE 128
    
    struct exec_t {
        u32 pid;
        u32 ppid;
        unsigned int uid;
        char container_id[13];
        int type;
        char comm[TASK_COMM_LEN];
        char fname[ARGSIZE];
    };
    
    BPF_PERF_OUTPUT(execve);
    
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
    
    static int __submit_arg(struct pt_regs *ctx, void *ptr, struct exec_t *exec)
    {
        bpf_probe_read_user(exec->fname, sizeof(exec->fname), ptr);
        execve.perf_submit(ctx, exec, sizeof(struct exec_t));
        return 1;
    }
    static int submit_arg(struct pt_regs *ctx, void *ptr, struct exec_t *exec)
    {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), ptr);
        if (argp) {
            return __submit_arg(ctx, (void *)(argp), exec);
        }
        return 0;
    }
    
    int syscall__execve(struct pt_regs *ctx,
        const char __user *filename,
        const char __user *const __user *__argv,
        const char __user *const __user *__envp)
    {
        struct exec_t exec = {0};
        exec.pid = bpf_get_current_pid_tgid();
        exec.ppid = task->real_parent->tgid;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        struct cred *cred = (struct cred *)task->cred
        if(!filter(uns->name.nodename)){
            return 0;
        }
        
        bpf_probe_read_kernel(exec.container_id,sizeof(exec.container_id),uns->name.nodename);
        exec.type = 0;
        bpf_get_current_comm(&exec.comm,sizeof(exec.comm));
        exec.uid = cred->euid.val;
        __submit_arg(ctx, (void *)filename, &exec);
        for (int i = 1; i < MAXARG; i++) {
            if (submit_arg(ctx, (void *)&__argv[i], &exec) == 0)
                goto out;
        }
out:        
    return 0;  
    } 
    
    int kretprobe_execve(struct pt_regs *ctx)
    {
        struct exec_t exec = {0};
        struct task_struct *task;
        exec.pid = bpf_get_current_pid_tgid();
        task = (struct task_struct *)bpf_get_current_task();
        exec.ppid = task->real_parent->tgid;
        struct cred *credp = (struct cred *)task->cred;
        bpf_get_current_comm(&exec.comm, sizeof(exec.comm));
        exec.type = 1;
        
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        if(!filter(uns->name.nodename)){
            return 0;
        }
        bpf_probe_read_kernel(exec.container_id,sizeof(exec.container_id),uns->name.nodename);
        exec.uid = credp->euid.val;
        execve.perf_submit(ctx, &exec, sizeof(exec));
        return 0;
    }
"""

fname_argv = defaultdict(list)

def execve_print_event(b: BPF):
    def print_event(cpu, data, size):
        global fname_argv
        event = b["execve"].event(data)
        if event.type == 0:
            fname_argv[event.pid].append(event.fname)
        elif event.type == 1:
            fname_text = str(b" ".join(fname_argv[event.pid]))
            container_name = docker_sdk.ContainerId_to_ContainerName(event.container_id)
            print("%6d %6d %6d %-16s %-16s %-16s" % (event.pid,event.ppid,event.uid,container_name,event.comm,fname_text))

    return print_event


def perf_buffer(b):
    global command_list
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            return 0


def execve_syscall_tracer(container_id):
    target = container_id
    arg = "10000"
    b = BPF(text=bpf_text.replace("TARGET", target).replace("MAXARG", arg))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
    b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="kretprobe_execve")
    b["execve"].open_perf_buffer(execve_print_event(b))
    print("execve syscal trace start")
    print("%6s %6s %6s %-16s %-16s %-16s" % ("PID","PPD","UID","container_name","Comm","Argv"))
    perf_buffer(b)
    return 0

command_list = []