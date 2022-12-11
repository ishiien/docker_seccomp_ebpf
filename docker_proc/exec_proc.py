from docker_sdk import dockerfile
import sys
from bcc import BPF
from bcc.utils import printb
import subprocess
import json
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>

    #define ARGSIZE 128

    struct exec_t {
        u32 pid;
        int type;
        char comm[TASK_COMM_LEN];
        char fname[ARGSIZE];
    };


    BPF_PERF_OUTPUT(execve);

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
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

        if(!filter(uns->name.nodename)){
            return 0;
        }
        exec.type = 0;
        bpf_get_current_comm(&exec.comm,sizeof(exec.comm));
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

        bpf_get_current_comm(&exec.comm, sizeof(exec.comm));
        exec.type = 1;
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

        if(!filter(uns->name.nodename)){
            return 0;
        }

        execve.perf_submit(ctx, &exec, sizeof(exec));

        return 0;
    }
"""
argv = defaultdict(list)

command_flag = True

def get_print_event(b: BPF, command_list):
    def print_event(cpu, data, size):
        event = b["execve"].event(data)
        if event.type == 0:
            argv[event.pid].append(event.fname)
        elif event.type == 1:
            fname_text = str(b" ".join(argv[event.pid]))
            if len(command_list) == 0:
                global command_flag
                command_flag = False
            for command in command_list:
                if command in fname_text:
                    print("%-6d %-16s %-16s" % (event.pid, event.comm, fname_text))
                    command_list.remove(command)
    return print_event

def perf_buffer(b):
    while command_flag:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            return 0
    return 0


def execve_syscall_tracer(container_id, command_list):
    target = container_id
    arg = "10000"
    b = BPF(text=bpf_text.replace("TARGET", target).replace("MAXARG", arg))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
    b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="kretprobe_execve")
    b["execve"].open_perf_buffer(get_print_event(b, command_list))
    print("execve syscal trace start")
    print("%-6s %-16s %-16s" % ("pid", "comm", "args"))

    with ProcessPoolExecutor(2) as execer:
        execer.submit(dockerfile.Start_Container_Test())
        execer.submit(perf_buffer(b))





