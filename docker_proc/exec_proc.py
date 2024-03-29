from docker_sdk import dockerfile, docker_sdk
import sys
from bcc import BPF
from bcc.utils import printb
import subprocess
import json
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
import queue

# This program traces execve system calls issued by containers in the test environment
# and verifies the execution commands and executable programs.

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
    
    struct data_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
    };
    
    BPF_PERF_OUTPUT(execve);
    BPF_PERF_OUTPUT(ends);
    
    static inline bool container_id_filter(char *container_id_str){
        char judge[] = "TARGET_CONTAINER_ID";
        char target_container_id[sizeof(judge)];
        bpf_probe_read_kernel(&target_container_id,sizeof(judge),container_id_str);
        for (int i = 0; i < sizeof(judge); ++i){
            if (target_container_id[i] != judge[i])
                return false;
        } 
        return true;
    }
    
    static int save_commands(struct pt_regs *ctx, void *ptr, struct exec_t *exec)
    {
        bpf_probe_read_user(exec->fname, sizeof(exec->fname), ptr);
        execve.perf_submit(ctx, exec, sizeof(struct exec_t));
        return 1;
    }
    
    static int save_argument(struct pt_regs *ctx, void *ptr, struct exec_t *exec)
    {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), ptr);
        if (argp) {
            return save_commands(ctx, (void *)(argp), exec);
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
        if(!container_id_filter(uns->name.nodename)){
            return 0;
        }
        exec.type = 0;
        bpf_get_current_comm(&exec.comm,sizeof(exec.comm));
        save_commands(ctx, (void *)filename, &exec);
        for (int i = 1; i < MAXARG; i++) {
            if (save_argument(ctx, (void *)&__argv[i], &exec) == 0)
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
        if(!container_id_filter(uns->name.nodename)){
            return 0;
        }
        execve.perf_submit(ctx, &exec, sizeof(exec));
        return 0;
    }

    TRACEPOINT_PROBE(sched,sched_process_exit){
        struct data_t data = {0};
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm,sizeof(data.comm));
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;

        if (!container_id_filter(uns->name.nodename)){
            return 0;
        }

        ends.perf_submit(args,&data,sizeof(data));
        return 0;    
    }
"""

fname_argv = defaultdict(list)
fname_exit = defaultdict(list)

start_command_pid_list = {}


def execve_print_event(b: BPF, command_list):
    def print_event(cpu, data, size):
        global start_command_pid_list
        global command_list
        global fname_exit
        global fname_argv
        event = b["execve"].event(data)
        if event.type == 0:
            fname_argv[event.pid].append(event.fname)
        elif event.type == 1:
            fname_text = str(b" ".join(fname_argv[event.pid]))
            fname_exit[event.pid].append(fname_text)
            for command in command_list:
                if command in fname_text:
                    start_command_pid_list[event.pid] = command

    return print_event


def ends_print_event(b: BPF):
    def print_event(cpu, data, size):
        global start_command_pid_list
        global command_list
        global fname_exit
        event = b["ends"].event(data)
        for proc_id in start_command_pid_list:
            if event.pid == proc_id:
                print("%6d %-16s %-16s" % (event.pid,event.comm,fname_exit[event.pid]))
                command_list.remove(start_command_pid_list[event.pid])

    return print_event


def perf_buffer(b,container_id,q):
    dockerfile.Start_Container_Test(container_id)
    global command_list
    while len(command_list) != 0:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            return 0

    dockerfile.Enter_Container_Test(container_id)
    q.put(1)
    return 0


def execve_syscall_tracer(q,container_id, container_command_list):
    global command_list
    for command in container_command_list:
        command_list.append(command)
    print(command_list)
    target_container_id = container_id
    arg = "10000"
    b = BPF(text=bpf_text.replace("TARGET_CONTAINER_ID", target_container_id).replace("MAXARG", arg))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
    b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="kretprobe_execve")
    b["execve"].open_perf_buffer(execve_print_event(b, command_list))
    b["ends"].open_perf_buffer(ends_print_event(b))
    print("execve syscall trace start")
    perf_buffer(b,container_id,q)

    print("execve syscall exit")
    return 0


command_list = []