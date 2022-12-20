from docker_sdk import dockerfile,docker_sdk
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

    struct data_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
    };

    BPF_PERF_OUTPUT(execve);
    BPF_PERF_OUTPUT(ends);

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
    
    TRACEPOINT_PROBE(sched,sched_process_exit){
        struct data_t data = {0};
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm,sizeof(data.comm));
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        
        if (!filter(uns->name.nodename)){
            return 0;
        }
        
        ends.perf_submit(args,&data,sizeof(data));
        return 0;    
    }
"""
argv = defaultdict(list)

start_command_pid_list = {}

def execve_print_event(b: BPF, command_list):
    def print_event(cpu, data, size):
        global start_command_pid_list
        global command_list
        event = b["execve"].event(data)
        if event.type == 0:
            argv[event.pid].append(event.fname)
        elif event.type == 1:
            fname_text = str(b" ".join(argv[event.pid]))
            for command in command_list:
                if command in fname_text:
                    start_command_pid_list[event.pid] = command
    return print_event

def ends_print_event(b: BPF):
    def print_event(cpu,data,size):
        global start_command_pid_list
        global command_list
        event = b["ends"].event(data)
        for proc_id in start_command_pid_list:
            if event.pid == proc_id:
                command_list.remove(start_command_pid_list[event.pid])

    return print_event

def perf_buffer(b,container_id):
    global command_list
    while len(command_list) != 0:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            return 0
    while 1:
        if docker_sdk.Container_Running_Inform(container_id) == False:
            continue
        elif docker_sdk.Container_Running_Inform(container_id) == True:
            dockerfile.Enter_Container_Test(container_id)
            break
    return 0


def execve_syscall_tracer(container_id, container_command_list):
    global command_list
    for command in container_command_list:
        command_list.append(command)
    target = container_id
    arg = "10000"
    b = BPF(text=bpf_text.replace("TARGET", target).replace("MAXARG", arg))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
    b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="kretprobe_execve")
    b["execve"].open_perf_buffer(execve_print_event(b, command_list))
    b["ends"].open_perf_buffer(ends_print_event(b))
    print("execve syscal trace start")

    with ProcessPoolExecutor(2) as execer:
        execer.submit(dockerfile.Start_Container_Test(container_id))
        execer.submit(perf_buffer(b,container_id))

command_list = []

