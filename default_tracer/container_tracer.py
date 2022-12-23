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
        char comm[TASK_COMM_LEN];
        char container_id[13];
        char fname[ARGSIZE];
        char option[ARGSIZE];
    };
    
    struct data_t {
        u32 pid;
        char comm[TASK_COMM_LEN];
        char container_id[13];
    };

    BPF_PERF_OUTPUT(execve);
    BPF_PERF_OUTPUT(ends);

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

    static int submit_arg(struct pt_regs *ctx, void *fn ,void *ptr, struct exec_t *exec)
    {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), ptr);
        bpf_probe_read_user(exec->option,sizeof(exec->option),argp);
        bpf_probe_read_user(exec->fname, sizeof(exec->fname), fn);
        execve.perf_submit(ctx, exec, sizeof(struct exec_t));
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


        bpf_probe_read_kernel(exec.container_id,sizeof(exec.container_id),uns->name.nodename);
        bpf_get_current_comm(&exec.comm,sizeof(exec.comm));

        for (int i = 1; i < MAXARG; i++) {
            if (submit_arg(ctx, (void *)filename,(void *)&__argv[i], &exec) == 0)
                goto out;
        }

out:        
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
        
        bpf_probe_read_kernel(data.container_id,sizeof(data.container_id),uns->name.nodename);
        
        ends.perf_submit(args,&data,sizeof(data));
        return 0;    
    }
"""

def execve_print_event(b: BPF):
    def print_event(cpu, data, size):
        event = b["execve"].event(data)
        argv[event.pid].append(event.fname)
        argv[event.pid].append(event.option)
        fname_text = str(b" ".join(argv[event.pid]))
        print("%d %-13s %-16s %-16s" % (event.pid,event.comm,event.container_id,fname_text))
    return print_event

def ends_print_event(b: BPF):
    def print_event(cpu,data,size):
        event = b["ends"].event(data)
        print("%d %-13s %-16s" % (event.pid,event.comm,event.container_id))
    return print_event

def perf_buffer(b):
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


def execve_syscall_tracer(container_list):
    target = container_list
    arg = "10000"
    b = BPF(text=bpf_text.replace("TARGET", target).replace("MAXARG", arg))
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
    b["execve"].open_perf_buffer(execve_print_event(b))
    b["ends"].open_perf_buffer(ends_print_event(b))
    print("execve syscal trace start")
    print("%-6s %-13s %-16s %-16s" % ("pid", "container_id", "comm", "filename"))
    perf_buffer(b)


argv = defaultdict(list)

fname_text = ""
command = ""
container_id = 0
proc_id = 0

container_list = ""
container_id_list = ["a79d0e172b84", "bc9d33944c72", "3b4b2c1206f3"]
exec_pid_list = []
for container in container_id_list:
    container_list = container + container_list

execve_syscall_tracer(container_list)