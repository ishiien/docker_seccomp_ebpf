from bcc import BPF
from time import sleep
import sys
import subprocess
import json


#if len(sys.argv) == 2:
#    target = sys.argv[1]
#else:
#    print("Specify the argument")
#    exit(1)


bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>
    
    struct data_t {
        u32 pid;
        u32 syscall_number;
    };
    
    BPF_PERF_OUTPUT(events);
    
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
    
    TRACEPOINT_PROBE(raw_syscalls,sys_enter){
        struct data_t data = {0};
        data.pid = bpf_get_current_pid_tgid();
        data.syscall_number = args->id;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        if(!filter(uns->name.nodename)){
            return 0;
        }
        
        events.perf_submit(args, &data,sizeof(data));
        
        return 0;
    }

"""

syscall_list = []

def out_name(number):
    try:
        s = subprocess.run(['ausyscall',str(number)],stdout = subprocess.PIPE).stdout
        return s.decode('UTF-8').rstrip()
    except:
        return str(number)


def call_event(b:BPF,proc_id):
    def get_event(cpu,data,size):
        event = b["events"].event(data)
        try:
            with open("/proc/%d/cgroup" % event.pid) as file:
                file_read = file.read().find("/docker/93089fe59db2a56c5c205d8f683fa37e6b64c0e83148a56ccd02d50584227f7a")
            if file_read != -1:
                if proc_id == event.pid:
                    syscall_judged = out_name(event.syscall_number)
                    if syscall_judged not in syscall_list:
                        syscall_list.append(syscall_judged)
                file.close()
        except:
            return 1

    return get_event

def make_json():
    write_seccomp = \
        {
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls":[
                {
                    "names":
                        syscall_list,
                    "action": "SCMP_ACT_ALLOW"
                }
            ]

        }

    with open("./process.json","w") as proc_file:
        json.dump(write_seccomp,proc_file,indent=4)

    proc_file.close()
    return 0

def proc_syscall_trace(container_name,proc_id):
    target = container_name
    b = BPF(text=bpf_text.replace("TARGET",target))
    b["events"].open_perf_buffer(call_event(b,proc_id))

    print("docker process syscall trace now")

    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            make_json()
            exit()

