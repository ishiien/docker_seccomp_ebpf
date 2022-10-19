from bcc import BPF
from time import sleep
import subprocess
import sys
import json

if len(sys.argv) == 2:
    target = sys.argv[1]
else:
    print("Container id is not set")
    exit(1)

bpf_text = """
    #include<linux/sched.h>
    #include<linux/nsproxy.h>
    #include<linux/ns_common.h>
    #include<linux/utsname.h>    

    struct key_t {
        u32 pid;
        u64 syscall_number;
    };

    BPF_PERF_OUTPUT(events);

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
        key.pid = bpf_get_current_pid_tgid();
        key.syscall_number = args->id;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct uts_namespace *uns = (struct uts_namespace *)task->nsproxy->uts_ns;
        if(!filter(uns->name.nodename)){
            return 0;
        }

        events.perf_submit(args, &key, sizeof(key));

        return 0;
    }


"""


def out_name(number):
    try:
        s = subprocess.run(['ausyscall', str(number)], stdout=subprocess.PIPE).stdout
        return s.decode('UTF-8').rstrip()
    except:
        return str(number)


def is_odd(s):
    return s == target

syscall_list = []

def call_event(b: BPF):
    def get_event(cpu, data, size):
        event = b["events"].event(data)
        try:
            with open("/proc/%d/cgroup" % event.pid) as file:
                file_read = file.read().find("/docker/93089fe59db2a56c5c205d8f683fa37e6b64c0e83148a56ccd02d50584227f7a")
            if file_read != -1:
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
            "syscalls": [
                {
                    "names":
                        syscall_list,
                    "action": "SCMP_ACT_ALLOW"
                }
            ]

        }

    with open("./seccomp.json","w") as file:
        json.dump(write_seccomp,file,indent=4)

    file.close()
    return 0


b = BPF(text=bpf_text.replace("TARGET", target))

b["events"].open_perf_buffer(call_event(b))

print("exec syscall trace start")

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        make_json()
        exit()

