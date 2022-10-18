from bcc import BPF
from time import sleep
import subprocess
import sys

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


def get_print_event(b: BPF):
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        try:
            with open("/proc/%d/cgroup" % event.pid) as file:
                file_read = file.read().find("/docker/93089fe59db2a56c5c205d8f683fa37e6b64c0e83148a56ccd02d50584227f7a")
            if file_read != -1:
                print("%6d %-16s" % (event.pid, out_name(event.syscall_number)))
                file.close()
        except:
            return 1

    return print_event


b = BPF(text=bpf_text.replace("TARGET", target))

b["events"].open_perf_buffer(get_print_event(b))

print("exec syscall trace start")
print("%-6s %-16s" % ("PROC_ID", "SYSCALL_NAME"))

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
        break