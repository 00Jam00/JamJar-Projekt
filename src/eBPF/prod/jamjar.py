import datetime
from bcc import BPF
from ptrace.debugger import PtraceDebugger
import os
from collections import defaultdict
import PtraceSubroutines
import pwd
DEBUGGER = PtraceDebugger()

# ASCII art created with https://emojicombos.com/skull-ascii-art, https://emojicombos.com/mason-jar-ascii-art, https://patorjk.com/software/taag/#p=display&f=Graffiti&t=JamJar
def ascii_art():
    print(r"""
                                                        ⣴⠟⠛⠛⠛⠛⠛⠛⠛⠛⢛⣛⣻⣦
                                                        ⣿⣶⣶⡶⠀⠀⠛⠛⠋⠉⠉⠉⠉⣿
     ____                     ____                     ⠘⠿⢿⡿⠿⠿⠿⠿⠿⠿⠿⠿⢿⡿⠿⠃
    |    |____    _____      |    |____ _______        ⣠⣶⠿⠃⠀⠀⠀⠀⠀⠀⣶⡀⠘⠿⣶⣄
    |    \__  \  /     \     |    \__  \\_  __ \      ⣼⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢷⣄⠈⢻⣧
/\__|    |/ __ \|  Y Y  \/\__|    |/ __ \|  | \/      ⣿⡇⠀⠀⠀⢀⣠⣤⣤⣄⡀⠀⠀⠀⣿⠀⢸⣿
\________(____  /__|_|  /\________(____  /__|         ⣿⡇⠀⠀⣴⣿⣿⣿⣿⣿⣿⣦⠀⠀⣿⠀⢸⣿
              \/      \/               \/             ⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⣿⠀⢸⣿
        © Jamjar v1.0                                 ⣿⡇⠀⠀⣇⠈⠉⡿⢿⠉⠁⣸⠀⠀⣿⠀⢸⣿
        by Anna Eisner, Oliver Werner,                ⣿⡇⠀⠀⠙⠛⢻⣷⣾⡟⠛⠋⠀⠀⣿⠀⢸⣿
        Jani Gabriel & Malte Schulten                 ⣿⡇⠀   ⡏  ⢹⠀⠀⠀⠀⣿⠀⢸⣿
                                                      ⢻⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠀⣸⡟
                                                       ⠛⢷⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⡾⠛
    """)


# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128
#define UID_FILTER 1000

enum event_type {
    EVENT_ARG,
    EVENT_RET,
    EVENT_CD,
    EVENT_PIPE,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != UID_FILTER) {
        return 0;
    }

    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < 20; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != UID_FILTER) {
        return 0;
    }

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__pipe2(struct pt_regs *ctx, int __user *pipefd)
{
    struct data_t data = {};
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != UID_FILTER) {
        return 0;
    }

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_PIPE;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int syscall__chdir(struct pt_regs *ctx, const char __user *argv) {
    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != UID_FILTER) {
        return 0;
    }

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.timestamp = bpf_ktime_get_ns();
    data.type = EVENT_CD;
    bpf_probe_read_user(&data.argv, sizeof(data.argv), argv);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

pipe2_fnname = b.get_syscall_fnname("pipe2")
b.attach_kprobe(event=pipe2_fnname, fn_name="syscall__pipe2")

chdir_fnname = b.get_syscall_fnname("chdir")
b.attach_kprobe(event=chdir_fnname, fn_name="syscall__chdir")

class EventType:
    EVENT_ARG = 0
    EVENT_RET = 1
    EVENT_CD = 2
    EVENT_PIPE = 3

argv = defaultdict(list)
pipeline_pids = set()
pipeline_events = []
piped = False
end_count = 0
previous_paths = {}
event_timestamps = {}

def event_handler(comm,pid,full_cmd,cwd,tty,ppid,username,target_process, piped, end_count):
    if full_cmd.startswith("bash./"):
        PtraceSubroutines.dir_routine(pid,ppid,full_cmd,username,cwd,target_process, piped, end_count)
        DEBUGGER.quit()
    else:
        match comm:
            case ("ls"|"rm"|"touch"|"cat"|"echo"|"mkdir"|"rmdir"):
                PtraceSubroutines.dir_routine(pid,ppid,full_cmd,username,cwd,target_process, piped, end_count)
                DEBUGGER.quit()
            case ("ping"|"arp"|"ip"|"traceroute"|"dig"|"iptables"):
                PtraceSubroutines.network_routine(pid,ppid,full_cmd,target_process, piped, end_count)
                DEBUGGER.quit()
            case ("ps"|"kill"|"killall"):
                PtraceSubroutines.process_routine(pid,ppid,full_cmd,tty,username,target_process, piped, end_count)
                DEBUGGER.quit()
            case ("whoami"|"w"|"id"):
                PtraceSubroutines.system_routine(pid, ppid, full_cmd, username, target_process, piped, end_count)
                DEBUGGER.quit()
            case _:
                print(f"[!] Subroutine for command {comm} is not implemented yet!")
                DEBUGGER.quit()

# Cleanup Commands
def cleaup_cmd(command,args):
    cmd = command.replace(b"/usr/bin/%s " % (command),b"%s"%(command)).replace(b"/usr/sbin/%s " % (command),b"%s"%(command))
    arguments = args.replace(b" --color=auto",b"").replace(b"/usr/bin/%s" % (command),b"").replace(b"/usr/sbin/%s" % (command),b"")
    fullcmd = cmd+arguments
    return fullcmd.decode(),cmd.decode()


# Print Trace and Kill Events to console
def print_event(command, cwd, uid, piped):
    ct = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if not piped:
        print(f"[+][{ct}] Traced Command: [{command}]")
    else:
        print(f"[+][{ct}] Traced Piped Command: [{command}]")
    print(f"\t\\--> Executed in [{cwd}] by UID [{uid}]")

def attach_ptrace(pid):
    process = DEBUGGER.addProcess(pid, False)
    return process

# Process event
def proc_event(cpu, data, size):
    global piped, end_count
    event = b["events"].event(data)

    if event.type == EventType.EVENT_CD:
        to_path = event.argv.decode('utf-8', 'replace')

        pid = event.pid
        from_path = previous_paths.get(pid, "<unknown>")

        comm = "cd"

        result = PtraceSubroutines.cd_routine(pid, event.ppid, comm, from_path, to_path)

        if "Changed directory" in result:
            previous_paths[pid] = to_path

        log_message = (f"[ACTION: CHDIR] PID={event.pid}, PPID={event.ppid}, "
                       f"UID={event.uid}, COMM={comm}, "
                       f"FROM={from_path}, TO={to_path}, RETVAL={event.retval}, RESULT={result}")

        print(log_message)
    elif event.type == EventType.EVENT_PIPE:
        piped = True
    elif event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        target_process = attach_ptrace(event.pid)
        if target_process is None:
            print(f"[DEBUG] Skipping process {event.pid} as attach failed.")
            return

        argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
        cwd = os.readlink(f"/proc/{event.pid}/cwd")
        tty = os.readlink(f"/proc/{event.pid}/fd/0").replace("/dev/","")
        username = pwd.getpwuid(event.uid).pw_name
        # Getting cleaned command
        full_command,cmd_wo_args = cleaup_cmd(event.comm,argv_text)

        # Print event to console
        print_event(full_command,cwd,event.uid, piped)
        # Handle commands
        event_handler(cmd_wo_args,event.pid,full_command,cwd,tty,event.ppid,username,target_process, piped, end_count)

        try:
            del(argv[event.pid])
        except Exception:
            pass

'''def process_piped_events():
    global piped, end_count, piped_events, event_timestamps

    piped_events.sort(key=lambda e: e["pid"])

    for event_data in piped_events:
        event = event_data["event"]

        if event_data["pid"] in event_timestamps:
            timestamps = event_timestamps[event_data["pid"]]

        handle_event(event, event_data["argv"])

    piped = False
    end_count = 0
    piped_events = []

def proc_event(cpu, data, size):
    global piped, pipeline_pids, end_count, piped_events, event_timestamps

    event = b["events"].event(data)

    if event.type == EventType.EVENT_PIPE:
        piped = True
        pipeline_pids.add(event.pid)
    elif event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if piped:
            piped_events.append({
                "pid": event.pid,
                "ppid": event.ppid,
                "comm": event.comm,
                "argv": argv[event.pid],
                "event": event
            })
            end_count += 1

            if end_count >= 2:
                process_piped_events()
        else:
            handle_event(event, argv[event.pid])

def handle_event(event, argv):
    target_process = attach_ptrace(event.pid)
    if target_process is None:
        return
    try:
        cwd = os.readlink(f"/proc/{event.pid}/cwd")
    except FileNotFoundError:
        cwd = "[Process terminated]"
    except PermissionError:
        cwd = "[Permission denied]"

    try:
        tty = os.readlink(f"/proc/{event.pid}/fd/0").replace("/dev/", "")
    except FileNotFoundError:
        tty = "[Process terminated]"
    except PermissionError:
        tty = "[Permission denied]"

    username = pwd.getpwuid(event.uid).pw_name
    argv_text = b' '.join(argv).replace(b'\n', b'\\n')
    full_command, cmd_wo_args = cleaup_cmd(event.comm, argv_text)
    print_event(full_command, cwd, event.uid, piped)
    event_handler(cmd_wo_args, event.pid, full_command, cwd, tty, event.ppid, username, target_process, piped, end_count)

    try:
        del(argv[event.pid])
    except Exception:
        pass'''


def initialize_previous_paths():
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                previous_paths[int(pid)] = os.readlink(f"/proc/{pid}/cwd")
            except:
                previous_paths[int(pid)] = "<unknown>"

if __name__ == "__main__":
    ascii_art()

    initialize_previous_paths()

    # Loop with callback to print_event
    b["events"].open_perf_buffer(proc_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
