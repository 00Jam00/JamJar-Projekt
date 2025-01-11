from helper.process import Process
from helper import helper


class PROCESS_handler():

    output = None

    def __init__(self) -> None:
        self.output = helper.create_fake_processes()

    def cmd(self, cmd, tty, uid):
        output = None

        cmd_name = cmd.split(" ")[0]
        args = cmd.split(" ")[1:]

        match cmd_name:

            case "ps":
                output = self.ps(args, tty, uid)

            case "kill":
                output = self.kill(args)

            case "killall":
                output = self.killall(args)

        return output


    def ps(self, args, tty, uid):
        output = ""
        process_list = []
        processes = []

        target, args_str = helper.get_main_arg_helper(args)

        # UNIX-Options
        # none = all processes of current terminal and current user
        a = "a" in args_str #all processes in current terminal of all users + not session leaders
        e = "e" in args_str or "A" in args_str #all processes of system
        f = "f" in args_str # more details
        c = "C" in args_str # filter process name
        u = "u" in args_str # filter user

        #BSD-Options
        a2 = "a" in target # list all processes in current terminal of all users + STAT
        x = "x" in target # all processes of current user + STAT
        ax = "a" in target and "x" in target # all processes
        u2 = "u" in target # Display user-oriented format
        
        if (not args_str and not target) or args_str: #UNIX options
            
            if not args_str:
                for process in self.output: # none
                    if (process.tty == tty or process.tty == "pts/0") and process.uid == uid:
                        processes.append(process)

            if a:
                for process in self.output:
                    if (process.tty == tty or process.tty == "pts/0") and process.pid != process.sid: #TODO mit Malte klären
                        if process not in processes:
                            processes.append(process)
                
            if e: 
                for process in self.output:
                    if process not in processes:
                        processes.append(process)  

            if u:
                for process in self.output:
                    if process.uid == target:
                        processes.append(process)

            if c:
                for process in self.output:
                    if process.cmd == target:
                        processes.append(process)

            if f:
                if args_str == f:
                    for process in self.output:
                        if process.tty == tty and process.uid == uid:
                            processes.append(process)

                for process in processes:
                    process_list.append([process.uid, process.pid, process.c, process.ppid, process.stime, process.tty, process.time, process.cmd])

                process_list = [["UID", "PID", "PPID", "C", "STIME","TTY", "TIME", "CMD"]] + sorted(process_list, key=lambda x: x[1])

                for row in process_list:
                    output+= "{:<8} {:>4} {:>6} {:>2} {:>6} {:<6} {:>10} {:<8}\n".format(*row)

            else:
                for process in processes:
                    process_list.append([process.pid, process.tty, process.time, process.cmd])

                process_list = [["PID", "TTY", "TIME", "CMD"]] + sorted(process_list, key=lambda x: x[0])

                for row in process_list:
                    output+= "{:>6} {:<8} {:>8} {:<4}\n".format(*row)

        elif not args_str: # BSD-Options

            for process in self.output: # none
                if (process.tty == tty or process.tty == "pts/0") and process.uid == uid: #TODO mit Malte klären
                    processes.append(process)
            if a2:
                for process in self.output:
                    if (process.tty == tty or process.tty == "pts/0") and process not in processes: 
                        processes.append(process)
            if x:
                for process in self.output:
                    if process.uid == uid and process not in processes: 
                        processes.append(process)
            if ax:
                for process in self.output:
                    if process not in processes:
                        processes.append(process)   
            if u2:
                for process in processes:
                    process_list.append([process.uid, process.pid, process.cpu, process.mem, process.vsz, process.rss, process.tty, process.stat, process.time[-4:], process.ucmd])

                process_list = [["USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "TIME", "COMMAND"]] + sorted(process_list, key=lambda x: x[0])

                for row in process_list:
                    output+= "{:<6} {:>4} {:>4} {:>8} {:>4} {:>4} {:<8} {:<6} {:<4} {:<4}\n".format(*row)

            else:
                for process in processes:
                    process_list.append([process.pid, process.tty, process.stat, process.time[-4:], process.ucmd])

                process_list = [["PID", "TTY", "STAT", "TIME", "COMMAND"]] + sorted(process_list, key=lambda x: x[0])

                for row in process_list:
                    output+= "{:>6} {:<8} {:<4} {:<4} {:<4}\n".format(*row)

        #TODO add error messages etc.
        return output
    
    def kill(self, args):
        valid_arg = False

        target_process, _ = helper.get_main_arg_helper(args)
        
        for process in self.output:
            if process.pid == target_process:
                self.output.remove(process)
                valid_arg = True

        if not valid_arg:       
            return f"bash: kill: {target_process}: arguments must be process or job IDs"

    def killall(self, args):

        valid_arg = False

        target_process, _ = helper.get_main_arg_helper(args)
        
        for process in self.output:
            if process.cmd == target_process:
                self.output.remove(process)
                valid_arg = True

        if not valid_arg:       
            return f"{target_process}: no process found"