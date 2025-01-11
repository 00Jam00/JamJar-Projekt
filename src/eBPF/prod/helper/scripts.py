import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import dir_handler
import PtraceSubroutines


def execute_command(handler, cmd, src_dir=""):
    comm = cmd.split(" ")[0]
    match comm:
        case ("ls"|"rm"|"touch"|"cat"|"echo"|"mkdir"|"rmdir"):

            dir = PtraceSubroutines.CMD.invoke_dir(cmd, src_dir)
            if isinstance(dir, list):
                dir = "\n".join(dir)
            return dir
        case ("ping"|"arp"|"ip"|"traceroute"|"dig"|"iptables"):
            network = PtraceSubroutines.CMD.invoke_network(cmd)
            if isinstance(network, list):
                network = "\n".join(network)

            return network
        case ("ps"|"kill"|"killall"):
            process = PtraceSubroutines.CMD.invoke_process(cmd,0,0)
            if isinstance(process, list):
                process = "\n".join(process)

            return process
        case ("w"|"whoami"|"id"):
            system = PtraceSubroutines.CMD.invoke_system(cmd,0,0)
            if isinstance(system, list):
                process = "\n".join(system)

            return system
        case _:
            print(f"[!] Subroutine for command {comm} is not implemented yet!")
            return ""

