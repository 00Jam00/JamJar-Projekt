

class Process():
    pid = 0 #process id
    tty = "" #terminal associated with the process
    time = "" #elapsed CPU utilization time for the process
    cmd = "" #simple name of executable command
    uid = "" #user id
    ppid = "" #parent process id #TODO not yet connected to any parents/children
    c = "" #CPU utilization in percentage
    stime = ""#start time of the process
    stat = "" #PROCESS STATE CODES
    sid = "" # session ID, If PID == SID, then this process is a session leader
    cpu = "" # %CPU: cpu utilization of the process in "##.#" format.
    mem = "" #ratio of the process's resident set size to the physical memory on the machine
    rss = "" #resident set size
    vsz = ""
    ucmd = "" # long name of executable command


    def __init__(self, pid, tty, time, cmd, uid, ppid, c, stime, stat, sid, cpu, mem, rss, vsz, ucmd) -> None:
        self.pid = pid
        self.tty = tty
        self.time = time
        self.cmd = cmd
        self.uid = uid
        self.ppid = ppid
        self.c = c
        self.stime = stime
        self.stat = stat
        self.sid = sid
        self.cpu = cpu
        self.mem = mem
        self.rss = rss
        self.vsz = vsz
        self.ucmd = ucmd








