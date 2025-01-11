import datetime

class File():
    perm = ""
    xxx = ""
    owner = ""
    group = ""
    size = ""
    created_month = ""
    created_day = ""
    created_time = ""
    name = ""
    parent = None
    filecontent = ""
    file_type = ""

    def __init__(self, name, perm="-rwxrwxrwx", xxx="1",
                 owner="root", group="root", size="4096",
                 created_month=datetime.datetime.now().strftime("%b"), created_day=datetime.datetime.now().strftime("%d"),
                 created_time=datetime.datetime.now().strftime("%H:%M"), file_type="", 
                 filecontent="#!/bin/bash\niptables -A OUTPUT -p icmp -j DROP\niptables -L\nping google.com\niptables -L\niptables -D OUTPUT -p icmp -j DROP\nping google.com\ntouch test2\necho 'ls -la\nping google.com\niptables -L' > test2\necho 'iptables -L' >> test2", parent=None) -> None:

        self.perm = perm
        self.xxx = xxx
        self.owner = owner
        self.group = group
        self.size = size
        self.created_month = created_month
        self.created_day = created_day
        self.created_time = created_time
        self.name = name
        self.file_type = file_type
        self.filecontent = filecontent
        self.parent = parent

