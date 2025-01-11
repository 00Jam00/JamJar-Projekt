from helper.file import File
from helper.dir import Dir
from helper.arp import ARP
from helper.route import ROUTE
from helper.interface import INTERFACE
from helper.process import Process
from helper.iptable import Iptables

import random
import time
import socket

TRACEROUTES = ["62.155.245.90", "217.5.70.26", "80.156.160.223", "80.231.65.10", "195.219.148.122", "162.158.84.111", "172.69.148.3"]


def path_to_list_helper(src_dir):
        return src_dir.strip("/").split("/") if src_dir != "/" and src_dir != "" else []



def get_main_arg_helper(args):
    target = ""
    for arg in args:
        if not arg.startswith("-"):
            target = arg
            args.remove(arg) # Call by reference hat auch Vorteile :D
            break
    return target, "".join(args)

def add_file_helper(root, path, data):
    if type(path) != list:
        path_list = path_to_list_helper(path)
    else:
         path_list = path

    parent = root

    for layer in path_list:
        if layer not in parent.content:
            raise KeyError(f"Path '{layer}' does not exist")
        parent = parent.content[layer]

    data.parent = parent
    parent.content[data.name] = data


def target_dir_is_path_helper(target_dir, src_dir_list=[]):
    if type(src_dir_list) != list:
        src_dir_list = path_to_list_helper(src_dir_list)

    if target_dir.startswith("/"):
        src_dir_list_tmp = path_to_list_helper(target_dir)
        src_dir_list = src_dir_list_tmp[:-1]
        target_dir = src_dir_list_tmp[-1]
    else:
        split = target_dir.split("/")
        src_dir_list = src_dir_list + split[:-1]
        target_dir = split[-1]

    return target_dir, src_dir_list


def nslookup_helper(domain):
    ip = []

    if domain[0].isalpha():
        try:
            ip_info = socket.getaddrinfo(domain, None)
            ip = list({info[4][0] for info in ip_info})
        except:
            ip = ["Keine IP gefunden"]
    else:
        ip.append(domain)

    return ip


def create_fake_dir_data_helper(username):
    root_start = ["bin", "dev", "etc", "usr", "home", "lib", "sbin", "tmp", "var"]

    home_user = [
        ["file", ".bash_history", "", "-rw-------", "Jul", "13", "12:31"],
        ["file", ".bash_logout", "", "-rw-r--r--", "Jul", "13", "12:31"],
        ["dir", ".cache", "", "drwx------", "May", "20", "21:13"],
        ["file", ".bashrc", "", "-rw-r--r--", "May", "20", "21:13"],
        ["dir", ".local", "", "drwxrwxr-x", "Jul", "1", "00:25"],
        ["file", ".profile", "", "-rw-r--r--", "Jul", "7", "14:10"],
        ["dir", ".ssh", "", "drwx------", "Jun", "13", "19:14"],
        ["file", "test_file", "txt", "-rw-r--r--", "Jun", "15", "11:12"],
        ["file", ".test_file_hidden", "txt", "-rw-r--r--", "Jun", "15", "11:13"]
    ]

    root = Dir("root", perm="drwxrwxrwx")
    root.parent = root

    for dir in root_start:
        add_file_helper(root, "/", Dir(dir, perm="drwxr-xr-x", created_month="Jul", created_day=11, created_time="12:29"))

    etc_dir = navigate_to_path(root, ["etc"])
    for file in etc_files:
        add_file_helper(root, "/etc", file)

    home_dir = "/home"

    add_file_helper(root, home_dir, Dir(username, perm="drwxr-x---"))

    for file in home_user:
        if file[0] == "dir":
            add_file_helper(root, os.path.join(home_dir, username), Dir(name=file[1], perm=file[3], created_month=file[4], created_day=file[5], created_time=file[6], owner=username, group=username))
        else:
            add_file_helper(root, os.path.join(home_dir, username), File(file[1], file_type="file" if not file[2] else file[2], perm=file[3], created_month=file[4], created_day=file[5], created_time=file[6], owner=username, group=username))

    # TODO more fake dirs

    return root

def create_fake_arp_data_helper(int1):
     return {"_gateway": ARP(address="_gateway", hwaddress="af:33:4f:f6:2c:dd", iface=int1)}



def create_fake_interface_data_helper():
     return {
            "lo": INTERFACE(),
            "ens18": INTERFACE(["ens18", "enp0s18"], "ether", 1500, "BROADCAST,MULTICAST", mac="42:f6:3a:54:ad", mac_brd="ff:ff:ff:ff:ff:ff", state=2, inet4=["192.168.0.12/24"], inet6="fe80::ef52:de12:d4ee:139a/64")
            }



def create_fake_route_data_helper(interface):
     return [ROUTE(inet_from="default", inet_to=interface.inet4_gtw[0], interface=interface)]



def create_fake_processes():
    processes = [
                Process(pid=1 , tty="?"   , time="00:00:09"   , cmd="systemd"                 , uid="root"    , ppid="0"  , c="2503"  , stime="12:30" , stat="Ss" , sid="1"   , cpu="0.2" , mem="0.0" , rss="11888"   , vsz="170260", ucmd="/sbin/init splash"          ),
                Process(2     , "?"       , "00:00:00"        , "kthreadd"                    , "root"        , "0"       , "0"       , "12:30"       , "S"       , "0"       , "0.0"     , "0.0"     , "0"           , "0", "[kthreadd]"                      ),
                Process(3     , "?"       , "00:00:00"        , "rcu_gp"                      , "root"        , "0"       , "0"       , "12:30"       , "I<"      , "0"       , "0.0"     , "0.0"     , "0"           , "0", "[rcu_gp]"),
                Process(4     , "?"       , "00:00:00"        , "rcu_par_gp"                  , "root"        , "0"       , "0"       , "12:30"       , "I<"      , "0"       , "0.0"     , "0.0"     , "0"           , "0", "[rcu_par_gp]"                    ),
                Process(5     , "?"       , "00:00:00"        , "slub_flushwq"                , "root"        , "0"       , "0"       , "12:30"       , "I<"      , "0"       , "0.0"     , "0.0"     , "0"           , "0", "[slub_flushwq]"                  ),
                Process(6     , "?"       , "00:00:00"        , "netns"                       , "root"        , "0"       , "0"       , "12:30"       , "I<"      , "0"       , "0.0"     , "0.0"     , "0"           , "0", "[netns]"                         ),
                Process(8     , "?"       , "00:00:00"        , "kworker/0:0H-events_highpri" , "root"        , "0"       , "0"       , "12:30"       , "I<"      , "0"       , "0.0"     , "0.0"     , "0"           , "0", "[kworker/0:0H-events_highpri]"   ),
                Process(10    , "?"       , "00:00:00"        , "mm_percpu_wq"                , "root"        , "0"       , "0"       , "12:30"       , "I<"      , "0"       , "0.0"     , "0.0"     , "0"           , "0", "[mm_percpu_wq]"                  ),                
                Process(1673  , "tty2"    , "00:00:00"        , "gdm-x-session"               , "user1"       , "0"       , "2503"    , "12:31"       , "S"       , "0"       , "0.0"     , "0.0"     , "0"           , "0", "/usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu"                  ),
                Process(1675  , "tty2"    , "00:00:00"        , "Xorg"                        , "user1"       , "0"       , "0"       , "12:32"       , "S"       , "0"       , "0.8"     , "0.0"     , "0"           , "0", "/usr/lib/xorg/Xorg vt2 -displayfd 3 -auth /run/user/1000/gdm/Xauthority -back"                  ),
                Process(1682  , "tty2"    , "00:00:00"        , "gnome-keyring-d"             , "user1"       , "0"       , "0"       , "12:32"       , "S"       , "0"       , "0.0"     , "0.0"     , "0"           , "0", "/usr/libexec/gnome-session-binary --systemd -systemd -session=ubuntu"                  ),
                Process(2587  , "pts/0"   , "00:00:00"        , "bash"                        , "user1"       , "0"       , "0"       , "12:32"       , "S"       , "0"       , "0.0"     , "0.0"     , "0"           , "0", "bash"                  )
                ]
    
    return processes

def dig(target_host, target_ip, record_type, status):
    output = f"""
; <<>> DiG 9.18.28-0ubuntu0.22.04.1-Ubuntu <<>> {target_host}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: {status}, id: {random.randint(10000,60000)}
;; flags: qr rd ra; QUERY: 1, ANSWER: {len(target_ip)}, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;{target_host}.                  IN      {record_type}

"""

    if status != "SERVFAIL":
        output += ";; ANSWER SECTION:\n"
        ttl = random.randint(60, 350)
        for ip in target_ip:
            output += f"{target_host}.              {ttl}   IN      {record_type}       {ip}\n"

    output += f"""
;; Query time: {random.randint(0,60)} msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: {time.strftime("%a %b %d %H:%M:%S %Z %Y")}
;; MSG SIZE  rcvd: {12 + (len(target_host) + 2) + 4 + (len(target_host) + 2) + (10 * len(target_ip))}
"""
    return output

def reverse_dig(target_host):
    output = []
    reversed_ip = ".".join(target_host.split(".")[::-1]) + ".in-addr.arpa"

    if all(part.isdigit() and 0 <= int(part) <= 255 for part in target_host.split(".")):
        try:
            ptr_record = socket.gethostbyaddr(target_host)[0]
            status = "NOERROR"
            answer = f"{reversed_ip}. 3600 IN   PTR     {ptr_record}."
            answer_count, authority_count = 1, 0
        except socket.herror:
            status = "NXDOMAIN"
            answer = ""
            authority = "in-addr.arpa.          3600    IN      SOA     b.in-addr-servers.arpa. nstld.iana.org. 2024092939 1800 900 604800 3600"
            answer_count, authority_count = 0, 1
    else:
        status = "NXDOMAIN"
        answer = ""
        authority = "in-addr.arpa.              3600    IN      SOA     b.in-addr-servers.arpa. nstld.iana.org. 2024092939 1800 900 604800 3600"
        answer_count, authority_count = 0, 1

    output = f"""
; <<>> DiG 9.18.28-0ubuntu0.22.04.1-Ubuntu <<>> -x {target_host}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: {status}, id: {random.randint(10000,60000)}
;; flags: qr rd ra; QUERY: 1, ANSWER: {answer_count}, AUTHORITY: {authority_count}, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;{reversed_ip}.                  IN      PTR
"""

    if answer:
        output += f"""
;; ANSWER SECTION:
{answer}
"""
    elif authority:
        output += f"""
;; AUTHORITY SECTION:
{authority}
"""

    output += f"""
;; Query time: {random.randint(0,60)} msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: {time.strftime("%a %b %d %H:%M:%S %Z %Y")}
;; MSG SIZE  rcvd: {len(output)}
"""
    return output


def create_sample_iptables():
    iptables = Iptables()

    iptables.add_rule(
        chain="INPUT",
        source="192.168.1.1",
        protocol="tcp",
        destination_port=22,
        action="ACCEPT"
    )
    iptables.add_rule(
        chain="INPUT",
        source="10.0.0.0/8",
        protocol="udp",
        source_port=53,
        action="DROP"
    )
    iptables.add_rule(
        chain="FORWARD",
        source="172.16.0.0/16",
        destination="192.168.0.0/16",
        protocol="tcp",
        destination_port=80,
        action="ACCEPT"
    )


    return iptables

def has_ping_drop_rule(iptable):
    for chain in ["INPUT", "OUTPUT"]:
        for rule in iptable.chains[chain]:
            if (rule["protocol"] == "icmp" and
                rule["action"] == "DROP"):
                return True
    return False

