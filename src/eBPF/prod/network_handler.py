from helper.arp import ARP
from helper.route import ROUTE
from helper import helper

import time
import random
import re
import ipcalc
import math

LOCAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "12.168.0.0/16"]

class NETWORK_handler():

    output = None

    arp_table = {}
    interfaces = []
    iptables = {}



    def __init__(self) -> None:
        self.interfaces = helper.create_fake_interface_data_helper()
        self.arp_table = helper.create_fake_arp_data_helper(self.interfaces["ens18"])
        self.routes = helper.create_fake_route_data_helper(self.interfaces["ens18"])
        self.iptable = helper.create_sample_iptables()



    def cmd(self, cmd):
        output = None

        cmd_name = cmd.split(" ")[0]
        args = cmd.split(" ")[1:]

        match cmd_name:

            case "ping":
                output = self.ping(args)

            case "arp":
                output = self.arp(args)

            case "ip":
                output = self.ip(args)

            case "traceroute":
                output = self.traceroute(args)

            case "dig":
                output = self.dig(args)

        
            case "iptables":
                output = self.iptables(args)

        return output


    def ping(self, args):
        output = []

        if not args:
            output.append("ping: usage error: Destination address required")
            return output

        count = 4

        target_host = args[-1] if not args[-1].startswith("-") else None

        if not target_host:
            output.append("ping: usage error: Destination address required")
            return output

        for i, arg in enumerate(args):
            if arg == "-c" and i + 1 < len(args):
                try:
                    count = int(args[i + 1])
                except ValueError:
                    output.append("ping: invalid count for -c")
                    return output
        target_ip = helper.nslookup_helper(target_host)
        if not helper.has_ping_drop_rule(self.iptable):

            if not target_ip or target_ip == ["Keine IP gefunden"]:
                return [f"ping: cannot resolve {target_host}: Unknown host"]

            target_ip = next((ip for ip in target_ip if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip)), None)

            local = False
            if target_host not in self.arp_table:
                for net in LOCAL_NETS:
                    if target_ip in ipcalc.Network(net):
                        local = True

                interface = self.interfaces["ens18"]
                arp_ip = target_ip if local else interface.inet4_gtw[0]

                self.arp_table[target_ip] = ARP(address=arp_ip, hwaddress="16:38:fd:f6:c2:c3", iface=interface)

            output.append(f"PING {target_host} ({target_ip}) 56(84) bytes of data.")

            times = []

            for i in range(1, count + 1):
                time_val = random.randint(10, 50)
                time_dec = random.randint(1, 9)
                rtt = float(f"{time_val}.{time_dec}")
                times.append(rtt)
                output.append(f"64 bytes from {target_ip}: icmp_seq={i} ttl=56 time={rtt} ms")

            time_min = min(times)
            time_avg = sum(times) / len(times)
            time_max = max(times)
            time_mdev = math.sqrt(sum((x - time_avg) ** 2 for x in times) / len(times))

            output.append(f"--- {target_host} ping statistics ---")
            output.append(f"4 packets transmitted, 4 received, 0% packet loss, time {sum(times):.0f} ms")
            output.append(
                    f"rtt min/avg/max/mdev = "
                    f"{time_min:.1f}{random.randint(0, 9)}{random.randint(0, 9)}/"
                    f"{time_avg:.1f}{random.randint(0, 9)}{random.randint(0, 9)}/"
                    f"{time_max:.1f}{random.randint(0, 9)}{random.randint(0, 9)}/"
                    f"{time_mdev:.1f}{random.randint(0, 9)}{random.randint(0, 9)} ms"
                    )

            return output
        else:
            randtime = random.randint(30, 210)
            output.append(f"PING {target_host} ({target_ip}) 56(84) bytes of data.")
            output.append(f"--- {target_host} ping statistics ---")
            output.append(f"4 packets transmitted, 0 received, 100% packet loss, time {randtime} ms")
            return output


    def arp(self, args):
        output = None

        target_host, args_str = helper.get_main_arg_helper(args)

        d =  "d" in args_str

        if d:
            if not target_host:
                return "arp: need host name"

            if not target_host in self.arp_table:
                return f"{target_host}: No address associated with name"

            self.arp_table.pop(target_host)

        else:
            output = "Address\t\tHWtype\t\tHWaddress\t\tFlags Mask\tIface\n"
            for entry in self.arp_table:
                output += str(self.arp_table[entry]) + "\n"

        return output



    def ip(self, args):

        output = ""

        args_str = "".join(args)
        a = bool(re.search(r'\b(a|addr)\b', args_str))
        r = bool(re.search(r'\b(r|route)\b', args_str))

        add = bool(re.search(r'\badd\b', args_str))
        delete = bool(re.search(r'\bdel\b', args_str))
        #a = "a" in args_str or "addr" in args_str
        #r = "r" in args_str or "route" in args_str
        #add = "add" in args_str
        #delete = "del" in args_str

        if a:
            if add:
                self.interfaces[args[-1]].add_ip(args[-3])

            elif delete:
                self.interfaces[args[-1]].del_ip(args[-3])

            else:
                for n, entry in enumerate(self.interfaces):
                    output += f"{n+1}: {str(self.interfaces[entry])}\n"

        if r:
            if add:
                self.routes.append(ROUTE(inet_to=args[-3], interface=self.interfaces[args[-1]]))

            elif delete:
                for x, route in enumerate(self.routes):
                    if args[-1] in route.interface.names and route.inet_to in args[-3]:
                        self.routes.pop(x)
                        break
            else:
                for entry in self.routes:
                    output += str(entry) + "\n"

        return output.strip("\n")



    def traceroute(self, args):
        output = []

        target_host, _ = helper.get_main_arg_helper(args)
        target_ip = helper.nslookup_helper(target_host)

        if not target_ip or target_ip == ["Keine IP gefunden"]:
            return [f"traceroute: unknown host {target_host}"]

        target_ip = next((ip for ip in target_ip if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip)), None)

        output.append(f"traceroute to {target_host} ({target_ip}), 64 hops max")

        random_hops = random.randint(5,11)

        for i in range(1, random_hops):
            time_total = []
            for _ in range(3):
                time = str(random.randint(1*(i-1), 10*(i-1)))
                time_dec = str(random.randint(1,9))

                time_total.append(str(float(time + "." + time_dec)) + "ms")

            interface = self.interfaces["ens18"]

            if i == 1:
                ip = interface.inet4_gtw[0]
            elif i == random_hops-1:
                ip = target_ip
            else:
                ip = random.choice(helper.TRACEROUTES)

            output.append(f"{i}  {ip} {' '.join(time_total)}")

        return output

    def iptables(self, args):
        output = []
    
        if not args:
            output.append("iptables v1.8.7 (nf_tables): no command specified \nTry `iptables -h' or 'iptables --help' for more information.")
            return output
    
        if args[0] == "-L":
            output.append(self.iptable.list_rules())
            return output
    
        if args[0] == "-h" or args[0] == "--help":
            output.append("iptables v1.8.7\n\nUsage: iptables -[ACD] chain rule-specification [options]\n        iptables -I chain [rulenum] rule-specification [options]\n        iptables -R chain rulenum rule-specification [options]\n        iptables -D chain rulenum [options]\n        iptables -[LS] [chain [rulenum]] [options]\n        iptables -[FZ] [chain] [options]\n        iptables -[NX] chain\n        iptables -E old-chain-name new-chain-name\n        iptables -P chain target [options]\n        iptables -h (print this help information)\n\nCommands:\nEither long or short options are allowed.\n  --append  -A chain            Append to chain\n  --check   -C chain            Check for the existence of a rule\n  --delete  -D chain            Delete matching rule from chain\n  --delete  -D chain rulenum\n                                Delete rule rulenum (1 = first) from chain\n  --insert  -I chain [rulenum]\n                                Insert in chain as rulenum (default 1=first)\n  --replace -R chain rulenum\n                                Replace rule rulenum (1 = first) in chain\n  --list    -L [chain [rulenum]]\n                                List the rules in a chain or all chains\n  --list-rules -S [chain [rulenum]]\n                                Print the rules in a chain or all chains\n  --flush   -F [chain]          Delete all rules in  chain or all chains\n  --zero    -Z [chain [rulenum]]\n                                Zero counters in chain or all chains\n  --new     -N chain            Create a new user-defined chain\n  --delete-chain\n             -X [chain]         Delete a user-defined chain\n  --policy  -P chain target\n                                Change policy on chain to target\n  --rename-chain\n             -E old-chain new-chain\n                                Change chain name, (moving any references)\nOptions:\n    --ipv4      -4              Nothing (line is ignored by ip6tables-restore)\n    --ipv6      -6              Error (line is ignored by iptables-restore)\n[!] --proto     -p proto        protocol: by number or name, eg. `tcp'\n[!] --source    -s address[/mask][...]\n                                source specification\n[!] --destination -d address[/mask][...]\n                                destination specification\n[!] --in-interface -i input name[+]\n                                network interface name ([+] for wildcard)\n --jump -j target\n                                target for rule (may load target extension)\n  --goto      -g chain\n                               jump to chain with no return\n  --match       -m match\n                                extended match (may load extension)\n  --numeric     -n              numeric output of addresses and ports\n[!] --out-interface -o output name[+]\n                                network interface name ([+] for wildcard)\n  --table       -t table        table to manipulate (default: `filter')\n  --verbose     -v              verbose mode\n  --wait        -w [seconds]    maximum wait to acquire xtables lock before give up\n  --wait-interval -W [usecs]    wait time to try to acquire xtables lock\n                                default is 1 second\n  --line-numbers                print line numbers when listing\n  --exact       -x              expand numbers (display exact values)\n[!] --fragment  -f              match second or further fragments only\n  --modprobe=<command>          try to insert modules using this command\n  --set-counters PKTS BYTES     set the counter during insert/append\n[!] --version   -V              print package version.")
            return output
    
        if args[0] == "-A":  # Add rule
            if len(args) < 2:
                output.append('iptables v1.8.7 (nf_tables): option "-A" requires an argument' + "\nTry `iptables -h' or 'iptables --help' for more information.")
                return output
            chain = args[1]
            if chain not in self.iptable.chains:
                output.append("iptables: No chain/target/match by that name.")
                return output
        
            chain = args[1]
            rule_options = self._parse_rule_options(args[2:])
            self.iptable.add_rule(chain, **rule_options)
            return ""
    
        if args[0] == "-D":  # Delete rule
            if len(args) < 2:
                output.append('iptables v1.8.7 (nf_tables): option "-D" requires an argument ' + "\nTry `iptables -h' or 'iptables --help' for more information.")
                return output
            chain = args[1]
            rule_options = self._parse_rule_options(args[2:])
            if self.iptable.rule_exists(chain, **rule_options):
                self.iptable.remove_rule(chain, **rule_options)
                return ""
            else:
                output.append("iptables: Bad rule (does a matching rule exist in that chain?).")
                return output
    
        if args[0] == "-F":  # Flush chain
            if len(args) < 2:
                self.iptable.clear_all()
                return ""
            else:
                chain = args[1]
                self.iptable.clear_chain(chain)
                return ""
    
        output.append(f"iptables v1.8.7 (nf_tables): unknown option {args[0]}")
        return output
    
    def _parse_rule_options(self, options):
        rule_options = {
            "source": None,
            "destination": None,
            "protocol": None,
            "source_port": None,
            "destination_port": None,
            "action": "ACCEPT",
        }
        i = 0
        while i < len(options):
            if options[i] == "-s":
                rule_options["source"] = options[i + 1]
                i += 2
            elif options[i] == "-d":
                rule_options["destination"] = options[i + 1]
                i += 2
            elif options[i] == "-p":
                rule_options["protocol"] = options[i + 1]
                i += 2
            elif options[i] == "--sport":
                rule_options["source_port"] = options[i + 1]
                i += 2
            elif options[i] == "--dport":
                rule_options["destination_port"] = options[i + 1]
                i += 2
            elif options[i] == "-j":
                rule_options["action"] = options[i + 1]
                i += 2
            else:
                i += 1
        return rule_options


    
    def dig(self, args):
        output = []

        target_host = ""
        for arg in args:
            if arg not in ["A", "AAAA", "-v", "-x"]:
                target_host = arg
                break

        ipv4 = "A" in args and "AAAA" not in args
        ipv6 = "AAAA" in args
        v = "-v" in args
        x = "-x" in args

        if v:
            return "DiG 9.18.28-0ubuntu0.22.04.1-Ubuntu"

        if target_host:
            if x:
                output = helper.reverse_dig(target_host)
            else:
                target_ip = helper.nslookup_helper(target_host)

                if ipv4:
                    target_ip = [ip for ip in target_ip if "." in ip]
                elif ipv6:
                    target_ip = [ip for ip in target_ip if ":" in ip]
                else:
                    target_ip = [ip for ip in target_ip if "." in ip]

                record_type = "AAAA" if ipv6 else "A"
                status = "NOERROR"
                if not target_ip or target_ip == ["Keine IP-Adressen gefunden"]:
                    status = "SERVFAIL"

                output = helper.dig(target_host, target_ip, record_type, status)

            return output
