import ipcalc

STATES = {0: "UNKNOWN", 1: "DOWN", 2: "UP"}

class INTERFACE():
    names = [""]
    link = ""
    mtu = 0
    type_str = ""
    mac = ""
    mac_brd = ""
    state = 0
    inet4 = []
    inet4_brd = []
    inet4_gtw = []
    inet6 = ""



    def __str__(self):
        output = f"{self.names[0]}: <{self.type_str},UP,LOWER_UP mtu {self.mtu} qdisc noqueue state {STATES[self.state]} group default qlen 1000\n"
        output += f"    link/{self.link} {self.mac} brd {self.mac_brd}\n"
        
        if len(self.names) > 1:
            for name in self.names[1:]:
                output += f"    altname {name}\n"

        if self.link == "loopback":
            output += f"    inet {self.inet4[0]} scope host lo\n"
            output += f"        valid_lft forever preferred_lft forever\n"
            output += f"    inet6 {self.inet6} scope host\n"
            output += f"        valid_lft forever preferred_lft forever"

        else:
            for id, ip in enumerate(self.inet4):
                output += f"    inet {ip} metric 100 brd {self.inet4_brd[id]} scope global dynamic {self.names[0]}\n"
            output += f"        valid_lft forever preferred_lft forever\n"
            output += f"    inet6 {self.inet6} scope link\n"
            output += f"        valid_lft forever preferred_lft forever"

        return output



    def __init__(self, name=["lo"], link="loopback", mtu=65536, type_str="LOOPBACK", mac="00:00:00:00:00:00", mac_brd="00:00:00:00:00:00", state=0, inet4=["127.0.0.1/8"], inet6="::1/128") -> None:
        self.names = name
        self.link = link
        self.mtu = mtu
        self.type_str = type_str
        self.mac = mac
        self.mac_brd = mac_brd
        self.state = state
        self.inet4 = []
        self.inet4_brd = []
        self.inet4_gtw = []

        for ip in inet4:
            self.inet4.append(str(ip).split("/")[0])
            self.inet4_brd.append(ipcalc.Network(ip).broadcast())
            self.inet4_gtw.append(ipcalc.Network(ip).network()+1)
        self.inet6 = inet6

    

    def add_ip(self, ip):
        self.inet4.append(str(ip).split("/")[0])
        self.inet4_brd.append(ipcalc.Network(ip).broadcast())
        self.inet4_gtw.append(ipcalc.Network(ip).network()+1)

    

    def del_ip(self, ip):
        self.inet4.remove(ip.split("/")[0])
        self.inet4_brd.remove(ipcalc.Network(ip).broadcast())
        self.inet4_gtw.remove(ipcalc.Network(ip).network()+1)
