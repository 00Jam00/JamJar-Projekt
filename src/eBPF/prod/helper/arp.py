



class ARP():
    address = ""
    HWtype = ""
    HWaddress = ""
    flags_mask = ""
    Iface = [""]
    


    def __str__(self):
     return f"{self.address}\t{self.HWtype}\t\t{self.HWaddress}\t{self.flags_mask}\t\t{self.Iface.names[0]}"



    def __init__(self, address="127.0.0.1", hwtype="ether", hwaddress="AA:BB:CC:DD:EE:FF", flags_mask="C", iface=[""]) -> None:
        self.address = address
        self.HWtype = hwtype
        self.HWaddress = hwaddress
        self.flags_mask = flags_mask
        self.Iface = iface
