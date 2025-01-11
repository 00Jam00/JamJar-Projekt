


class ROUTE():
    inet_from = ""
    inet_to = ""
    interface = None


    
    def __str__(self):
        output = f"{self.inet_from} via {self.inet_to} dev {self.interface.names[0]} proto dhcp src {self.interface.inet4[0]} metric 100"

        return output

    def __init__(self, inet_from="default", inet_to="", interface=None) -> None:
        self.inet_from = inet_from
        self.inet_to = str(inet_to).split("/")[0]
        self.interface = interface