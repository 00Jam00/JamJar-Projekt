class Iptables:
    def __init__(self):
        self.chains = {
            "INPUT": [],
            "FORWARD": [],
            "OUTPUT": []
        }

    def add_rule(self, chain, source=None, destination=None, protocol=None,
                 source_port=None, destination_port=None, action="ACCEPT"):
        if chain not in self.chains:
            raise ValueError(f"Ungültige Kette: {chain}. Verfügbare Ketten sind INPUT, FORWARD, OUTPUT.")

        rule = {
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "action": action
        }
        self.chains[chain].append(rule)

    def remove_rule(self, chain, source=None, destination=None, protocol=None,
                    source_port=None, destination_port=None, action=None):
        if chain not in self.chains:
            raise ValueError(f"Ungültige Kette: {chain}. Verfügbare Ketten sind INPUT, FORWARD, OUTPUT.")

        self.chains[chain] = [
            r for r in self.chains[chain]
            if not (
                r["source"] == source and
                r["destination"] == destination and
                r["protocol"] == protocol and
                r["source_port"] == source_port and
                r["destination_port"] == destination_port and
                (action is None or r["action"] == action)
                
            )
        ]

    def list_rules(self):
        output = []
        for chain, rules in self.chains.items():
            output.append(f"Chain {chain} (policy ACCEPT)")
            output.append("target     prot opt source               destination")
    
            for r in rules:
                target = r["action"] if r["action"] else ""
                protocol = r["protocol"] if r["protocol"] else "all"
                source = r["source"] if r["source"] else "anywhere"
                destination = r["destination"] if r["destination"] else "anywhere"
    
                ports = []
                if r["source_port"]:
                    ports.append(f"sport:{r['source_port']}")
                if r["destination_port"]:
                    ports.append(f"dport:{r['destination_port']}")
                port_info = " ".join(ports)
    
                output.append(f"{target:<10} {protocol:<4} --  {source:<20} {destination:<20} {port_info}")
    
            if not rules:
                output.append("")
    
        return "\n".join(output)


    def clear_chain(self, chain):
        if chain not in self.chains:
            raise ValueError(f"Ungültige Kette: {chain}. Verfügbare Ketten sind INPUT, FORWARD, OUTPUT.")
        
        self.chains[chain] = []

    def clear_all(self):
        for chain in self.chains:
            self.chains[chain] = []

    def rule_exists(self, chain, source=None, destination=None, protocol=None,
                source_port=None, destination_port=None, action=None):
      
        if chain not in self.chains:
            return False
    
        for rule in self.chains[chain]:
            if (rule["source"] == source and
                rule["destination"] == destination and
                rule["protocol"] == protocol and
                rule["source_port"] == source_port and
                rule["destination_port"] == destination_port and
                (action is None or rule["action"] == action)):
                return True
    
        return False


    
    def simulate(self):
        output = []
        for chain, rules in self.chains.items():
            for r in rules:
                rule_description = []
                if r["source"]:
                    rule_description.append(f"-s {r['source']}")
                if r["destination"]:
                    rule_description.append(f"-d {r['destination']}")
                if r["protocol"]:
                    rule_description.append(f"-p {r['protocol']}")
                if r["source_port"]:
                    rule_description.append(f"--sport {r['source_port']}")
                if r["destination_port"]:
                    rule_description.append(f"--dport {r['destination_port']}")
                rule_description.append(f"-j {r['action']}")
                output.append(f"iptables -A {chain} " + " ".join(rule_description))
        return "\n".join(output) if output else "Keine Regeln zu simulieren."

    
