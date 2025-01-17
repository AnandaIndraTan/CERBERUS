from suite import Suite


class Interface:

    def __init__(self):
        with open('interface.txt') as f:
            self.interface = f.read()
        self.config = "config.toml"
        self.credential = "credentials.json"
        self.threat_map_config = "threat_map_config.json"
            

    def print_interface(self):
        print(self.interface)
    
    def run(self):
        self.print_interface()
        prompt = input("Enter Prompt:")
        suite = Suite(self.credential, self.threat_map_config, self.config, prompt, logging_level="DEBUG")
        suite.run()
