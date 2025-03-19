from digest import Digest
from report_generator import VulnerabilityReport
import toml
import logging

class Interface:
    def __init__(self):
        with open('interface.txt') as f:
            self.interface = f.read()
        self.config_path = "config.toml"
        self.credential = "credentials.json"
        self.threat_map_config = "threat_map_config.json"
        
        self.config = toml.load(self.config_path)
        self.debugging = self.config.get("Debugging", {}).get("state", False)
        
        # Configure logging
        if self.debugging:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(level=logging.ERROR)
            
        self.logger = logging.getLogger("Interface")
            
    def print_interface(self):
        print(self.interface)
    
    def run(self):
        if self.debugging:
            self.logger.debug("Starting interface")
            
        self.print_interface()
        prompt = input("Enter Prompt:")
        
        if self.debugging:
            self.logger.debug(f"Creating Digest with prompt: {prompt}")
            
        # Pass the debugging parameter to Digest
        digest = Digest(
            self.credential, 
            self.threat_map_config, 
            self.config_path, 
            prompt,
            debugging=self.debugging
        )
        
        if self.debugging:
            self.logger.debug("Running KAG analysis")
            
        result = digest.kag_analysis()
        
        if self.debugging:
            self.logger.debug("Creating vulnerability report")
            
        report = VulnerabilityReport()
        
        # Get report folder location from config
        report_folder = self.config.get("Report_Format", {}).get("report_folder_location", "reports")
        
        if self.debugging:
            self.logger.debug(f"Generating report in folder: {report_folder}")
            
        report.generate_report(result, report_folder)
        
        if self.debugging:
            self.logger.debug("Interface execution complete")
            
        return result