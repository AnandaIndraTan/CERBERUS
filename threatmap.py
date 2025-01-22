from typing import Dict, Union, List
import json
from neo4j import GraphDatabase
from datetime import datetime



class ThreatMap:
    def __init__(self, config: str, credentials: str):
        self.config = config
        with open(credentials) as f:
            self.credentials = json.load(f)["neo4j_cred"]
        self.driver = GraphDatabase.driver(
            uri=self.credentials["neo4j_uri"],
            auth=(self.credentials["neo4j_user"], self.credentials["neo4j_password"])
        )
        self.load_schema()
        self.init_schema()

    def __del__(self):
        self.driver.close()

    def load_schema(self):
        with open(self.config) as f:
            schema = json.load(f)
            self.schema_mapping = schema["schema_mapping"]

    def _dict_to_props(self, props: Dict) -> str:
        props_list = []
        for k, v in props.items():
            if v is None:
                props_list.append(f'{k}: null')
            elif isinstance(v, str):
                # Use double quotes for string values containing apostrophes
                props_list.append(f'{k}: "{v}"')
            elif isinstance(v, bool):
                props_list.append(f'{k}: {str(v).lower()}')
            else:
                props_list.append(f'{k}: {v}')
        return "{" + ", ".join(props_list) + "}"

    def generate_constraint(self, label: str, constraints: Union[str, List[str]]) -> str:
        if not constraints:  
            return ""  
        
        if isinstance(constraints, list):
            return f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE ({', '.join(f'n.{prop}' for prop in constraints)}) IS UNIQUE"
        return f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.{constraints} IS UNIQUE"

    def generate_index(self, rel_type: str, prop: str) -> str:
        return f"CREATE INDEX IF NOT EXISTS FOR ()-[r:{rel_type}]-() ON (r.{prop})"

    def init_schema(self):
        with self.driver.session() as session:
            # Drop all existing nodes
            session.run("MATCH (n) DETACH DELETE n")
            
            # List all constraints
            constraints = session.run("SHOW CONSTRAINTS").data()
            
            # Drop all existing constraints
            for constraint in constraints:
                try:
                    session.run(f"DROP CONSTRAINT {constraint['name']}")
                except:
                    pass
                
            # Create new constraints based on schema_mapping
            for label, schema_info in self.schema_mapping.items():
                if schema_info["constraints"]:  # Only create constraint if not empty
                    constraint_query = self.generate_constraint(label, schema_info["constraints"])
                    if constraint_query:  # Only run if there's a query to run
                        session.run(constraint_query)
            
            # Create indexes
            processed_indexes = set()
            for schema_info in self.schema_mapping.values():
                for rel_info in schema_info["relationships"].values():
                    rel_key = (rel_info["type"], rel_info["index_prop"])
                    if rel_key not in processed_indexes:
                        index_query = self.generate_index(rel_info["type"], rel_info["index_prop"])
                        session.run(index_query)
                        processed_indexes.add(rel_key)

    def create_relationship(self, from_node: Dict, to_node: Dict, schema_mapping: Dict, properties: Dict = None):
        from_type = from_node["label"]
        to_type = to_node["label"]
        
        if from_type not in schema_mapping or to_type not in schema_mapping[from_type]["relationships"]:
            raise ValueError(f"Invalid relationship: {from_type} -> {to_type}")
            
        rel_info = schema_mapping[from_type]["relationships"][to_type]
        rel_type = rel_info["type"]
        
        props = rel_info["default_props"].copy()
        if properties:
            props.update(properties)
            
        props.update({
            "created_at": datetime.now(),
            "last_seen": datetime.now()
        })
        
        # For Port nodes, MERGE on IP and port number combination
        if to_type == "Port":
            query = f"""
            MATCH (a:{from_type} {self._dict_to_props(from_node['properties'])})
            MERGE (a)-[r:{rel_type}]->(b:{to_type} {{number: {to_node['properties']['number']}}})
            ON CREATE SET b = {self._dict_to_props(to_node['properties'])}, r = $props
            ON MATCH SET b = {self._dict_to_props(to_node['properties'])}, r.last_seen = datetime()
            """
        else:
            query = f"""
            MERGE (a:{from_type} {self._dict_to_props(from_node['properties'])})
            MERGE (b:{to_type} {self._dict_to_props(to_node['properties'])})
            MERGE (a)-[r:{rel_type}]->(b)
            ON CREATE SET r = $props
            """
        
        with self.driver.session() as session:
            session.run(query, {"props": props})

    def add_entity(self, scan_data: dict):
        # Create Host -> IP relationship
        if scan_data["host"] != "" and scan_data["ip"] != "":
            self.create_relationship(
                from_node={"label": "Host", "properties": {"name": scan_data["host"]}},
                to_node={"label": "IPAddress", "properties": {"address": scan_data["ip"]}},
                schema_mapping=self.schema_mapping
            )

        for port_data in scan_data["ports"]:
            # Create IP -> Port relationship with IP address included in port properties
            port_properties = {
                "number": port_data["port"],
                "protocol": port_data["protocol"],
                "ip_address": scan_data["ip"]  # Include IP address in port properties
            }

            self.create_relationship(
                from_node={"label": "IPAddress", "properties": {"address": scan_data["ip"]}},
                to_node={"label": "Port", "properties": port_properties},
                schema_mapping=self.schema_mapping
            )

            # Create Port -> Service relationship
            service_data = {
                "name": port_data["service"]["name"],
                "version": port_data["service"]["version"]
            }
            
            self.create_relationship(
                from_node={"label": "Port", "properties": port_properties},  # Use the same port properties
                to_node={"label": "Service", "properties": service_data},
                schema_mapping=self.schema_mapping
            )

            # Process vulnerabilities
            for vuln in port_data["vulnerabilities"]:
                vuln_data = {
                    "description": vuln["description"],
                    "cvss": vuln["cvss"],
                    "is_vulnerable": vuln["is_vulnerable"]
                }
                if vuln.get("cve_id"):
                    vuln_data["cve_id"] = vuln["cve_id"]

                self.create_relationship(
                    from_node={"label": "Service", "properties": service_data},
                    to_node={"label": "Vulnerability", "properties": vuln_data},
                    schema_mapping=self.schema_mapping
                )

    def verify_data(self):
        with self.driver.session() as session:
            queries = [
                """MATCH (h:Host)-[r:RESOLVES_TO]->(ip:IPAddress) 
                RETURN h.name as host, ip.address as ip""",
                
                """MATCH (ip:IPAddress)-[r:HOSTS]->(p:Port) 
                RETURN ip.address as ip, p.number as port, p.protocol as protocol, p.ip_address as port_ip""",
                
                """MATCH (p:Port)-[r:RUNS]->(s:Service) 
                RETURN p.number as port, p.ip_address as ip, s.name as service, s.version as version""",
                
                """MATCH (s:Service)-[r:HAS_VULNERABILITY]->(v:Vulnerability) 
                RETURN s.name as service, v.description as vulnerability, v.cvss as cvss"""
            ]
            
            results = []
            for query in queries:
                try:
                    result = session.run(query)
                    # Optionally, you can collect and print the results
                    records = list(result)
                    print(f"Query results: {records}")
                    results.append(records)
                except Exception as e:
                    print("ERROR", e)
                    raise e
            return "SUCCESS"