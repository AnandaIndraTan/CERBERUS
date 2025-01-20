from typing import Annotated, TypedDict, List, Dict, NotRequired, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass


class Vulnerability(TypedDict):
    cve_id: NotRequired[Annotated[str, "The CVE ID of the vulnerability, '' if not available"]]
    description: Annotated[str, "The description of the vulnerability"]
    cvss: Annotated[float, "The CVSS score of the vulnerability"]
    is_vulnerable: Annotated[bool, "Whether the vulnerability is confirmed"]

class Service(TypedDict):
    name: Annotated[str, "The name of the service"]
    version: Annotated[str, "The version of the service"]

class Port(TypedDict):
    port: Annotated[int, "The port number"]
    protocol: Annotated[str, "The protocol used (tcp/udp)"]
    service: Annotated[Service, "The service running on the port"]
    vulnerabilities: Annotated[List[Vulnerability], "Vulnerabilities linked to this port"]

class ScanResult(TypedDict):
    host: Annotated[str, "The Host/Domain address of the host"]
    ip: Annotated[str, "The IP address of the host"]
    ports: Annotated[List[Port], "List of open ports and their details"]

class ScanResultTemplate(TypedDict):
    command: Annotated[str, "The command executed"]
    result: Annotated[ScanResult, "The result of the command parsed into ScanResult format"]

class ReturnTemplate(BaseModel):
    result: List[ScanResultTemplate] = Field(description="Result of each tool execution")


class ToolOutput(TypedDict):
    command: str
    output: str

class Results(TypedDict):
    tool_name: Dict[str, Any]

@dataclass
class AgentState:
    prompt: str
    results: Results
    current: str
    next: str