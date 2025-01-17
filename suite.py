from typing import List
import json
import toml
import logging
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langgraph.graph import StateGraph, END

from _template import AgentState
from head import Head, ParserHead
from threatmap import ThreatMap




class Suite:
    def __init__(self, credential:str, threat_map_config:str, config_path: str, prompt: str, logging_level: str = "INFO"):
        self.config = toml.load(config_path)
        self.list_of_tools = self.config["Suite_config"]["tool_list"] + ["FINISH"]
        self.prompt = prompt
        self.credential = credential
        self.parser = ParserHead(credential, self.config)
        self.threat_map = ThreatMap(threat_map_config, credential)
        self.verbose = logging_level

        self.logger = logging.getLogger(__name__)
        try:
            logging_level = getattr(logging, self.verbose.upper())
            self.logger.setLevel(logging_level)
        except AttributeError:
            raise ValueError(f"Invalid logging level: {self.verbose}. Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def supervisor(self, state: AgentState) -> AgentState:        
        if state.current != "supervisor":
            try:
                agent = Head(self.credential, self.config, state.current, state.prompt, self.verbose)
                result = agent.head()
                new_results = dict(state.results)
                new_results[state.current] = result
            except Exception as e:
                self.logger.error(f"Error executing tool: {e}")
                raise e
        else:
            new_results = state.results

        with open(self.credential) as f:
            token = json.load(f)["token"]

        llm = ChatOpenAI(
            model=self.config["LLM"]["model"],
            openai_api_key=token,
            openai_api_base=self.config["LLM"]["api_url"],
        )

        used_tools = list(new_results.keys())
        
        parser = JsonOutputParser()
        supervisor_prompt = PromptTemplate(
            template="""You are a penetration testing expert.
            Given a list of tools: {list_of_tools}
            Given a task: {task}
            Previously used tools: {used_tools}
            
            Return the next tool needed to complete the task.
            Do not select a tool that has already been used.
            When all necessary tools have been used, respond with FINISH.
            {format_instructions}
            
            Example output format:
            "tool1"
            """,
            input_variables=["list_of_tools", "task", "used_tools"],
            partial_variables={"format_instructions": parser.get_format_instructions()}
        )
        chain = supervisor_prompt | llm | parser
        
        try:
            next_tool_response = chain.invoke({
                "list_of_tools": self.list_of_tools,
                "task": state.prompt,
                "used_tools": used_tools
            })
            
            if isinstance(next_tool_response, dict) and 'tool' in next_tool_response:
                next_tool = str(next_tool_response['tool'])
            elif isinstance(next_tool_response, str):
                next_tool = next_tool_response
            else:
                next_tool = "FINISH"
                    
            if next_tool not in self.list_of_tools or next_tool in used_tools:
                next_tool = "FINISH"
                    
            self.logger.debug(f"LLM selected next tool: {next_tool}")
        except Exception as e:
            self.logger.error(f"Error in LLM chain: {e}")
            raise
        
        if next_tool == state.current:
            next_tool = "FINISH"
        
        new_state = AgentState(
            prompt=state.prompt,
            results=new_results,
            current=next_tool,
            next=next_tool
        )
        return new_state
        
    def create_workflow(self):
        self.logger.debug("=== Creating Workflow ===")
        workflow = StateGraph(AgentState)
        workflow.add_node("supervisor", self.supervisor)

        for tool in self.list_of_tools:
            if tool != "FINISH":
                workflow.add_node(tool, lambda x: x)
                self.logger.debug(f"Added node: {tool}")

        # Add edges from tools back to supervisor
        for tool in self.list_of_tools:
            if tool != "FINISH":
                workflow.add_edge(tool, "supervisor")
                self.logger.debug(f"Added edge: {tool} -> supervisor")

        # Add conditional edges from supervisor to tools
        conditional_map = {tool: tool for tool in self.list_of_tools}
        conditional_map["FINISH"] = END
        workflow.add_conditional_edges(
            "supervisor",
            lambda x: x.next,
            conditional_map
        )
        self.logger.debug("Added conditional edges from supervisor")

        workflow.set_entry_point("supervisor")
        self.logger.debug("=== Workflow Created ===")
        return workflow.compile()
    
    def suite(self):
        workflow = self.create_workflow()
        self.logger.debug("=== Starting Workflow Execution ===")
        initial_state = AgentState(
            prompt=self.prompt,
            results={},
            current="supervisor",
            next="supervisor"
        )
        self.logger.debug(f"Initial State: current={initial_state.current}, next={initial_state.next}")
        
        try:
            result = workflow.invoke(initial_state)
            self.logger.debug("=== Workflow Execution Complete ===")
            return result
        except Exception as e:
            self.logger.error(f"Error during workflow execution: {e}")
            self.logger.error(f"Error type: {type(e)}")
            raise
    
    def run(self):
        result = self.suite()
        parsed_result = self.parser.head(result["results"])
        self.logger.debug("=== Parsed Results ===")
        self.logger.debug(json.dumps(parsed_result, indent=2))
        self.logger.debug("=== Adding data to Threat Map ===")
        for scan_data in parsed_result["result"]:
            self.threat_map.add_entity(scan_data["result"])
            self.threat_map.verify_data()
        self.logger.debug("=== Data added to Threat Map ===")