from typing import List
import json
import toml
import logging
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import DocArrayInMemorySearch
from langchain.schema import Document
from langchain.chains import RetrievalQA
from langgraph.graph import StateGraph, END

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_mistralai import ChatMistralAI, MistralAIEmbeddings
from langchain_community.embeddings import JinaEmbeddings


from _template import AgentState
from healthcheck import HealthCheck
from head import Head, ParserHead
from threatmap import ThreatMap


class Suite:
    def __init__(self, credential:str, threat_map_config:str, config_path: str, prompt: str, debugging: bool = False):
        self.debugging = debugging
        
        # Configure logging
        if self.debugging:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(
                level=logging.INFO,  
                format='%(message)s' 
            )
            
        self.logger = logging.getLogger("Suite")
        
        self.config = toml.load(config_path)
        self.list_of_tools = self.config["Suite_config"]["tool_list"] + ["FINISH"]
        self.prompt = prompt
        self.credential = credential
        
        if self.debugging:
            self.logger.debug("Initializing ParserHead")
        self.parser = ParserHead(credential, self.config, debugging=self.debugging)
        
        if self.debugging:
            self.logger.debug("Initializing ThreatMap")
        self.threat_map = ThreatMap(threat_map_config, credential)
        
        if self.debugging:
            self.logger.debug("Performing health check")
        self.llm, self.embeddings = HealthCheck(credential, self.config).health_check()
        
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=50,
            separators=["\n", ".\n", "?\n", "!\n"],
        )

        if self.debugging:
            self.logger.debug("Creating initial vector store")
        initial_text = f"Security Assessment Task: {prompt}\nAvailable Tools: {self.list_of_tools}"
        texts = self.text_splitter.split_text(initial_text)
        documents = [Document(page_content=text) for text in texts]
        self.vectorstore = DocArrayInMemorySearch.from_documents(
            documents,
            self.embeddings
        )

    def update_rag(self, text:str):
        if self.debugging:
            self.logger.debug("Updating RAG with new text")
            
        texts = self.text_splitter.split_text(text)
        documents = [Document(page_content=text) for text in texts]
        if self.vectorstore is None:
            if self.debugging:
                self.logger.debug("Creating new vector store")
            self.vectorstore = DocArrayInMemorySearch.from_documents(
                documents,
                self.embeddings
            )
        else:
            if self.debugging:
                self.logger.debug(f"Adding {len(documents)} documents to existing vector store")
            self.vectorstore.add_documents(documents)

    def supervisor(self, state: AgentState) -> AgentState:  
        if self.debugging:
            self.logger.debug(f"Supervisor processing state with current={state.current}")
              
        if state.current != "supervisor":
            try:
                if self.debugging:
                    self.logger.debug(f"Creating Head agent for tool: {state.current}")
                agent = Head(self.credential, self.config, state.current, state.prompt, debugging=self.debugging)
                
                if self.debugging:
                    self.logger.debug(f"Running Head agent for tool: {state.current}")
                result = agent.head()
                new_results = f"{state.results}\n{result}"
                used_tools = state.used_tools + [state.current]

                if self.debugging:
                    self.logger.debug(f"Updating RAG with results from {state.current}")
                self.update_rag(result)
                
            except Exception as e:
                self.logger.error(f"Error executing tool: {e}")
                raise e
        else:
            new_results = state.results
            used_tools = state.used_tools

        if self.vectorstore:
            if self.debugging:
                self.logger.debug("Creating QA chain for tool selection")
                
            qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            chain_type="refine",
            retriever=self.vectorstore.as_retriever(
                    search_kwargs={"k": 4}
                )
            )
            
            supervisor_prompt = f"""Given the security scan results so far, analyze:

            1. Current Task: {state.prompt}
            2. Tools already used: {used_tools}
            3. All available tools: {self.list_of_tools}

            Based on the scan results and findings:
            1. What security aspects have already been discovered?
            2. What potential vulnerabilities or attack vectors need further investigation?
            3. Which tool would be most appropriate to use next?

            Return only the name of the next tool to use. If no more tools are needed, return FINISH.
            """

            try:
                if self.debugging:
                    self.logger.debug("Running QA chain for next tool selection")
                    
                next_tool = qa_chain.run(supervisor_prompt)
                if next_tool not in self.list_of_tools or next_tool in used_tools:
                    next_tool = "FINISH"
                
                self.logger.debug(f"RAG Analysis recommended next tool: {next_tool}")
            
            except Exception as e:
                self.logger.error(f"Error in RAG analysis: {e}")
                next_tool = "FINISH"

        else:
            if self.debugging:
                self.logger.debug("No vector store available, using direct LLM for tool selection")
                
            supervisor_prompt = f"""You are a penetration testing expert.
        Given these available security testing tools: {self.list_of_tools}
        And this security testing task: {state.prompt}
        
        Which tool should be used first to begin the security assessment?
        Consider the most logical starting point for the given task.
        Return only the name of the tool.
        """
            try:
                next_tool = self.llm.invoke(supervisor_prompt)
                if next_tool not in self.list_of_tools or next_tool in used_tools:
                    next_tool = "FINISH"
                    
                self.logger.debug(f"Supervisor selected first tool: {next_tool}")

            except Exception as e:
                self.logger.error(f"Error in initial tool selection: {e}")
                next_tool = "FINISH"
             
            
            if next_tool == state.current:
                next_tool = "FINISH"
            
        new_state = AgentState(
            prompt=state.prompt,
            results=new_results,
            used_tools=used_tools,
            current=next_tool,
            next=next_tool
        )
        
        if self.debugging:
            self.logger.debug(f"New state: current={new_state.current}, next={new_state.next}")
            
        return new_state
        
    def create_workflow(self):
        self.logger.info("\n=== Creating Workflow ===")
        workflow = StateGraph(AgentState)
        workflow.add_node("supervisor", self.supervisor)

        for tool in self.list_of_tools:
            if tool != "FINISH":
                workflow.add_node(tool, lambda x: x)
                self.logger.info(f"Added node: {tool}")

        # Add edges from tools back to supervisor
        for tool in self.list_of_tools:
            if tool != "FINISH":
                workflow.add_edge(tool, "supervisor")
                self.logger.info(f"Added edge: {tool} -> supervisor")

        # Add conditional edges from supervisor to tools
        conditional_map = {tool: tool for tool in self.list_of_tools}
        conditional_map["FINISH"] = END
        workflow.add_conditional_edges(
            "supervisor",
            lambda x: x.next,
            conditional_map
        )
        
        self.logger.info("Added conditional edges from supervisor")
        workflow.set_entry_point("supervisor")
        self.logger.info("=== Workflow Created ===\n")
            
        return workflow.compile()
    
    def suite(self):
        workflow = self.create_workflow()
        
        self.logger.info("\n=== Starting Workflow Execution ===")
            
        initial_state = AgentState(
            prompt=self.prompt,
            results="",  
            used_tools=[],
            current="supervisor",
            next="supervisor"
        )
        
        self.logger.debug(f"Initial State: current={initial_state.current}, next={initial_state.next}")
        
        try:
            result = workflow.invoke(initial_state)
            self.logger.info("\n=== Workflow Execution Complete ===")
            return result
        
        except Exception as e:
            self.logger.error(f"\n!!! Error during workflow execution: {e}")
            self.logger.error(f"Error type: {type(e)}")
            raise
    
    def run(self):
        if self.debugging:
            self.logger.debug("Starting suite run")
            
        result = self.suite()
        
        self.logger.debug(f"This is result: {result['results']} {type(result['results'])}")
        
        if self.debugging:
            self.logger.debug("Parsing results with ParserHead")
            
        parsed_result = self.parser.head(result["results"])
        
        self.logger.info("\n=== Parsed Results ===")
        self.logger.debug(json.dumps(parsed_result, indent=2))
            
        self.logger.info("\n=== Adding data to Threat Map ===")
            
        for scan_data in parsed_result["result"]:
            self.logger.debug(f"\nAdding this data: {scan_data['result']}")
            
            self.threat_map.add_entity(scan_data["result"])
            if self.debugging:
                self.threat_map.verify_data()
            
        self.logger.info("\n=== Data added to Threat Map ===")
            
        return result["results"], self.threat_map.get_kg_data()
    
