from langchain.chains import LLMChain
from langchain_community.document_loaders import PyPDFLoader
from langgraph.graph import StateGraph
from typing import TypedDict, Annotated
import os
import toml
import logging
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import DocArrayInMemorySearch
from langchain.schema import Document
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_mistralai import ChatMistralAI, MistralAIEmbeddings
from langchain_community.embeddings import JinaEmbeddings

from head import ParserHead
from healthcheck import HealthCheck
from suite import Suite


class Digest:
    def __init__(self, credential:str, threat_map_config: str, config_path: str, prompt: str, debugging: bool = False):
        self.config = toml.load(config_path)
        self.debugging = debugging
        
        if self.debugging:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(level=logging.ERROR)
            
        self.logger = logging.getLogger("Digest")
        
        self.parser = ParserHead(credential, self.config, self.debugging)
        
        if self.debugging:
            self.logger.debug("Initializing Suite...")
        self.results, self.threat_map_data = Suite(credential, threat_map_config, config_path, prompt).run()
        
        if self.debugging:
            self.logger.debug("Performing health check...")
        self.llm, self.embeddings = HealthCheck(credential, self.config).health_check()

        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=50,
            separators=["\n", ".\n", "?\n", "!\n"],
        )

        initial_text = f"""Generate a security assessment report based on given prompt and data, the data included in report should comprise of:
        1. Target information (IP address, Hostname, Services, Ports, Versions, Protocols)
        2. The commad used to test the target
        3. Each vulnerabilities identified in the target, related to the OWASP Top 10
        4. Provide the assessment purely in paragraphs and strings
        Task:
        {prompt}
        """
        if self.debugging:
            self.logger.debug("Creating initial vector store...")
        texts = self.text_splitter.split_text(initial_text)
        documents = [Document(page_content=text) for text in texts]
        self.vectorstore = DocArrayInMemorySearch.from_documents(
            documents,
            self.embeddings
        )

    def _merge_and_vectorize(self):
        """Load OWASP document and scan results into vector store"""
        try:
            # Get the path to the OWASP Top 10 PDF file from config
            owasp_pdf_path = self.config["Report_Format"]["security_benchmark"]
            owasp_content = ""
            
            if os.path.exists(owasp_pdf_path):
                # Load and parse the PDF
                loader = PyPDFLoader(owasp_pdf_path)
                pages = loader.load()
                
                # Extract text from all pages
                owasp_content = "\n".join([page.page_content for page in pages])
                if self.debugging:
                    self.logger.debug(f"Successfully loaded OWASP document from {owasp_pdf_path}")
            else:
                self.logger.warning(f"OWASP document not found at: {owasp_pdf_path}")
            
            # Combine scan results with OWASP reference
            if owasp_content:
                if self.debugging:
                    self.logger.debug("Combining scan results with OWASP content")
                combined_text = f"""
                # Scan Results
                {self.results}
                
                # OWASP Reference
                {owasp_content}
                """
            else:
                if self.debugging:
                    self.logger.debug("Using scan results only (no OWASP content)")
                combined_text = f"""
                # Scan Results
                {self.results}
                """
            
            # Split the combined text
            texts = self.text_splitter.split_text(combined_text)
            
            # Create documents and update vectorstore
            documents = [Document(page_content=text) for text in texts]
            if self.debugging:
                self.logger.debug(f"Creating vector store with {len(documents)} documents")
            self.vectorstore = DocArrayInMemorySearch.from_documents(
                documents,
                self.embeddings
            )
            
        except Exception as e:
            self.logger.error(f"Error in merging and vectorizing data: {str(e)}")
            # If there's an error, just use the scan results
            texts = self.text_splitter.split_text(self.results)
            documents = [Document(page_content=text) for text in texts]
            self.vectorstore = DocArrayInMemorySearch.from_documents(
                documents,
                self.embeddings
            )

    def _rag_analysis(self, state):
        # Get relevant context from the vectorstore - prioritize scan results
        if self.debugging:
            self.logger.debug("Performing RAG analysis...")
        docs = self.vectorstore.similarity_search("security vulnerabilities scan results", k=7)
        context = "\n".join(doc.page_content for doc in docs)
        
        if self.debugging:
            self.logger.debug("Creating LLM chain for report generation")
        chain = LLMChain(
            llm=self.llm,
            prompt=PromptTemplate(
                template="""
                Generate a security vulnerability report based on the provided context.
                
                CONTEXT:
                {context}
                
                Your task:
                1. Identify all vulnerabilities present in the scan results
                2. For each vulnerability found, mention which OWASP Top 10 category it relates to (if applicable)
                3. Describe the impact and risk of each vulnerability
                4. Provide practical remediation steps
                
                Structure your report with:
                1. Executive Summary
                2. Key Findings (including OWASP references where relevant)
                3. Risk Assessment
                4. Recommendations
                
                Important: When mentioning OWASP, be natural. For example: "A SQL Injection vulnerability was found in the login form. This aligns with the OWASP Top 10 category A3:2021-Injection."
                """,
                input_variables=["context"]
            )
        )
        
        if self.debugging:
            self.logger.debug("Invoking LLM for report generation")
        state["report"] = chain.invoke({"context": context})["text"]
        if self.debugging:
            self.logger.debug("RAG analysis complete")
        return state

    def _kg_cross_analysis(self, state):
        if self.debugging:
            self.logger.debug("Performing knowledge graph cross-analysis...")
        chain = LLMChain(
            llm=self.llm,
            prompt=PromptTemplate(
                template="""
                Cross-analyze the current report with knowledge graph insights:
                
                Current Report:
                {current_report}
                
                Knowledge Graph Data:
                {kg_data}
                
                Provide a final comprehensive report that integrates both analyses.
                """,
                input_variables=["current_report", "kg_data"]
            )
        )
        
        if self.debugging:
            self.logger.debug("Invoking LLM for report enrichment with KG data")
        result = chain.invoke({
            "current_report": state["report"],
            "kg_data": self.threat_map_data
        })
        
        state["report"] = result["text"]
        state["final"] = True
        if self.debugging:
            self.logger.debug("Knowledge graph cross-analysis complete")
        return state
    
    def kag_analysis(self):
        try:
            # Get all data sources ready
            if self.debugging:
                self.logger.debug("Starting KAG analysis workflow")
                self.logger.debug("Merging and vectorizing data...")
            self._merge_and_vectorize()
            
            # Define state type
            ReportState = TypedDict("ReportState", {
                "report": Annotated[str, "Current report state"],
                "final": Annotated[bool, "Whether analysis is complete"]
            })
            
            # Create workflow
            if self.debugging:
                self.logger.debug("Creating workflow graph")
            workflow = StateGraph(ReportState)
            
            # Add nodes and edges
            workflow.add_node("rag", self._rag_analysis)
            workflow.add_node("kg", self._kg_cross_analysis)
            workflow.add_edge("rag", "kg")
            
            workflow.set_entry_point("rag")
            
            # Run workflow
            if self.debugging:
                self.logger.debug("Executing workflow")
            final_state = workflow.compile().invoke({
                "report": "",
                "final": False
            })
            
            if self.debugging:
                self.logger.debug("Workflow execution complete")
            return final_state["report"]
            
        except Exception as e:
            self.logger.error(f"Error in KAG analysis: {str(e)}")
            return None