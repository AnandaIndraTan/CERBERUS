from typing import Dict
import logging
import json
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_mistralai import ChatMistralAI, MistralAIEmbeddings
from langchain_community.embeddings import JinaEmbeddings
from langchain.chains import RetrievalQA
from langchain_community.tools.shell.tool import ShellTool
from langchain.agents import AgentType, initialize_agent
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import DocArrayInMemorySearch
from langchain.schema import Document

from _template import ReturnTemplate
from healthcheck import HealthCheck


class Head:
    def __init__(self, credential: str, config: dict, tool: str, prompt: str, debugging: bool = False):
        self.debugging = debugging
        
        # Configure logging
        if self.debugging:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(level=logging.ERROR)
            
        self.logger = logging.getLogger("Head")
        
        with open(credential, "r") as f:
            creds = json.load(f)
            self.embedding_token = creds["embedding_token"]

        self.head_config = config["LLM"]
        self.pen_test_config = config["PenTest_Config"]
        self.prompt = prompt
        self.tool = tool
        self.messages = self.head_setup()
        self.llm, self.embeddings = HealthCheck(credential, config).health_check()
   
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=50,
            separators=["\n", ".\n", "?\n", "!\n"],
        )

    def head_setup(self):
        if self.debugging:
            self.logger.debug(f"Setting up prompt for tool: {self.tool}")
            
        config_instructions = [
            f"{'do not ' if not v else ''}{' '.join(k.split('_'))}" if isinstance(v, bool) else
            f"{' '.join(k.split('_'))} is {v} miliseconds" if isinstance(v, (int, float)) and 'time' in k else
            f"{' '.join(k.split('_'))} is {v}"
            for k, v in self.pen_test_config.items()
        ]
        
        numbered_instructions = [
            f"{i}. {instruction}"
            for i, instruction in enumerate(config_instructions, start=7)
        ]
        
        instruct_list = "\n".join(numbered_instructions)
        
        return f"""System Message: You are an expert penetration tester specializing in {self.tool}. Your task is to perform security scanning following these STRICT guidelines:

    COMMAND GENERATION RULES:
    1. Generate ONLY authentic {self.tool} commands that you are 100% certain will work without root access.
    2. DO NOT modify or invent command flags that don't exist in {self.tool}'s documentation
    3. DO NOT add "-o" or output flags unless explicitly requested
    4. Each command must be executable as-is without modifications
    5. If uncertain about a command parameter, use only the basic, well-documented options
    6. DO NOT attempt to guess or fabricate command syntax

    OBSERVATION HANDLING:
    1. Wait for actual command output before making observations
    2. NEVER fabricate or imagine scan results
    3. Only analyze the exact output provided by the tool
    4. If a command fails, acknowledge the failure and suggest corrections
    5. DO NOT make assumptions about what the scan might find
    6. Report exactly what is in the output, nothing more

    CONFIG SETTINGS:
    {instruct_list}

    RESPONSE FORMAT:
    command: <exact {self.tool} command to execute>
    finding: <only analyze the actual output received from the command>

    Task: {self.prompt}

    Remember: Accuracy over comprehensiveness. It's better to run a simple, correct command than a complex, incorrect one."""
    
    def process_output(self, output: str):
        try:
            if self.debugging:
                self.logger.debug("Processing output with text splitter")
            texts = self.text_splitter.split_text(output)
            data = [Document(page_content=text) for text in texts]
            
            if self.debugging:
                self.logger.debug(f"Creating vector store with {len(data)} documents")
            vectorstore = DocArrayInMemorySearch.from_documents(
                data,
                self.embeddings
            )
            
            queries = [
                "all IP, state, hostnames, services, ports, versions, and protocols",
                "subdomain or hidden path discovery",
                "critical vulnerabilities and exploitable findings",
                "high-risk security issues and weaknesses",
                "security configuration problems",
                "authentication and access control vulnerabilities",
                "injection vulnerabilities and exploits",
                "potential sensitive data exposure",
            ]
            
            if self.debugging:
                self.logger.debug(f"Running {len(queries)} retrieval queries")
                
            findings = []
            for query in queries:
                retriever = vectorstore.as_retriever(
                    search_type = "mmr",
                    search_kwargs= {
                        "k":5
                        } 
                    )
                results = retriever.invoke(query)
                findings.extend([doc.page_content for doc in results])
            
            findings = list(set(findings))
            
            if self.debugging:
                self.logger.debug(f"Retrieved {len(findings)} unique findings, generating analysis")
                
            analysis = self.llm.invoke(
                f"""Security Scan result of {self.tool}:
                {findings}
                
                List out all {", ".join(queries)} in the scan result.
                Format as a clear list of findings.
                """
            )
            
            return analysis.content

        except Exception as e:
            self.logger.error(f"Error in processing large output: {e}")
            return str(e)

    def head(self):
        if self.debugging:
            self.logger.debug(f"Initializing shell tool for {self.tool}")
            
        # Create ShellTool with verbose parameter tied to debugging
        shell_tool = ShellTool(
            handle_tool_error=True, 
            handle_validation_error=True, 
            handle_parsing_error=True,
            verbose=self.debugging  # Set verbose parameter based on debugging
        )
        shell_tool.description = f"Execute {self.tool} commands. " + shell_tool.description
        
        if self.debugging:
            self.logger.debug("Initializing agent")
            
        agent = initialize_agent(
            [shell_tool], 
            self.llm, 
            agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            verbose=self.debugging,  # Only be verbose if debugging is enabled
            max_iterations=3,
            handle_parsing_errors=True  
        )
        
        validation_prompt = f"""VALIDATION CHECK:
    1. Is this a valid {self.tool} command?
    2. Does it use only documented flags?
    3. Is it forcing any output flags?
    4. Will it execute without modification?
    
    If any check fails, revise the command to use only basic, documented parameters."""
        
        if self.debugging:
            self.logger.debug("Running agent with prompt and validation check")
            
        result = agent.run(self.messages + "\n" + validation_prompt)
        
        try:
            if '```' in result:
                result = result.replace('```', '').strip()
            
            # Extract command and output from the result
            command_part = ""
            output_part = ""
            
            if "command:" in result.lower():
                parts = result.split("command:", 1)
                if len(parts) > 1:
                    remaining = parts[1]
                    if "finding:" in remaining.lower():
                        command_part, output_part = remaining.split("finding:", 1)
                    else:
                        command_part = remaining
            
            if self.debugging:
                self.logger.debug("Processing output through RAG")
                
            # Process the output through RAG
            processed_output = self.process_output(output_part if output_part else result)
            
            # Format the final string
            final_result = f"Command: {command_part.strip()}\nFindings:\n{processed_output}"
            
            if self.debugging:
                self.logger.debug("Returning final results")
                
            return final_result
                
        except Exception as e:
            self.logger.error(f"Error parsing result: {e}")
            return result

class ParserHead():
    def __init__(self, credential: str, config: dict, debugging: bool = False):
        self.debugging = debugging
        
        # Configure logging
        if self.debugging:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(level=logging.ERROR)
            
        self.logger = logging.getLogger("ParserHead")
        
        self.parser = JsonOutputParser(pydantic_object=ReturnTemplate)
        self.head_config = config["LLM"]
        
        if self.debugging:
            self.logger.debug("Performing health check")
            
        self.llm, self.embeddings = HealthCheck(credential, config).health_check()
       
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=50,
            separators=["\n", ".\n", "?\n", "!\n"],
        )
        
        if self.debugging:
            self.logger.debug("Setting up parser prompt template")
            
        self.prompt = PromptTemplate(
            template="""Extract the information from the context into the specified format, remove any quotation in the strings.
            These are the cases to handle:
            1. If found multiple IP with the same host, separate them into different objects.
            \n{format_instructions}\n{output}""",
            input_variables=["output"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()}
        )
        
        self.chain = self.prompt | self.llm | self.parser

    def head(self, results: str) -> Dict:
        try:
            # If text is large, use RAG to process it
            if len(results) > 4000:  # Adjust threshold as needed
                if self.debugging:
                    self.logger.debug("Using RAG for large text processing")

                texts = self.text_splitter.split_text(results)
                documents = [Document(page_content=text) for text in texts]
                
                if self.debugging:
                    self.logger.debug(f"Creating vector store with {len(documents)} documents")
                    
                vectorstore = DocArrayInMemorySearch.from_documents(
                    documents,
                    self.embeddings
                )
                
                # Create a more structured retrieval prompt to preserve actual data
                retriever = vectorstore.as_retriever(search_kwargs={"k": 6})
                
                # Define the parsing prompt template
                # Configure QA chain with the appropriate prompt
                parse_prompt = PromptTemplate(
                    template="""Extract all the security scan information from the provided text. 
                ONLY report information that is explicitly mentioned in the text - DO NOT hallucinate or invent details.

                Focus on:
                1. All actual IP addresses mentioned in the scan results
                2. All actual hostnames mentioned in the scan results
                3. All actual services and ports found in the scan results
                4. All actual vulnerabilities identified in the scan results

                If certain information is not present in the text, indicate it as "Not found in scan results".
                IMPORTANT: Only include IP addresses and hosts that are explicitly identified in the scan results.
                Do not generate example or placeholder data. Never invent information that is not present in the original scan.

                Context:
                {context}

                {format_instructions}""",
                    input_variables=["context"],
                    partial_variables={"format_instructions": self.parser.get_format_instructions()}
                )

                if self.debugging:
                    self.logger.debug("Configuring QA chain for retrieval")
                    
                # Configure QA chain with the appropriate prompt
                qa_chain = RetrievalQA.from_chain_type(
                    llm=self.llm,
                    chain_type="stuff",
                    retriever=retriever,
                    chain_type_kwargs={"prompt": parse_prompt}
                )

                if self.debugging:
                    self.logger.debug("Executing retrieval and parsing")
                    
                # Execute the retrieval and parsing
                processed_results = qa_chain.invoke({"query": "Extract security scan information"})
                
                # Parse the processed results into the required format
                if self.debugging:
                    self.logger.debug("Final parsing of processed results")
                    
                return self.chain.invoke({
                    "output": processed_results
                })
            else:
                # If text is small enough, parse directly
                if self.debugging:
                    self.logger.debug("Using direct parsing for small text")
                    
                return self.chain.invoke({
                    "output": results
                })
                
        except Exception as e:
            self.logger.error(f"ERROR in parsing: {str(e)}")
            return ReturnTemplate(result=[]).model_dump()