from typing import Dict
import json
from langchain_community.tools.shell.tool import ShellTool
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate

from _template import ReturnTemplate


class Head:
    def __init__(self, credential: str, config: dict, tool: str, prompt: str, verbose: str = "INFO"):
        with open(credential, "r") as f:
            self.token = json.load(f)["token"]
        self.head_config = config["LLM"]
        self.url = self.head_config["api_url"]
        self.pen_test_config = config["PenTest_Config"]
        self.prompt = prompt
        self.tool = tool
        self.messages = self.head_setup()
        self.verbose = verbose
        

    def head_setup(self):
        instruct_list = ", ".join([
            f"don't {' '.join(k.split('_'))}" if isinstance(v, bool) and not v else
            f"{' '.join(k.split('_'))}" if isinstance(v, bool) and v else
            f"{' '.join(k.split('_'))} is {v}" if isinstance(v, (int, float)) else
            f"{' '.join(k.split('_'))} is {v}"
            for k, v in self.pen_test_config.items()
        ])
        
        return f"""You are an expert at using {self.tool} for penetration testing.
        {instruct_list}.
        Time is in miliseconds.
        Return ONLY a JSON object in this format:
        {{
            "command": "<the command to execute>",
            "output": "<the output from the command>"
        }}
        Task: {self.prompt}"""

    def head(self):
        llm = ChatOpenAI(
            model=self.head_config["model"],
            openai_api_key=self.token,
            openai_api_base=self.url,
        )
        shell_tool = ShellTool(handle_tool_error=True)
        shell_tool.description = f"Execute {self.tool} commands. " + shell_tool.description
        agent = initialize_agent(
            [shell_tool], 
            llm, 
            agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            verbose=True if self.verbose == "DEBUG" else False
        )
        result = agent.run(self.messages)
        
        try:
            # First, try to clean markdown code blocks if present
            if '```' in result:
                cleaned_result = result.replace('```json', '').replace('```', '').strip()
                try:
                    parsed_response = json.loads(cleaned_result)
                    return parsed_response
                except json.JSONDecodeError:
                    pass
            
            # If that fails or if no markdown blocks, try direct parsing
            if isinstance(result, dict):
                return result
            elif isinstance(result, str):
                # Try to find and parse JSON in the string
                try:
                    json_start = result.find('{')
                    json_end = result.rfind('}') + 1
                    if json_start != -1 and json_end != -1:
                        json_str = result[json_start:json_end]
                        parsed_response = json.loads(json_str)
                        return parsed_response
                except json.JSONDecodeError:
                    pass
                
            # If all parsing attempts fail, format the raw output
            return {
                "command": "",
                "output": result
            }
        except Exception as e:
            print(f"Error parsing result: {e}")
            return {
                "command": "",
                "output": result
            }

class ParserHead():
    def __init__(self, credential: str, config: dict):
        self.parser = JsonOutputParser(pydantic_object=ReturnTemplate)
        with open(credential, "r") as f:
            self.token = json.load(f)["token"]
        self.head_config = config["LLM"]
        self.url = self.head_config["api_url"]
        self.llm = ChatOpenAI(
            model=self.head_config["model"],
            openai_api_key=self.token,
            openai_api_base=self.url,
        )
        
        self.prompt = PromptTemplate(
            template="""Extract the information from the context into the specified format, remove any quotation in the strings.
            These are the cases to handle:
            1. If found multiple IP with the same host, separate them into different objects.
            \n{format_instructions}\n{output}""",
            input_variables=["output"],
            partial_variables={"format_instructions": self.parser.get_format_instructions()}
        )
        
        self.chain = self.prompt | self.llm | self.parser

    def head(self, result: dict) -> Dict:
        try:
            combined_output = ""
            
            for tool_name, tool_data in result.items():
                command = tool_data.get('command', '')
                output = tool_data.get('output', '')
                combined_output += f"\nTool: {tool_name}\nCommand: {command}\nOutput:\n{output}\n"
            
            return self.chain.invoke({
                "output": combined_output
            })
                
        except Exception as e:
            print(f"ERROR in parsing: {str(e)}")
            return ReturnTemplate(result=[]).model_dump()


class RAGHead():

    def __init__(self, credential: str, config: dict, prompt: str):
        with open(credential, "r") as f:
            self.token = json.load(f)["token"]
        self.llm_config = config["LLM"]
        self.embedding_config = config["RAG"]
        self.prompt = prompt