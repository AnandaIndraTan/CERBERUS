from typing import Dict
import json
import logging
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_mistralai import ChatMistralAI, MistralAIEmbeddings
from langchain_community.embeddings import JinaEmbeddings

class HealthCheck:
    def __init__(self, credential: str, config: dict):
        # Configure logging for errors only
        logging.basicConfig(
            level=logging.ERROR,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("HealthCheck")

        try:
            with open(credential, "r") as f:
                self.token = json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Credential file {credential} not found")
            raise FileNotFoundError(f"Credential file {credential} not found")
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON format in credential file {credential}")
            raise ValueError(f"Invalid JSON format in credential file {credential}")
        except KeyError:
            self.logger.error("Token not found in credential file")
            raise KeyError("Token not found in credential file")

        required_sections = ["PenTest_Config", "LLM", "Embedding", "Suite_config"]
        missing_sections = [sect for sect in required_sections if sect not in config]
        if missing_sections:
            self.logger.error(f"Missing required config sections: {missing_sections}")
            raise KeyError(f"Missing required config sections: {missing_sections}")

        self.head_config = config["LLM"]
        self.pen_test_config = config["PenTest_Config"]
        self.embedding_config = config["Embedding"]
        self.suite_config = config["Suite_config"]

        self.mapping_model = {
            "mistral": (
                ChatMistralAI,
                "model",
                "mistral_api_key",
                "mistral_api_endpoint"
            ),
            "openai": (
                ChatOpenAI,
                "model",
                "openai_api_key", 
                "openai_api_base"
            )
        }

        self.mapping_embedding = {
            "jina": (
                JinaEmbeddings,
                "jina_api_key",
                "model_name"
            ),
            "openai": (
                OpenAIEmbeddings,
                "model",
                "api_key"
            ),
            "mistral": (
                MistralAIEmbeddings,
                "model",
                "api_key"
            )
        }

    def _validate_configs(self) -> None:
        """Validate all configurations"""
        # Validate Suite Config
        if "tool_list" not in self.suite_config:
            self.logger.error("Missing tool_list in Suite_config")
            raise KeyError("Missing tool_list in Suite_config")
        if not isinstance(self.suite_config["tool_list"], list):
            self.logger.error("tool_list must be a list")
            raise TypeError("tool_list must be a list")

    def health_check(self):
        """
        Perform health check and return the LLM service
        Returns: llm_service
        """
        self._validate_configs()
        llm_distribution = self.head_config["distribution"]
        embedding_distribution = self.embedding_config["distribution"]

        try:
            # LLM Setup
            if llm_distribution not in self.mapping_model:
                self.logger.error(f"Unsupported LLM distribution: {llm_distribution}")
                raise ValueError(f"Unsupported LLM distribution: {llm_distribution}")

            llm_class, model_param, key_param, url_param = self.mapping_model[llm_distribution]
            llm_service = llm_class(
                **{
                    model_param: self.head_config["model"],
                    key_param: self.token["token"],
                    url_param: self.head_config["api_url"]
                }
            )

            # Embedding Setup
            if embedding_distribution not in self.mapping_embedding:
                self.logger.error(f"Unsupported Embedding distribution: {embedding_distribution}")
                raise ValueError(f"Unsupported Embedding distribution: {embedding_distribution}")

            embedding_class, key_param, model_param = self.mapping_embedding[embedding_distribution]
            embedding_params = {
                model_param: self.embedding_config["model"],
                key_param: self.token["embedding_token"]
            }
            embedding_service = embedding_class(**embedding_params)

            # Test connections
            test_result = self._test_services(llm_service, embedding_service)
            if not all(test_result.values()):
                failed = [svc for svc, status in test_result.items() if not status]
                self.logger.error(f"Connection test failed for: {failed}")
                raise ConnectionError(f"Connection test failed for: {failed}")

            return llm_service, embedding_service

        except Exception as e:
            error_msg = (
                f"Health check failed:\n"
                f"Distribution: LLM={llm_distribution}, Embedding={embedding_distribution}\n"
                f"Error: {str(e)}"
            )
            self.logger.error(error_msg)
            raise Exception(error_msg)

    def _test_services(self, llm, embedding) -> dict:
        """Test connections to services"""
        results = {}
        
        try:
            response = llm.invoke("hi")
            results["llm"] = bool(response)
        except Exception as e:
            self.logger.error(f"LLM connection test failed: {str(e)}")
            results["llm"] = False

        try:
            response = embedding.embed_query("test embedding connection")
            results["embedding"] = isinstance(response, list) and len(response) > 0
        except Exception as e:
            self.logger.error(f"Embedding connection test failed: {str(e)}")
            results["embedding"] = False

        return results