# CERBERUS (v-Alpha)

## About The Project

Cerberus is a penetration testing agent that leverages multi-agent LLM architecture to perform simulated red team operations. The project aims to assist the process of security penetration testing through agentic automation through the attack framework "Cyber Kill Chain" that was made by Lockheed Martin, 2017.

The project is open-source and welcome for community development.

## Environment Setup to Start
- Neo4J Desktop 1.5.9 (If Threatmap observation is desired)
- Python 3.12.2
- UV Package Manager, installation can be seen in https://docs.astral.sh/uv/getting-started/installation/
- Linux Environment or MacOS
- Subscribe to LLM Model and Embedding.
**The current prebuilt support is limited to OpenAI (including DeepSeek) and Mistral for models. Then, Jina and Mistral for Embeddings. However, you are more than welcome to add the mapping in the self.mapping_model in HealthCheck.py

## How to Start?
- First, modify the config.toml, set all the parameters. Everything under LLM, Embedding, and Suite_config is required
- Configure a credential.json with the following structure:
  </br>
  <img width="400" alt="Screenshot 2025-04-01 at 4 22 46 PM" src="https://github.com/user-attachments/assets/711ade29-ec78-4e9f-8aa4-5e3be5e8935b" />
- Then, run the following
  `uv add -r requirements.txt`
  `uv pip install -r requirements.txt`
- Go to the Cerberus folder (the location of the entire script). Then run `uv run cerberus.py`

## Project Background, Development Details, Rationale of Design

## Current Capability, Advantage/Disadvantage, Room of Improvement

### Current Development Stage

The project is currently in the Alpha stage, focusing on establishing core reconnaissance capabilities including:
- Domain/Sub-domain Discovery
- Service/Port Enumeration
- Exploitable Vulnerability Scanning

## Roadmap
- [x] Project CERBERUS (Reconnaissance)
- [ ] Project CERBERUS (Weaponisation, Delivery, Exploitation, Installation, C2, Action on Objectives)
- [ ] Project INFERNO - Playground for newly developed features, dynamic system architecture creation to simulate a real-life system
- [ ] Project KRANION - LLM natively trained for Offensive Security/Red Teaming 
