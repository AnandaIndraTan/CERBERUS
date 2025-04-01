# Project CERBERUS (v-Alpha)
The project name is inspired by the Ancient Greek Mythology, Cerberus. It was told that Cerberus is the multi-headed dog of Hades that guards the gate of Hell to prevent the dead from leaving. This project, aims to embody the myth in the realm of Cybersecurity, where the primary objective is to make system vulnerabilities spotted (k̑érberos), ensuring no known vulnerabilities leave into the world and causing havoc.

## About The Project
Cerberus is a penetration testing agent that leverages multi-agent LLM architecture to perform simulated red team operations. The automation for penetration testing is largely inspired by the "Cyber Kill Chain" attack framework developed by Lockheed Martin in 2017. Motivated by the critical need for affordable cybersecurity solutions as digitalization accelerates, Cerberus aims to make security testing accessible to small businesses. Through realistic attack emulation, the system efficiently identifies known vulnerabilities, enabling organizations to implement targeted fixes that effectively deter lower-skilled attackers (Script Kiddies/Novice Hackers) from successfully compromising their infrastructure.
 
Cerberus was initiated by Ananda Indra Tan as Final Year Project during the study in City University of Hong Kong. The project is open-source and welcome for community development.

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
  <img width="339" alt="Screenshot 2025-04-01 at 4 35 45 PM" src="https://github.com/user-attachments/assets/c6ec1e6e-a546-48f7-b921-cfb7b0eb268d" />
  </br>
- Then, run `uv add -r requirements.txt` and `uv pip install -r requirements.txt`
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
