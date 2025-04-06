# Project CERBERUS (v-Alpha)
The project name is inspired by the Ancient Greek Mythology, Cerberus. It was told that Cerberus is the multi-headed dog of Hades that guards the gate of Hell to prevent the dead from leaving. This project, aims to embody the myth in the realm of Cybersecurity, where the primary objective is to make system vulnerabilities spotted (k̑érberos), ensuring no known vulnerabilities leave into the world and causing havoc.

<img width="214" alt="Screenshot 2025-04-06 at 5 41 04 PM" src="https://github.com/user-attachments/assets/4aa72235-10a8-445d-a0ae-994d2f831346" />


## About The Project
Cerberus is a penetration testing agent that leverages multi-agent LLM architecture to perform simulated red team operations. The automation for penetration testing is largely inspired by the "Cyber Kill Chain" attack framework developed by Lockheed Martin in 2017. Motivated by the critical need for affordable cybersecurity solutions as digitalization accelerates, Cerberus aims to make security testing accessible to small businesses. Through realistic attack emulation, the system efficiently identifies known vulnerabilities and provide mitigation methodologies according to OWASP Top 10. Hence, enabling organizations to implement targeted fixes that effectively deter "Script Kiddies" /Novice Hackers from successfully compromising their infrastructure.
 
Cerberus was initiated by Ananda Indra Tan as Final Year Project during the study in City University of Hong Kong. The project is open-source and welcome for community development.

## Environment Setup to Start
- Neo4J Desktop 1.5.9 (If Threatmap observation is desired)
- Python 3.12.2
- UV Package Manager, installation can be seen in https://docs.astral.sh/uv/getting-started/installation/
- Linux Environment or MacOS
- Subscribe to LLM Model and Embedding.</br>
**The current prebuilt support is limited to OpenAI (including DeepSeek) and Mistral for models. Then, Jina and Mistral for Embeddings. However, you are more than welcome to add the mapping in the self.mapping_model in HealthCheck.py

## How to Start?
- First, modify the config.toml, set all the parameters. Everything under LLM, Embedding, and Suite_config is required
- Configure a credential.json with the following structure:
  </br>
  <img width="339" alt="Screenshot 2025-04-01 at 4 35 45 PM" src="https://github.com/user-attachments/assets/c6ec1e6e-a546-48f7-b921-cfb7b0eb268d" />
  </br>
- Then, run `uv add -r requirements.txt` and `uv pip install -r requirements.txt`
- Go to the Cerberus folder (the location of the entire script). Then run `uv run cerberus.py`

## Development Details, Rationale of Design
From a general perspective, Cerberus is implemented to utilise Multi-Agent LLM (LLM-MA) architecture as a “divide and conquer” mechanism to assess a target, where each agent is specialised in a specific tool. Then, simulating a formal penetration testing service, Cerberus will generate a comprehensive report in compliance to OWASP Top 10 standard, providing potential attack vectors (i.e., “How would someone attack a system") and mitigation advice to affected threat surfaces (Where would someone execute the relevant attack vector).This part utilises Knowledge Augmented Generation (KAG) methodology to ensure accuracy.

The High Level Design for Cerberus v-Alpha:
</br>
</br>
<img width="626" alt="Screenshot 2025-04-01 at 6 10 11 PM" src="https://github.com/user-attachments/assets/8a1bc85a-7753-4005-a16e-7f941712b0b1" />
</br>

### Rationale of Design - LLM-MA

The project uses LLM-MA to mimic a real-life typical cybersecurity team workflow, where each team member has each specialty. Then, consolidating results into a report. This approach is mainly motivated by my personal experience working and observing in corporate level cybersecurity team where there is no simply one-man-army operation to find out a hollistic view of an entire system. Plus, from the approaches I saw previously implemented, most assuming a single model to tackle assessment of a whole big system. Therefore, this design serves as well as a different perspective into solving the very same problem.
</br>
<img width="613" alt="Screenshot 2025-04-06 at 5 38 49 PM" src="https://github.com/user-attachments/assets/4c2d8713-cee4-4322-a852-6fc224c25632" />
</br>
Secondly, as a benchmark to the similar project that is using LLM to perform pen-testing. The author (Gelei et al., 2023) of PentestGPT mentioned some issues related to what is known as "Critical Forgetting" (CF) and "Lost in the Middle" in LLM. The idea of both problems essentially highlight the limitations possessed by the LLM itself, where it struggles to maintain long context and thus, forgetting information. The difference of two problems lies on the approaches. CF happens when user continuously finetune the context (i.e., whn you are using chatbot, you might keep adding requirements), then "Lost in the Middle" happens on several retrieval usecase when user dump a large sum of info (i.e., in cybersecurity usecase, think of the large output from Nikto or Bruteforce tools, such as Dirb).

Therefore, to solve this problem, LLM-MA primarily dividing a task into a more manageable size, essentially to let each LLM Agent (_Head_) instances to handle each tool output and perform analytic purely only from the tool specific perspective. The expected measure is then even somehow one _Head_ starts hallucinating or experiencing the other issues, the other _Head_ will still provide the correct result, hence from consolidation, the correct results could "outvote" the wrong one.

### Rationale of Design - KAG

In terms of report generation, one can actually just plug in RAG module to perform the analytic and generates the reports. However, here lies the problem, RAG is basically similar to a search engine. So, it looks for patterns of words and return it to user according to whatever it found that semantically similar to the prompt/queries.

In a situation where consolidated scan results are way larger than the single tool output. LLM's native problems shine even brighter. While all scanning tools reflect the exact relationship of entities in a system (Hostname, IP Addresses, etc), format of each tool are different, which looking back to how RAG works, is exactly how can innacuracy of entities mapping comes around.

On the other hand, one might argue to use Knowledge Graph (KG) instead, which is reasonable if the sole purpose of the entire report is just to present relationship finding from scan data. However, as the objective of this project also to provide mitigation measure based on OWASP Top 10, the mapping fo information purely from KG will be a data management nightmare.
</br>
</br>
<img width="594" alt="Screenshot 2025-04-06 at 5 37 54 PM" src="https://github.com/user-attachments/assets/dfb22064-3445-48f6-9800-a44731ef3f5f" />
</br>
</br>
Therefore, it comes to Knowledge Augmented Generation (KAG). First was developed (Liang et al., 2024) to bridge the problems of RAG and KG. Essentially taking the benefits of both, KG for the structural relationship and RAG for the data inference. The primary mechanism is to first check for all results purely by RAG, then reinforcing the "truthfulness" of relationships by knowledge injection from the KG data. Think of it like telling the LLM to memorize a concepts by RAG, then KG is the cheatsheet.

## Current Status, Potentials/Limitations, Room of Improvement

### Current Development Stage

The project is currently in the Alpha stage, focusing on establishing core reconnaissance capabilities including:
- Domain/Sub-domain Discovery
- Service/Port Enumeration
- Exploitable Vulnerability Scanning

### The good and the bad

Cerberus at this point is good for general scanning and reconnaissance. The mechanisms and rationale of my design works in general (which is good, means the project is in right track). However, one of the highlights that I always discover is that general knowledge LLMs and the Coders are quite bad at using hacking tools, especially those that are not generally known by people outside of Cybersecurity Field (e.g., sqlmap, Gobuster, etc). Therefore, the accuracy lack-off mainly due to the questionnable tool usage/parameters generated (i.e., Models sometimes confuses Nikto -T as timeout instead of Tuning). 

However, despite those limitations, the mechanism and accuracy is still acceptable, noting that the phase is just to do reconnaissance and discovery, which means any result that needs confirmation (delivery and exploitation) is still out of scope. For the test purposes, using **Nikto** **only** on juiceshop-heroku.com, Cerberus can identify 9/14 potential vulnerabilities across injections, misconfigurations, and XSS. Compared to the ideal identifiable by only using Nikto, that is up to 90% itself (the other 5 requires burpsuite or other tools to confirm). So in general, I would say finetuning is much needed.
</br>
</br>
<img width="622" alt="Screenshot 2025-04-06 at 5 36 46 PM" src="https://github.com/user-attachments/assets/445a6fe3-3d31-4f22-b8a8-0db46e28a230" />
</br>
</br>

### Room for Improvement

From the previous segment, I guess it is very obvious on what is needed to be done. First of all, I do think that general purpose/general coding models are not meant to know cybersecurity much.
(Think of in people case, if you are just a software engineer / common non-computer person, you most likely won't know how to hack things either)

So, the room for improvement is definitely a LLM trained for Cybersecurity (red-teaming specifically). I saw that Google has the Sec-Gemini that is good for threat intel works. I would say then training one for red-teaming should not be impossible as well.

Then, the testing part. Honestly speaking Cerberus has limited testing playground since I need a live host to launch an attack framework completely, which I'd say not quite fit in the usecase of using Tryhackme or HackTheBox. So, I am thinking that in corporate level, you would have a User Acceptance Testing (UAT) sandbox to mimic Production level env for things. So, we can do that as well, which is simple Infrastructure 
As Code (IAC) product. The idea would be Deploy on cloud -> Test -> Pipe the result back to model for CI/CD and finetuning.

Lastly, I do think there is one large module still needed in tooling perspective. Using tools like BurpSuite or OWASP Zap requires interaction with mouse continuously. Also, same goes to some bruteforce tools that has streaming I/O data. Both of these issues are essentially streaming data and real-time interactivity related. Simple solution would be to use Multimodal Models that can integrates the desktop apps. However, the data streaming part were quite a problematic issue by itself. When I tried using Gobuster, Cerberus often prematurely end the observation while the bruteforce process is running.

## Roadmap
So given the room for improvement, I can summarize the next steps that this project should go. In a nutshell: 1 down, 3 mores to go.
- [x] Project CERBERUS (Reconnaissance)
- [ ] Project CERBERUS (Weaponisation, Delivery, Exploitation, Installation, C2, Action on Objectives)
- [ ] Project INFERNO - Playground for newly developed features, dynamic system architecture creation to simulate a real-life system
- [ ] Project KRANION - LLM natively trained for Offensive Security/Red Teaming 


Overall, Thank you for reading and perhaps contributing to this project. I hope that this project can democratise Cybersecurity :)
