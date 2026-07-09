# Evaluating Prompt Engineering Strategies for DAST Findings Triage with Local Open-Weight LLMs

## Aim

To evaluate the effectiveness of large language models, specifically open-source models via Ollama, in automating the triage of DAST web application vulnerability scanner findings using structured prompt engineering techniques.

## Research question

To what extent can Chain-of-Thought and zero-shot prompt engineering strategies with local open-weight LLMs produce accurate and calibrated triage decisions, including true/false positive classification and exploitability scoring, for DAST-generated web application vulnerability findings when evaluated against verified ground truth labels?

## Objectives

- Assemble a labeled DAST findings dataset (OWASP ZAP + Burp Suite runs against DVWA and one additional test app) with true/false labels and exploitability/prioritization annotations.
- Implement a reproducible Ollama pipeline that runs two local models (e.g., gemma3, gemma4) and enforces structured JSON outputs.
- Explore NVIDIA NIM as an alternative open-weight inference backend, comparing cloud-hosted NIM deployment to local Ollama execution.
- Integrate a reasoning safety monitor and explicit calibration layer into prompt templates, inspecting Chain-of-Thought steps and confidence reasoning for overconfidence and reasoning inconsistencies.
- Compare three prompt patterns (zero-shot JSON, few-shot JSON, Chain-of-Thought with JSON enforcement) and evaluate using classification metrics and calibration against a baseline.
- Deliverables: prompt templates, an evaluation notebook with results and examples, and a short report summarizing failure modes and recommendations.

## Project focus

This research targets DAST findings from OWASP ZAP and Burp Suite, using open-source LLMs to automate triage of findings into true/false positive classification, exploitability scoring, and remediation priority. The current direction emphasizes evaluation of cloud/open-weight inference via NVIDIA NIM and the addition of a Reasoning Safety Monitor-style calibration layer that validates Chain-of-Thought reasoning and confidence outputs.

## Current direction

- Port the structured triage pipeline to NVIDIA NIM for open-weight model inference and compare it with the existing Ollama-based local execution.
- Use a calibration-aware prompt design that requires explicit confidence probability, calibrated reasoning justification, and monitor-style review of the reasoning chain.
- Measure not only classification accuracy and exploitability MAE, but also calibration metrics such as expected calibration error and reasoning consistency.

## Relevant Sources

- **Prompting the Priorities: A First Look at Evaluating LLMs for Vulnerability Triage and Prioritization**
  - Authors: Osama Al Haddad, Muhammad Ikram, Ejaz Ahmed, Young Lee
  - Date: 21 October 2025
  - Link: https://arxiv.org/pdf/2510.18508
- **Streamlining Security Vulnerability Triage with Large Language Models**
  - Authors: Mohammad Jalili Torkamani, Joey NG, Nikita Mehrotra, Mahinthan Chandramohan, Padmanabhan Krishnan, Rahul Purandare
  - Date: 31 January 2025
  - Link: https://arxiv.org/pdf/2501.18908
- **SastBench: A Benchmark for Testing Agentic SAST Triage**
  - Authors: Jake Feiglin, Guy Dar
  - Date: 6 January 2026
  - Link: https://arxiv.org/pdf/2509.15195
- **LLM-Driven SAST-Genius: A Hybrid Static Analysis Framework for Comprehensive and Actionable Security**
  - Authors: Vaibhav Agrawal, Kiarash Ahi
  - Date: 18 September 2025
  - Link: https://arxiv.org/pdf/2509.15433
- **Learning to Triage Taint Flows Reported by Dynamic Program Analysis in Node.js Packages**
  - Authors: Ronghao Ni, Aidan Z. H. Yang, Min-Chien Hsu, Nuno Sabino, Limin Jia, Ruben Martins, Darion Cassel, Kevin Cheang
  - Date: 23 October 2025
  - Link: https://arxiv.org/pdf/2510.20739

## Extra Sources

- **Adaptive and AI-Augmented Security Testing: A Systematic Survey of Program Analysis, Feedback-Driven Testing, and Hybrid Learning-Based Approaches**
  - Authors: Michael Wienczkowski
  - Date: 28 April 2026
  - Link: https://arxiv.org/pdf/2604.27000
- **Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection**
  - Authors: Damian Gnieciak, Tomasz Szandala
  - Date: 6 August 2025
  - Link: https://arxiv.org/pdf/2508.04448
- **From Description to Score: Can LLMs Quantify Vulnerabilities?**
  - Authors: Sima Jafarikhah, Daniel Thompson, Eva Deans, Hossein Siadati, Yi Liu
  - Date: 4 January 2026
  - Link: https://arxiv.org/pdf/2512.06781
- **Beyond Content Safety: Real-Time Monitoring for Reasoning Vulnerabilities in Large Language Models**
  - Authors: Xunguang Wang, Yuguang Zhou, Qingyue Wang, Zongjie Li, Ruixuan Huang, Zhenlan Ji, Pingchuan Ma, Shuai Wang
  - Date: 26 March 2026
  - Link: https://arxiv.org/pdf/2603.25412v1
- **CHAINTRIX: A Multi-Pipeline LLM-Augmented Framework for Automated Smart-Contract Security Auditing**
  - Authors: Gabriela Dobrita, Simona-Vasilica Oprea, Adela Bara
  - Date: 10 May 2026
  - Link: https://arxiv.org/pdf/2605.09350
- **AgenticVM: Agentic AI for Adaptive Software Vulnerability Management**
  - Authors: Asrul Arifin, Hussain Ahmad, Yiyao Zhang, Diksha Goel
  - Date: 3 May 2026
  - Link: https://arxiv.org/pdf/2605.01739

_Nothing triaged yet. New items will appear here as contributions are promoted from the INBOX._