---
prompt: triage
---
# Triage Prompt

Classify the following INBOX item and suggest a target page and section.

## Input
{{content}}

## Output
Return JSON: { "targetPage": "...", "targetSection": "...", "confidence": "high|medium|low" }