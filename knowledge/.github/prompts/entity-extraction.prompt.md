---
prompt: entity-extraction
---
# Entity Extraction Prompt

Extract structured data from the following content.

## Input
{{content}}

## Output
Return JSON array of entities: [{ "name": "...", "type": "person|org|concept|date", "context": "..." }]