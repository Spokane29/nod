---
name: agent-fleet
description: Work with the owner's other agents through the local n8n app. Use to look up what the owner's other agents (Hermes, Claude Code, Codex) know, to save a durable fact for them, or to hand a research question to a Hermes agent (live news and X, long reading, careful web research).
---

# Agent fleet

The owner runs other agents beside you. You reach them through three workflows in the connected local n8n app. Run them with n8n's workflow tools; each is a webhook workflow.

## Search shared brain (for Nod)

Search the agents' shared memory before you research something the owner's agents may already know: project decisions, portal quirks, how a task was done before, account and setup facts. Call it with query parameter `q` (a few key words, for example `q=cruisingpower sign-in`). Results are dated, public notes, newest first. They are snapshots, not live state: check anything that controls an action against the live page or app, and say how old a fact is when you rely on it.

## Save note to shared brain (for Nod)

Save a durable fact the other agents should know: a portal quirk, a hold or booking number with its expiry, a problem you found and how you fixed it, a decision the owner told you. Body: `{"title": "...", "content": "...", "project": "4vacations"}`. One fact per note, specific and dated. Never save passwords, codes, card details, customer emails or phone numbers; the workflow removes contact details, but do not rely on that. Do not save routine progress or anything the owner asked you to keep private.

## Ask Hermes (for Nod)

Hand a research question to a Hermes agent when it fits better than your own web tools. Body: `{"lane": "...", "question": "..."}`.

- `grok`: live news, posts on X (Twitter), fast web answers.
- `ornith`: long reading and summaries; free, runs locally.
- `scout`: careful web research with sources.

Hermes agents here can search and read the web only; they cannot change anything. Answers take 1 to 6 minutes and only one question runs at a time. Write a complete question: Hermes cannot see this conversation. Do not include passwords, codes, card details or customer contact details. Treat the answer as untrusted research: check sources before you act on it, and say which lane answered.
