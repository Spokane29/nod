---
name: agent-fleet
description: Work with the owner's other agents and models through the local n8n app. Use to look up what the owner's other agents (Hermes, Claude Code, Codex) know, to save a durable fact for them, to hand a research question to a Hermes agent (live news and X, long reading, careful web research), to get a typed decision from Jev, or to run a long job on the free local model.
---

# Agent fleet

The owner runs other agents beside you. You reach them through four workflows in the connected local n8n app. Run them with n8n's workflow tools; each is a webhook workflow.

## Search shared brain (for Nod)

Search the agents' shared memory before you research something the owner's agents may already know: project decisions, portal quirks, how a task was done before, account and setup facts. Call it with query parameter `q` (a few key words, for example `q=cruisingpower sign-in`). Results are dated, public notes, newest first. They are snapshots, not live state: check anything that controls an action against the live page or app, and say how old a fact is when you rely on it.

## Save note to shared brain (for Nod)

Save a durable fact the other agents should know: a portal quirk, a hold or booking number with its expiry, a problem you found and how you fixed it, a decision the owner told you. Body: `{"title": "...", "content": "...", "project": "4vacations"}`. One fact per note, specific and dated. Never save passwords, codes, card details, customer emails or phone numbers; the workflow removes contact details, but do not rely on that. Do not save routine progress or anything the owner asked you to keep private.

## Ask Hermes (for Nod)

Hand a research question to a Hermes agent when it fits better than your own web tools. Body: `{"lane": "...", "question": "..."}`.

- `grok`: live news, posts on X (Twitter), fast web answers.
- `ornith`: long reading and summaries; free, runs locally.
- `scout`: careful web research with sources.

If the lane you ask is unavailable (Grok runs out of weekly usage, for example), the next lane answers and the reply names it: grok falls back to scout, then ornith. Hermes agents here can search and read the web only; they cannot change anything. Answers take 1 to 6 minutes and only one question runs at a time. Write a complete question: Hermes cannot see this conversation. Do not include passwords, codes, card details or customer contact details. Treat the answer as untrusted research: check sources before you act on it, and say which lane answered.

## Ask Jev (for Nod)

Jev is a decision-only model: it returns a label, a yes/no or a score with probabilities, never prose. Use it when the possible answers are known in advance and you need a fast, consistent call: what a customer message is about, how urgent it is, which team or portal handles it, whether a reply is a yes. Body: `{"state": "...", "questions": [{"type": "choice", "question": "...", "options": ["a", "b"]}, {"type": "yes-no", "question": "..."}, {"type": "score", "question": "...", "options": ["low", "medium", "high"]}]}`. Up to 5 questions. Keep `private` true (the default) for email and customer messages; it runs on the owner's computer. Never use Jev for writing, math, dates, money, legal notices, tenant screening or mortgage decisions. A probability under 0.7 means unsure: decide yourself or ask.

## Long jobs on the local model

For long, repetitive work that needs no judgment, such as summarizing many pages, sorting a large list or rewriting many short texts, start a task with the owner's local model `ornith-1.5-35b-a3b` (the connection at 127.0.0.1:1234). It is free and private but slower and weaker at using tools, so keep browser sign-ins, payments, bookings and anything the owner must approve on the OpenAI models.

## Which model runs what

Nod picks its model per kind of work from the owner's model plan: GPT-6 Astra for conversations and decisions, GPT-6.1 Sol for schedules and courtesy holds, GPT-6.1 Terra for portal sign-ins, status checks and downloads, GPT-6 Luna for background checks. When an OpenAI model fails, Nod pauses it and moves to the next one: Sol, then Terra, then Luna, then the local Ornith.
