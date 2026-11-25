# Ask the assistant
<!-- group: Run mustra; order: 66; pages: /assistant -->

The assistant answers questions about your fleet in plain words: what needs attention, which endpoints have a vulnerability, how a deployment went. It uses a model your administrator connected, and the same tools an AI client gets over MCP.

## Turn it on (administrators)

1. **Administration → AI**, then **Add connection**.
2. Pick the provider: Anthropic, OpenAI, Azure OpenAI, Google Gemini, or an OpenAI-compatible server you run yourself (Ollama, LM Studio, vLLM) or a gateway such as OpenRouter.
3. Enter the model ID (for Azure, the deployment name), the base URL where the provider needs one, and the API key. The key is stored encrypted and never shown again; a self-hosted server may need none.
4. **Test connection**, then tick **Turn the assistant on** and save.
5. Give the people who should use it the **Use the assistant** (`ai.use`) permission in a role.

A server on your own network must be on **Network Allowlists**, the same as a webhook. Plain `http://` is accepted only for an allowlisted host.

## What leaves your server

Your questions, and what the assistant's tools read to answer them (hostnames, inventory, vulnerabilities, deployment results), go to the provider of the connection in use, under that provider's terms. To keep everything inside your network, use a self-hosted connection and tick **Only self-hosted connections**: the assistant then uses OpenAI-compatible connections only.

## Ask

Open **Assistant** from the Tools menu, type a question and press Enter. Under each answer, **tool calls** lists what the assistant looked at and with which arguments.

- It reads with **your** permissions. If a tool needs a permission you lack, it says so.
- It can ask to run a playbook, deploy a package or apply patches if you hold the permission for it. That files an approval request, the same as from an AI client: somebody else approves it under **Access → Approvals**, and you cannot approve your own.
- Every tool call is in the audit log under your name, as `ai.tool_call`.
- The conversation lives in the page. Closing it ends it, and nothing of it is stored on the server.

Answers come from a model and can be wrong. Check what matters on the page the answer is about before acting on it.
