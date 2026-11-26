# Connect an AI client
<!-- group: Run mustra; order: 65; pages: /settings -->

GitHub Copilot, Claude, ChatGPT and other AI clients that speak MCP can read your fleet through mustra and ask for changes to it. A client never changes anything itself: what it asks for waits until a person approves it.

## Create a token for the client

1. **Administration → API Tokens**, under **New token**.
2. Name it after the client ("Copilot in VS Code — Sam") and give it an expiry.
3. Tick **See the fleet** (`fleet.read`). For a client that only reads, tick nothing else.
4. For a client that may also ask for changes, add **Deploy software and run actions** (`deploy.manage`, for playbooks and packages) or **Manage patches** (`patches.manage`), or both.
5. Tick **MCP only**. The token then works on the MCP endpoint and nowhere else, so a client holding `deploy.manage` can ask to deploy but cannot deploy.
6. Create it and copy the token. It is shown **once**.

Give each client and each person their own token, so one can be revoked without the others, and the audit log names who asked.

## Add mustra to the client

**Connect an AI client**, below API Tokens, shows this console's endpoint (`https://mustra.example.com/api/mcp`) and a configuration to copy for each client:

- **VS Code and GitHub Copilot:** a `.vscode/mcp.json` that asks for the token once and keeps it in VS Code's secret storage.
- **Claude Code:** a `claude mcp add --transport http` command that reads the token from `MUSTRA_TOKEN`.
- **Claude Desktop:** a `claude_desktop_config.json` entry using the `mcp-remote` bridge.
- **ChatGPT and the OpenAI API:** a remote MCP tool for the Responses API. OpenAI connects from its own servers, so the console must be reachable from the internet over HTTPS.
- **Other clients:** the endpoint and header, for anything that speaks MCP over Streamable HTTP.

## What a client can read

What a token may see, the client may see, and no more: the tools answer through the same routes as the console, with the same permissions and content sets.

- **Endpoints:** `list_endpoints` (by name, IP, OS, site, group or online state), `get_endpoint` (facts, attributes, recent actions), `get_sensor` (any sensor's last cached answer), `list_groups`.
- **What is outstanding:** `get_needs_attention` (the Guide queue), `list_vulnerabilities`, `get_hardening` (benchmark scores and failing checks), `list_enforce_drift`, `list_pending_updates`, `list_notifications`.
- **What was done:** `list_deployments` and `get_deployment`, with each device's own result, so failed, timed out and no response stay apart.
- **What can be run:** `list_playbooks`, `list_packages`.
- **Containers:** `list_containers` and `list_container_changes`.

Lists are limited (200 rows unless the client asks for fewer or more, up to 1,000) and say when they were cut short.

## What a client can ask for

- `request_playbook_run`: run a playbook, on the endpoints it targets or on some of them.
- `request_package_deployment`: install, update or remove a catalog package, or run an action package, on named endpoints.
- `request_patch_deployment`: install pending updates on named endpoints, optionally only some packages.

Each one checks the request as the action would (the token's permission, your management rights, the module's action group, the package's content set) and then files an approval request. The client gets its ID and a link to tell you about. It is not done until somebody else approves it under **Access → Approvals**, or from the link:

- The person who asked cannot approve it, through the console or any of their tokens.
- Approving runs it as the token that asked, with what that token may do then. A token revoked in the meantime runs nothing.
- Nobody deciding within eight hours expires it.
- A package or patch request always names its endpoints; none targets the whole fleet. A playbook whose computer group was deleted cannot be requested.

## Keep in mind

Endpoint values (hostnames, process names, alert text) and release notes are written by endpoints and third parties. mustra tells the client to treat them as data, but read what a client asks you to approve before you approve it.
