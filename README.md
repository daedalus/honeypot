# 🍯 LLM SSH Honeypot

An SSH honeypot that uses Claude as a dynamic shell backend.
Attackers interact with a realistic-looking Linux environment while every
credential attempt and command is logged for TTP analysis.

## Architecture

```
attacker SSH client
       │
       ▼
 honeypot.py          asyncssh server, accepts all auth, captures creds
       │
       ▼
 llm_shell()          sends command + session history to Claude API
       │              Claude responds as a convincing bash shell
       ▼
 sessions.jsonl       structured JSONL log (one event per line)
       │
       ▼
 monitor.py           CLI dashboard — TTP classification, top creds, live feed
```

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

Generate host key on first run (automatic).

## Run

```bash
# Start honeypot on port 2222 (no root needed)
python honeypot.py --port 2222 --log sessions.jsonl

# On a real server, bind port 22 by redirecting with iptables:
# sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Live dashboard
python monitor.py --log sessions.jsonl --watch
```

## Log format

Each line in `sessions.jsonl` is one of:

| event         | fields                                         |
|---------------|------------------------------------------------|
| `connect`     | sid, peer, ts                                  |
| `auth`        | sid, peer, user, password, ts                  |
| `cmd`         | sid, peer, user, cmd, ts                       |
| `session_end` | sid, peer, user, duration_s, cmd_count, ts     |

## Safety design

- **Payload execution always fails** — any `chmod +x` + run attempt returns
  SIGILL / Killed / segfault so attackers cannot test malware payloads.
- **Fake secrets use known-invalid values** — AWS example keys, doc passwords.
  They look real but are rejected instantly by any real service.
- **No outbound network calls** from the simulated shell — curl/wget output
  is faked; no actual HTTP requests leave the host.
- **Session cap** (default 50 concurrent) prevents resource exhaustion.
- **Session timeout** (default 600s) evicts idle sessions.

## Without an API key

Runs in static fallback mode — responds to ~10 common commands with
hardcoded output. Credential capture still works fully.
