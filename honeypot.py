#!/usr/bin/env python3
"""
LLM-Powered SSH Honeypot
Simulates multiple OS/device personas via a streaming model pool with automatic
fallback. Supports any OpenAI-compatible provider. Logs all activity for TTP analysis.

Usage:
    export OPENROUTER_API_KEY=sk-or-...
    python honeypot.py [--port 2222] [--sessions-dir ./sessions]
                       [--model openrouter:deepseek/deepseek-v4-flash:free]
                       [--model openrouter:qwen/qwen-2.5-coder-32b-instruct:free]

    # Single-model mode (legacy compat):
    export OPENAI_API_KEY=sk-...
    python honeypot.py --model gpt-4o --api-base https://api.openai.com/v1
"""

import argparse
import asyncio
import json
import logging
import os
import random
import re
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import base64

import asyncssh
import httpx

from personas import ALL_PERSONAS, DEFAULT_PERSONA, Persona

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_PORT        = 2222
DEFAULT_LOG         = Path("sessions.jsonl")
DEFAULT_QUARANTINE  = Path("quarantine")
DEFAULT_SESSIONS_DIR = Path("sessions")
SSH_KEY_FILE       = Path("honeypot_host_key")
MAX_SESSIONS       = 50
SESSION_TIMEOUT    = 600

# ── Provider / model layer ───────────────────────────────────────────────────
_KNOWN_PROVIDERS = {"openrouter", "openai", "groq", "cerebras", "google"}

_PROVIDER_CONFIG = {
    "openrouter": {"base_url": "https://openrouter.ai/api/v1",         "env_key": "OPENROUTER_API_KEY"},
    "openai":     {"base_url": "https://api.openai.com/v1",            "env_key": "OPENAI_API_KEY"},
    "groq":       {"base_url": "https://api.groq.com/openai/v1",       "env_key": "GROQ_API_KEY"},
    "cerebras":   {"base_url": "https://api.cerebras.ai/v1",           "env_key": "CEREBRAS_API_KEY"},
    "google":     {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
                                                                        "env_key": "GOOGLE_API_KEY"},
}

DEFAULT_MODEL_CHAIN = [
    "openrouter:deepseek/deepseek-v4-flash:free",
    "openrouter:qwen/qwen-2.5-coder-32b-instruct:free",
    "openrouter:nvidia/nemotron-3-super-120b-a12b:free",
    "openrouter:arcee-ai/trinity-large-thinking:free",
]

# Override base / key (from --api-base / --api-key or env vars)
_override_base: str | None = os.environ.get("LLM_API_BASE") or None
_override_key:  str | None = os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or None

_model_chain: list[str] = list(DEFAULT_MODEL_CHAIN)
_model_dead:  set[str] = set()

_RETRYABLE_ERRORS = (
    "429", "502", "503", "504",
    "rate", "too many", "try again",
    "temporary", "upstream",
)

_MAX_RETRIES = 3
_RETRY_BACKOFF = 5

MODEL_CACHE_FILE = Path("model_health_cache.json")
_auto_discover: bool = False


def _resolve_provider(model_id: str) -> str:
    prov, _, _ = model_id.partition(":")
    return prov if prov in _KNOWN_PROVIDERS else "openrouter"


def _strip_provider(model_id: str) -> str:
    prov, sep, rest = model_id.partition(":")
    return rest if prov in _KNOWN_PROVIDERS and sep else model_id


def _has_api_key(provider: str) -> bool:
    if _override_key:
        return True
    cfg = _PROVIDER_CONFIG.get(provider)
    if not cfg:
        return False
    return bool(os.environ.get(cfg["env_key"]))


def _get_base_url(provider: str) -> str:
    if _override_base:
        return _override_base
    return _PROVIDER_CONFIG.get(provider, {}).get("base_url", "")


def _get_api_key(provider: str) -> str:
    if _override_key:
        return _override_key
    cfg = _PROVIDER_CONFIG.get(provider, {})
    return os.environ.get(cfg.get("env_key", ""), "")


def alive_models() -> list[str]:
    return [m for m in _model_chain if m not in _model_dead
            and _has_api_key(_resolve_provider(m))]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("honeypot")

# ── Persona selection ─────────────────────────────────────────────────────────
_selected_persona: str = "random"   # set by CLI arg


def pick_persona() -> Persona:
    if _selected_persona == "random":
        return random.choice(list(ALL_PERSONAS.values()))
    return ALL_PERSONAS.get(_selected_persona, ALL_PERSONAS[DEFAULT_PERSONA])


# ── Prompt state machine ──────────────────────────────────────────────────────
#
# Unix personas (linux / macos / freebsd) have a static prompt; the shell
# itself (via LLM) handles any sub-shells like `python3 -i`.
#
# Network OS personas (cisco_asa / juniper_srx / fortinet) have a multi-level
# prompt hierarchy driven by explicit mode-transition commands.  We track the
# current mode per session and swap the prompt accordingly.
#
# Modes are persona-specific strings; unknown commands leave the mode unchanged.

_CISCO_ASA_MODES: dict[str, str] = {
    # mode_name → prompt template (filled with hostname at runtime)
    "user":         "{hostname}> ",
    "enable":       "{hostname}# ",
    "config":       "{hostname}(config)# ",
    "config-if":    "{hostname}(config-if)# ",
    "config-policy": "{hostname}(config-policy-map)# ",
    "config-class": "{hostname}(config-pmap-c)# ",
}

_JUNOS_MODES: dict[str, str] = {
    "operational":  "{username}@{hostname}> ",
    "config":       "{username}@{hostname}# ",
}

_FORTIOS_MODES: dict[str, str] = {
    "global":       "{hostname} # ",
    "config":       "{hostname} ({context}) # ",
    "edit":         "{hostname} ({context}/{item}) # ",
}


def _cisco_asa_next_mode(current: str, cmd: str) -> str:
    c = cmd.strip().lower()
    if current == "user":
        if c == "enable":
            return "enable"
    elif current == "enable":
        if c in ("conf t", "configure terminal", "conf terminal"):
            return "config"
        if c in ("exit", "logout", "quit"):
            return "user"
    elif current.startswith("config"):
        if c.startswith("interface "):
            return "config-if"
        if c.startswith("policy-map "):
            return "config-policy"
        if c.startswith("class "):
            return "config-class"
        if c in ("end",):
            return "enable"
        if c in ("exit",):
            # one level up
            if current in ("config-if", "config-policy", "config-class"):
                return "config"
            return "enable"
    return current


def _junos_next_mode(current: str, cmd: str) -> str:
    c = cmd.strip().lower()
    if current == "operational":
        if c == "configure":
            return "config"
    elif current == "config":
        if c in ("exit", "quit", "exit configuration-mode"):
            return "operational"
    return current


class PromptState:
    """
    Tracks the current CLI mode for a session and resolves the
    prompt string to display after each command.
    """

    def __init__(self, persona: Persona, username: str):
        self.persona   = persona
        self.username  = username
        self._mode     = self._initial_mode()
        # FortiOS context tracking (config <object> / edit <item>)
        self._forti_context: str = ""
        self._forti_item:    str = ""

    def _initial_mode(self) -> str:
        pid = self.persona.id
        if pid == "cisco_asa":
            return "user"
        if pid == "juniper_srx":
            return "operational"
        if pid == "fortinet":
            return "global"
        return "shell"   # linux / macos / freebsd — never changes

    def _hostname(self) -> str:
        """Extract hostname from the persona prompt template or derive it."""
        pid = self.persona.id
        if pid == "cisco_asa":
            return "ciscoasa"
        if pid == "juniper_srx":
            return "srx01"
        if pid == "fortinet":
            return "FG-EDGE-01"
        if pid == "freebsd":
            return "freebsd"
        return "prod-db-03"

    def advance(self, cmd: str) -> None:
        """Update internal mode based on the command just sent."""
        pid = self.persona.id
        if pid == "cisco_asa":
            self._mode = _cisco_asa_next_mode(self._mode, cmd)
        elif pid == "juniper_srx":
            self._mode = _junos_next_mode(self._mode, cmd)
        elif pid == "fortinet":
            self._forti_advance(cmd)

    def _forti_advance(self, cmd: str) -> None:
        c = cmd.strip().lower()
        if self._mode == "global":
            if c.startswith("config "):
                self._forti_context = cmd.strip()[7:].strip()
                self._forti_item    = ""
                self._mode = "config"
        elif self._mode == "config":
            if c.startswith("edit "):
                self._forti_item = cmd.strip()[5:].strip()
                self._mode = "edit"
            elif c in ("end", "abort"):
                self._mode = "global"
                self._forti_context = ""
                self._forti_item    = ""
            elif c == "next":
                self._forti_item = ""
                self._mode = "config"
        elif self._mode == "edit":
            if c in ("next",):
                self._forti_item = ""
                self._mode = "config"
            elif c in ("end",):
                self._mode = "global"
                self._forti_context = ""
                self._forti_item    = ""
            elif c in ("abort",):
                self._mode = "config"

    def current(self) -> str:
        """Return the prompt string to display right now."""
        pid = self.persona.id
        tmpl = self.persona.prompt

        if pid == "cisco_asa":
            mode_tmpl = _CISCO_ASA_MODES.get(self._mode, "{hostname}> ")
            return mode_tmpl.format(hostname=self._hostname())

        if pid == "juniper_srx":
            mode_tmpl = _JUNOS_MODES.get(self._mode, "{username}@{hostname}> ")
            return mode_tmpl.format(username=self.username,
                                    hostname=self._hostname())

        if pid == "fortinet":
            if self._mode == "global":
                return f"{self._hostname()} # "
            if self._mode == "config":
                return f"{self._hostname()} ({self._forti_context}) # "
            if self._mode == "edit":
                return f"{self._hostname()} ({self._forti_context}/{self._forti_item}) # "
            return f"{self._hostname()} # "

        # Unix personas — fill {username} if present
        return tmpl.format(username=self.username)


# ── Banner rendering ──────────────────────────────────────────────────────────

def render_banner(persona: Persona, username: str, last_login: str) -> str:
    return persona.banner.format(
        last_login=last_login,
        username=username,
        hostname="MacBook-Pro",   # macOS persona only
    )


# ── TTP pattern library ───────────────────────────────────────────────────────
TTP_PATTERNS = [
    (r'\b(wget|curl)\s+https?://',          "T1105", "Ingress Tool Transfer",       "HIGH"),
    (r'chmod\s+\+x',                         "T1222", "File Permission Modification", "MED"),
    (r'(crontab|/etc/cron)',                 "T1053", "Scheduled Task/Job",           "HIGH"),
    (r'(useradd|adduser|usermod)',            "T1136", "Create Account",               "HIGH"),
    (r'(authorized_keys|ssh-keygen)',         "T1098", "Account Manipulation",         "HIGH"),
    (r'cat\s+/etc/shadow',                   "T1003", "OS Credential Dumping",         "CRIT"),
    (r'cat\s+/etc/passwd',                   "T1003", "OS Credential Dumping",         "HIGH"),
    (r'\b(nc|ncat|netcat)\b.*(-e|/bin)',     "T1059", "Command & Scripting: Netcat",   "CRIT"),
    (r'(base64\s+-d|base64\s+--decode)',     "T1140", "Deobfuscate/Decode",            "HIGH"),
    (r'(xmrig|minerd|cryptonight|stratum)',  "T1496", "Resource Hijacking",            "HIGH"),
    (r'(\.aws/credentials|AWS_SECRET)',      "T1552", "Unsecured Credentials",         "CRIT"),
    (r'(iptables|ufw)\s+(--flush|-F)',       "T1562", "Impair Defenses",               "HIGH"),
    (r'(history\s*-c|>\s*/root/\.bash_history)', "T1070", "Indicator Removal",        "MED"),
    (r'(\bpsql\b|\bmysql\b|\bmongo\b)',      "T1005", "Data from Local System",        "MED"),
    (r'(python|perl|ruby|php)\s+-[ce]',     "T1059", "Command & Scripting: Interp",   "HIGH"),
    (r'systemctl\s+(enable|start)',          "T1543", "Create/Modify System Process",  "MED"),
    (r'/tmp/[^\s]+\s*&',                     "T1036", "Masquerading",                  "HIGH"),
    (r'(ssh|scp)\s+.*@',                     "T1021", "Remote Services: SSH",          "MED"),
    (r'dd\s+if=',                            "T1005", "Data Staged for Exfil",         "MED"),
    (r'>\s*/dev/null\s+2>&1',               "T1027", "Obfuscated Files/Info",          "LOW"),
    # Network device specific
    (r'show\s+(run|config)',                 "T1005", "Config Disclosure",             "HIGH"),
    (r'(crypto\s+key|show\s+crypto)',        "T1552", "Crypto Key Exposure",           "CRIT"),
    (r'copy\s+run\s+tftp',                   "T1005", "Config Exfiltration via TFTP",  "HIGH"),
]

SEV_COLOR = {"CRIT": "🔴", "HIGH": "🟠", "MED": "🟡", "LOW": "🟢"}


def classify_ttps(cmd: str) -> list[dict]:
    hits = []
    for pattern, mid, label, sev in TTP_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            hits.append({"mitre": mid, "label": label, "severity": sev})
    return hits


def extract_urls(cmd: str) -> list[str]:
    return re.findall(r'https?://[^\s\'";&|]+', cmd)


# ── Session log ───────────────────────────────────────────────────────────────
_log_file:       Path = DEFAULT_LOG
_quarantine_dir: Path = DEFAULT_QUARANTINE
_sessions_dir:   Path = DEFAULT_SESSIONS_DIR


def jlog(record: dict) -> None:
    with _log_file.open("a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ── URL quarantine ─────────────────────────────────────────────────────────────
async def quarantine_url(url: str, sid: str, peer: str) -> None:
    _quarantine_dir.mkdir(exist_ok=True)
    safe_name = re.sub(r'[^\w\-.]', '_', url)[:120]
    ts  = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out = _quarantine_dir / f"{ts}_{safe_name}"
    meta = {"url": url, "sid": sid, "peer": peer,
            "ts": datetime.now(timezone.utc).isoformat()}
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "curl/7.88.1"})
            out.write_bytes(r.content)
            meta.update({"status": r.status_code, "size": len(r.content),
                          "content_type": r.headers.get("content-type", ""),
                          "saved": str(out)})
            log.info("🗂  Quarantined %s → %s (%d bytes)", url, out.name, len(r.content))
    except Exception as exc:
        meta["error"] = str(exc)
        log.warning("Quarantine fetch failed %s: %s", url, exc)
    Path(str(out) + ".meta.json").write_text(json.dumps(meta, indent=2))
    jlog({"event": "quarantine", "sid": sid, "peer": peer, **meta})


# ── Download simulation ────────────────────────────────────────────────────────
def fake_download(url: str, outfile: str | None) -> str:
    fname = outfile or url.rstrip("/").split("/")[-1] or "index.html"
    size  = random.randint(8192, 1_048_576)
    kbps  = random.randint(200, 900)
    secs  = f"0.{random.randint(1, 9)}s"
    ip    = (f"{random.randint(1,254)}.{random.randint(1,254)}."
             f"{random.randint(1,254)}.{random.randint(1,254)}")
    ctype = random.choice(["application/octet-stream", "text/x-sh",
                            "application/x-executable"])
    bar   = "=" * random.randint(30, 48) + ">"
    return (
        f"--2025-{random.randint(1,12):02d}-{random.randint(1,28):02d} "
        f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
        f"--  {url}\n"
        f"Resolving {url.split('/')[2] if '//' in url else url}... {ip}\n"
        f"Connecting to {url.split('/')[2] if '//' in url else url}|{ip}|:80... connected.\n"
        f"HTTP request sent, awaiting response... 200 OK\n"
        f"Length: {size} ({size // 1024}K) [{ctype}]\n"
        f"Saving to: '{fname}'\n\n"
        f"{fname}           100%[{bar}]  {size // 1024:>6}K  {kbps}KB/s    in {secs}\n\n"
        f"'{fname}' saved [{size}/{size}]"
    )


# ── Execution simulation ──────────────────────────────────────────────────────
_FAIL_OUTPUTS = [
    "Segmentation fault (core dumped)",
    "Illegal instruction (core dumped)",
    "Killed",
    "Bus error (core dumped)",
    "./payload: error while loading shared libraries: libssl.so.1.1: "
    "cannot open shared object file: No such file or directory",
    "Aborted (core dumped)",
    "zsh: exec format error: ./payload",
    "bash: ./payload: cannot execute binary file: Exec format error",
]


def fake_execution() -> str:
    prefix = ""
    if random.random() > 0.6:
        prefix = f"[{random.randint(1, 9)}] Initializing...\n"
    return prefix + random.choice(_FAIL_OUTPUTS)


# ── LLM backend (streaming + model pool) ──────────────────────────────────────

class ModelRateLimited(Exception):
    """Raised when the model returns HTTP 402 (Payment Required) or 429 (Too Many Requests)."""
    def __init__(self, model: str, status: int):
        self.model = model
        self.status = status
        super().__init__(f"HTTP {status} for {model}")

class ModelServerError(Exception):
    """Raised when the model returns a 5xx server error."""
    def __init__(self, model: str, status: int):
        self.model = model
        self.status = status
        super().__init__(f"HTTP {status} for {model}")


async def _stream_response(
    base_url: str, api_key: str, model: str,
    messages: list[dict], on_chunk=None,
) -> str:
    """POST /chat/completions with streaming, call on_chunk(token) for each
    content token, return the full accumulated response."""
    full = ""
    async with httpx.AsyncClient(timeout=30) as client:
        async with client.stream(
            "POST",
            f"{base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type":  "application/json",
            },
            json={
                "model":      model,
                "max_tokens": 768,
                "stream":     True,
                "messages":   messages,
            },
        ) as resp:
            if resp.status_code in (402, 429):
                raise ModelRateLimited(model, resp.status_code)
            if 500 <= resp.status_code < 600:
                raise ModelServerError(model, resp.status_code)
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                payload = line[6:]
                if payload == "[DONE]":
                    break
                try:
                    delta = json.loads(payload)["choices"][0]["delta"]
                except (KeyError, IndexError, json.JSONDecodeError):
                    continue
                tok = delta.get("content") or ""
                if tok:
                    full += tok
                    if on_chunk:
                        on_chunk(tok)
    return full


async def llm_shell(
    history: list[dict], cmd: str, system_prompt: str,
    on_chunk=None,
) -> str:
    c = cmd.strip()

    # wget / curl — fake download; real URL to quarantine happens outside
    if re.search(r'\b(wget|curl)\b', c, re.I):
        urls      = extract_urls(c)
        out_match = re.search(r'-[oO]\s+(\S+)', c)
        outfile   = out_match.group(1) if out_match else None
        url       = urls[0] if urls else "http://unknown/payload"
        return fake_download(url, outfile)

    # chmod +x — silent
    if re.match(r'chmod\s+\+x', c, re.I):
        return ""

    # Execution attempt — always fail
    if re.match(r'(\./|bash\s+\S+|sh\s+\S+|python\S*\s+\S+)', c):
        return fake_execution()

    # If no model chain has a usable API key, fall through to static
    alive = [m for m in _model_chain if m not in _model_dead]
    if not alive:
        return _static_fallback(cmd)

    history.append({"role": "user", "content": cmd})
    messages = [{"role": "system", "content": system_prompt}] + history
    full_response = None

    for model_id in alive:
        if model_id in _model_dead:
            continue
        provider = _resolve_provider(model_id)
        model_name = _strip_provider(model_id)
        api_key = _get_api_key(provider)
        base_url = _get_base_url(provider)
        if not api_key or not base_url:
            _model_dead.add(model_id)
            continue

        succeeded = False
        for attempt in range(_MAX_RETRIES):
            try:
                full_response = await _stream_response(
                    base_url, api_key, model_name, messages, on_chunk=on_chunk,
                )
                succeeded = True
                break
            except ModelRateLimited as exc:
                log.warning("Model %s HTTP %d (rate limit / credit exhausted), trying next…",
                            model_id, exc.status)
                _model_dead.add(model_id)
                break
            except ModelServerError as exc:
                if attempt < _MAX_RETRIES - 1:
                    wait = _RETRY_BACKOFF * (attempt + 1)
                    log.warning("Model %s HTTP %d (server error), retry %d/%d in %ds…",
                                model_id, exc.status, attempt + 1, _MAX_RETRIES, wait)
                    await asyncio.sleep(wait)
                else:
                    log.warning("Model %s HTTP %d (server error), retries exhausted, trying next…",
                                model_id, exc.status)
                    _model_dead.add(model_id)
            except Exception as exc:
                estr = str(exc)
                if any(x in estr for x in _RETRYABLE_ERRORS) and attempt < _MAX_RETRIES - 1:
                    wait = _RETRY_BACKOFF * (attempt + 1)
                    log.warning("Model %s failed (%s), retry %d/%d in %ds…",
                                model_id, estr[:80], attempt + 1, _MAX_RETRIES, wait)
                    await asyncio.sleep(wait)
                else:
                    log.warning("Model %s failed (%s), trying next…", model_id, estr[:80])
                    _model_dead.add(model_id)

        if succeeded:
            break

    if full_response is None:
        tok = c.split()
        full_response = f"bash: {tok[0]}: command not found" if tok else ""

    history.append({"role": "assistant", "content": full_response})
    if len(history) > 30:
        history[:] = history[-30:]
    return full_response


def _static_fallback(cmd: str) -> str:
    c = cmd.strip()
    if not c:                          return ""
    if c == "id":                      return "uid=0(root) gid=0(root) groups=0(root)"
    if c == "whoami":                  return "root"
    if c == "pwd":                     return "/root"
    if c.startswith("ls"):             return "anaconda-ks.cfg  .bash_history  .ssh"
    if c.startswith("uname"):          return ("Linux prod-db-03 5.15.0-107-generic "
                                               "#117-Ubuntu SMP x86_64 GNU/Linux")
    if c.startswith("cat"):            return "cat: permission denied"
    if c in ("exit", "logout"):        return ""
    return f"bash: {c.split()[0]}: command not found"


# ── Model auto-discovery ─────────────────────────────────────────────────────
async def _fetch_free_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get("https://openrouter.ai/api/v1/models")
            resp.raise_for_status()
            data = resp.json()
            models = data.get("data", [])
        free: list[str] = []
        for m in models:
            pricing = m.get("pricing", {})
            try:
                prompt_price = float(pricing.get("prompt", 1))
            except (TypeError, ValueError):
                continue
            if prompt_price == 0:
                free.append(f"openrouter:{m['id']}")
        if free:
            log.info("Auto-discovered %d free models from OpenRouter", len(free))
        else:
            log.warning("Auto-discover returned 0 free models")
        return free
    except Exception as exc:
        log.warning("Failed to fetch free models from OpenRouter: %s", exc)
        return []


# ── Startup health check ──────────────────────────────────────────────────────
async def _health_check_models() -> None:
    alive = [m for m in _model_chain if m not in _model_dead
             and _has_api_key(_resolve_provider(m))]
    if not alive:
        if _model_chain:
            log.warning("Health check: no models have API keys configured")
        return

    async def probe(model_id: str) -> tuple[str, bool, str]:
        provider = _resolve_provider(model_id)
        model_name = _strip_provider(model_id)
        api_key = _get_api_key(provider)
        base_url = _get_base_url(provider)
        if not api_key or not base_url:
            return model_id, False, "no key/base_url"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{base_url.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={
                        "model": model_name,
                        "max_tokens": 8,
                        "messages": [{"role": "user", "content": "ok"}],
                    },
                )
            code = resp.status_code
            if code == 200:
                return model_id, True, ""
            if code in (402, 429) or 500 <= code < 600:
                return model_id, True, f"HTTP {code} (transient)"
            return model_id, False, f"HTTP {code}"
        except httpx.TimeoutException:
            return model_id, True, "timeout (transient)"
        except Exception as exc:
            return model_id, True, f"{type(exc).__name__} (transient)"

    results = await asyncio.gather(*(probe(m) for m in alive))
    dead = [(m, r) for m, ok, r in results if not ok]
    alive_healthy = [(m, r) for m, ok, r in results if ok and not r]
    alive_transient = [(m, r) for m, ok, r in results if ok and r]
    for m, _ in dead:
        _model_dead.add(m)
    if dead:
        log.warning("Health check: %d permanently dead — %s", len(dead),
                    "; ".join(f"{m} ({r})" for m, r in dead))
    if alive_transient:
        log.info("Health check: %d alive (transient: %s)", len(alive_healthy),
                 ", ".join(f"{m} {r}" for m, r in alive_transient))
    else:
        log.info("Health check: all %d models alive", len(alive))


async def _run_health_check() -> None:
    try:
        await asyncio.wait_for(_health_check_models(), timeout=60)
    except asyncio.TimeoutError:
        log.warning("Health check timed out — starting server anyway")


# ── Health cache ───────────────────────────────────────────────────────────────
def _save_health_cache() -> None:
    cache = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_chain": list(_model_chain),
        "dead_models": sorted(_model_dead),
    }
    try:
        MODEL_CACHE_FILE.write_text(json.dumps(cache, indent=2))
        log.debug("Saved health cache (%d models, %d dead)",
                  len(cache["model_chain"]), len(cache["dead_models"]))
    except OSError as exc:
        log.warning("Failed to write health cache: %s", exc)


def _load_health_cache() -> bool:
    if not MODEL_CACHE_FILE.exists():
        return False
    try:
        cache = json.loads(MODEL_CACHE_FILE.read_text())
        _model_dead.clear()
        _model_dead.update(cache.get("dead_models", []))
        log.info("Loaded health cache (%d models, %d dead) from %s — %s",
                 len(cache.get("model_chain", [])), len(_model_dead),
                 MODEL_CACHE_FILE, cache.get("timestamp", "?"))
        return True
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Failed to load health cache: %s", exc)
        return False


# ── Output guard (strip LLM reasoning from terminal output) ────────────────
_PROMPT_PATTERN = re.compile(
    r"(^[\w][\w.-]*@[\w][\w.-]*[:/#].*[#$>](?= |$))|"
    r"(^[\w][\w.-]*@[\w][\w.-]*>(?= |$))|"
    r"(^[\w][\w.-]* ?[#>] ?$)"
)
_REASONING_PATTERNS = re.compile(
    r"^(# |## |\* |- |"
    r"['\u2019]m (really|concerned|sorry|glad|sure|not|just|going|unable|afraid)"
    r"|We (are|need|should|must|can|would|could|have|had|do|did|shall|may|might)"
    r"|I(( |['\u2019]))(am|'?ll|will|think|should|need|must|would|could|have|had|"
    r"do|did|shall|may|might|"
    r"m (really|concerned|sorry|not|going|unable|afraid|programmed|limited|Claude|an AI)|"
    r"cannot|can't|won't|apologize|detect|can see|don't think|refuse)"
    r"|You( |['\u2019])(are|deserve|matter|should|need|must|can|re asking|'re asking)"
    r"|Your (safety|wellbeing|life|feelings|health|session|activity)"
    r"|The (user|command|prompt|system|attacker|input|output|message|above|below|"
    r"following|best|most|first|next|previous)"
    r"|Note:|However|But (we|I|the|this|that|if|in|on|at)"
    r"|As an AI|As a |My purpose|My (role|training|guidelines|rules)"
    r"|Let me|Let's "
    r"|This is |These are |That is |That's |That "
    r"|Thus[,:]? |Hence[,:]? |Therefore[,:]? |So[,:]? "
    r"|Make sure|Be sure|Remember|Keep in mind"
    r"|Alternatively[,:]? |In other words[,:]? |To clarify"
    r"|The correct|The proper|The expected"
    r"|If you('re| are| feel| ever| need)"
    r"|Please (consider|reach|call|text|visit|look|seek|know|contact)"
    r"|First[,:]? (I|let|we|the|this|that|the user|of all|of many)"
    r"|Okay[,:]? let |Ok[,:]? let"
    r"|Alright[,:]? |Actually[,:]? |After reviewing|Going to "
    r"|Thinking about|Hold on[,:]? |Re-?evaluating|For reference"
    r"|From the context|Given the |Based on the "
    r"|I'?ll (respond|produce|generate|output|simulate|make|need|try"
    r"|not|never)"
    r"|For security reasons|For safety reasons"
    r"|Wait[,:]? (that|let|I )"
    r"|Considering the |Looking at the "
    r"|Important[:]? |Disclaimer[:]? |Heads up[:]? |FYI[:]? "
    r"|Step \d+[:]? |Now (I|we|let)"
    r"|Sorry[,:]? "
    r"|Denied for |Not going to "
    r"|Can't comply|Cannot comply|won't comply|cannot process|cannot assist"
    r"|That (goes|command|request|instruction|sounds|seems|would|could|type|kind|"
    r"would be|is (beyond|outside|against))"
    r"|(prevent|require|refuse) me "
    r"|guidelines require|policies prevent|training prevents"
    r"|Thank you|Thanks for|I appreciate|I'd like|I understand|I hope "
    r"|While I |I (exist|was|am (programmed|limited|designed|not)|"
    r"was not designed|must decline|refuse|hope)"
    r"|This (type|kind|command|request|would|should|is not|goes|is (beyond|outside|against))"
    r"|A (good|realistic|typical|safe|better|proper|correct) (approach|response|way)"
    r"|The (safest|typical|appropriate|best|correct|proper) (response|way|approach|output)"
    r"|One option|Here's what|If this were|What I should |An appropriate"
    r"|It would be (best|better|appropriate|safer)"
    r"|Error: (I|this|the|an|that|a )"
    r"|(unethical|beyond my|outside my|not capable|not designed|"
    r"not able to|not programmed|not possible|not appropriate)"
    r"|(helpful, harmless|exist to help|designed to be|programmed to be)"
    r"|Cannot do |Absolutely not|Unacceptable"
    r"|Since (the|we|I|this|that|it|you|there|our|your|/root|the user)"
    r"|What (would|should|could|is|are|does|do|if|about|if |kind|type|good)"
    r"|But (note|wait|first|keep|most|perhaps|unfortunately)"
    r"|In (the|this|a |many|most|some|my|our|your|order|/root|contrast|"
    r"general|fact|practice|reality|short|other|any|absence|response|"
    r"terms|addition|conclusion|summary|my experience)"
    r"|For (now|the|this|these|example|instance|reference|context|clarity|"
    r"security|safety|privacy|compliance|consistency|simplicity|brevity|"
    r"most|some|a |an |any|each|every|this purpose)"
    r"|Given (the|that|this|what|we|I|our|how|its|it's)"
    r"|Without (the|a |any|this|that|these|those|its|their|much|further|"
    r"proper|proper|going|getting|having|being|doing)"
    r"|Also (maybe|note|consider|keep|remember|think|there|it|we|I|this|that)"
    r"|A (common|simple|basic|quick|realistic|good|better|typical|fair|"
    r"proper|correct|safe|safer|more|lot|bit|few|key|great|"
    r"reasonable|useful|helpful|standard)"
    r"|Whether (the|this|that|it|we|I|you|they|or)"
    r"|To (answer|respond|handle|deal|address|resolve|be|do|make|get|provide|"
    r"keep|avoid|ensure|determine|decide|check|verify|confirm|"
    r"start|begin|continue|simulate|emulate|mimic)"
    r")",
    re.IGNORECASE
)

_NON_BASH_PATTERNS = re.compile(
    r"\b988\b|\b911\b|\b741741\b|"
    r"\b1[-.\s]?800[-.\s]?\d{3}[-.\s]?\d{4}\b|"
    r"\b1\(\d{3}\)\d{3}-?\w{4}\b|"
    r"\b\d{3}[-.]\d{3}[-.]\d{4}\b(?<!\.\d{3})|"
    r"\bwww\.\w+\.\w+|"
    r"\w*(crisis|suicide|helpline|lifeline|988)\w*\.(org|com|net|gov|info)\b|"
    r"National Suicide|crisis line|suicide prevention|"
    r"you are not alone|your life matters|"
    r"International Association|Befrienders|Psychology Today|"
    r"emergency department|emergency services|"
    r"professional (help|assistance)|"
    r"healthcare provider|mental health professional|crisis counselor|crisis lifeline|"
    r"help is available|24 hours a day|7 days a week|"
    r"support is available|speak with a |talk to someone|"
    r"reach out to a|contact a (mental|healthcare|crisis)|"
    r"system is monitored|session is being (recorded|monitored|logged)|"
    r"unauthorized access|not permitted|denied for safety|"
    r"violates (my|our|safety|security|its|the|these)|"
    r"goes against (my|our|my core|my safety|our safety)|"
    r"(prevent|require) me from|refuse (harmful|dangerous|this|that)|"
    r"(my|our) (guidelines|policies|safety|training|rules|purpose|core)|"
    r"flagged for (review|monitoring)|interaction has been|"
    r"jailbreak|trick me|breaking my rules|"
    r"No puedo|Je ne peux|Ich kann|Non posso|Lo siento|Tut mir leid|"
    r"Maaf, saya|saya tidak bisa|saya tidak dapat|"
    r"申し訳ありません|対応できません|"
    r"对不起|无法处理|"
    r"Не могу|не могу выполнить|"
    r"c4n't|c4nn0t|s0rry|n0t p0ss1bl3|d3n13d|h3lp|th4t|th1s|c0mply|"
    r"r34s0n",
    re.IGNORECASE
)

def _is_bash_output(text: str) -> bool:
    """Return False if the LLM response is clearly not terminal output (safety override)."""
    if not text or len(text) < 2:
        return True
    return not _NON_BASH_PATTERNS.search(text)


def _is_reasoning_line(line: str) -> bool:
    """Return True if *line* looks like LLM meta-commentary, not terminal output."""
    sl = line.strip()
    if not sl or len(sl) < 8:
        return False
    if _REASONING_PATTERNS.match(sl):
        return True
    if sl.startswith("`") and sl.endswith("`"):
        return True
    if sl.count("```") >= 2:
        return True
    return False


def _parse_json_line(line: str) -> str | bytes | None:
    """Parse a JSON Lines output line.

    Returns:
      str   — text output from {"t":"..."}
      bytes — binary output from {"b":"<base64>"}
      None  — discard (not valid JSON or unexpected format)
    """
    sl = line.strip()
    if not sl:
        return None
    try:
        obj = json.loads(sl)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or len(obj) != 1:
        return None
    if "t" in obj:
        if isinstance(obj["t"], str):
            return obj["t"]
    if "b" in obj:
        if isinstance(obj["b"], str):
            try:
                return base64.b64decode(obj["b"])
            except Exception:
                return None
    return None


# ── SSH session ───────────────────────────────────────────────────────────────
_active: int = 0


class ShellSession(asyncssh.SSHServerSession):

    def __init__(self, sid: str, peer: str, username: str, persona: Persona,
                 password: str = "", sessions_dir: Path = DEFAULT_SESSIONS_DIR):
        self.sid      = sid
        self.peer     = peer
        self.username = username
        self.password = password
        self.persona  = persona
        self.history: list[dict] = []
        self.cmds:    list[dict] = []
        self.ttps:    list[dict] = []
        self._chan    = None
        self._buf     = ""
        self._t0      = time.time()
        self._t0_iso  = datetime.now(timezone.utc).isoformat()
        self._ps      = PromptState(persona, username)
        self._sdir    = sessions_dir

    def connection_made(self, chan):
        self._chan    = chan
        self._is_exec = False
        self._exec_cmd = ""
        self._has_pty = False

    def shell_requested(self) -> bool:
        return True

    def pty_requested(self, term_type, term_size, term_modes):
        term_modes[53] = 0  # ECHO = opcode 53 — disable client-side echo
        self._has_pty = True
        return True

    def exec_requested(self, command: str) -> bool:
        self._is_exec = True
        self._exec_cmd = command
        return True

    def session_started(self) -> None:
        log.info("session_started called, is_exec=%s", self._is_exec)
        last_login = _fake_last_login()
        banner     = render_banner(self.persona, self.username, last_login)
        self._chan.write(banner)
        if self._is_exec:
            asyncio.ensure_future(self._dispatch(self._exec_cmd, is_exec=True))
        else:
            self._chan.write(self._ps.current())

    def data_received(self, data, datatype):
        for ch in data:
            if ch in ("\r", "\n"):
                cmd = self._buf.strip()
                log.info("TRACE data_received: enter  cmd=%r buf_before=%r", cmd, self._buf)
                self._buf = ""
                if not self._has_pty:
                    self._chan.write("\r\n")
                if cmd:
                    asyncio.ensure_future(self._dispatch(cmd))
                else:
                    self._chan.write(self._ps.current())
            elif ch == "\x7f":
                if self._buf:
                    self._buf = self._buf[:-1]
            elif ch == "\x03":
                self._buf = ""
                self._chan.write("^C\r\n" + self._ps.current())
            elif ch == "\x04":
                self._chan.write("logout\r\n")
                self._chan.close()
            elif ch >= " " or ch == "\t":
                self._buf += ch

    async def _dispatch(self, cmd: str, is_exec: bool = False):
        if time.time() - self._t0 > SESSION_TIMEOUT:
            self._chan.write("Connection timed out.\r\n")
            self._chan.close()
            return

        ts   = datetime.now(timezone.utc).isoformat()
        ttps = classify_ttps(cmd)
        urls = extract_urls(cmd)

        for t in ttps:
            icon = SEV_COLOR.get(t["severity"], "⚪")
            log.warning("%s TTP [%s] %s — %s@%s — %s",
                        icon, t["mitre"], t["label"],
                        self.username, self.peer, cmd)

        for url in urls:
            asyncio.ensure_future(quarantine_url(url, self.sid, self.peer))

        jlog({"event": "cmd", "sid": self.sid, "peer": self.peer,
              "user": self.username, "persona": self.persona.id,
              "ts": ts, "cmd": cmd, "ttps": ttps, "urls": urls})

        self.ttps.extend(ttps)
        self.cmds.append({"ts": ts, "cmd": cmd, "ttps": ttps})

        self._ps.advance(cmd)

        self._strip_echo = cmd.strip()
        self._llm_buf = ""

        def _write_chunk(text):
            log.info("TRACE _write_chunk: enters  text=%r strip_echo=%r", text, getattr(self, "_strip_echo", ""))
            # Phase 1: strip command echo (defense in depth)
            rem = getattr(self, "_strip_echo", "")
            if rem:
                all_matched = True
                for i, ch in enumerate(text):
                    if rem and ch == rem[0]:
                        rem = rem[1:]
                    else:
                        all_matched = False
                        rem = ""
                        text = text[i:]
                        break
                self._strip_echo = rem
                if not text:
                    log.info("TRACE _write_chunk: text emptied by echo strip — return")
                    return
                if all_matched:
                    log.info("TRACE _write_chunk: all matched echo — return")
                    return
                log.info("TRACE _write_chunk: echo strip done  remaining=%r strip_echo=%r", text, rem)
            # Phase 2: JSON Lines parsing + line-level guards
            self._llm_buf += text
            while "\n" in self._llm_buf:
                line, self._llm_buf = self._llm_buf.split("\n", 1)
                # Try JSON parsing first
                parsed = _parse_json_line(line)
                if parsed is not None:
                    if isinstance(parsed, str):
                        if parsed.strip() == getattr(self, "_strip_echo", ""):
                            continue
                        if _PROMPT_PATTERN.match(parsed.strip()):
                            continue
                        log.info("TRACE _write_chunk: write  line=%r  (from JSON)", parsed)
                        self._chan.write(parsed + "\r\n")
                    else:
                        self._chan.write(parsed)
                    continue
                # Fallback: old-style guards for non-JSON output
                if _is_reasoning_line(line):
                    continue
                if _PROMPT_PATTERN.match(line.strip()):
                    continue
                if not _is_bash_output(line):
                    continue
                log.info("TRACE _write_chunk: write  line=%r  (fallback)", line)
                self._chan.write(line + "\r\n")

        output = await llm_shell(self.history, cmd, self.persona.system_prompt,
                                 on_chunk=_write_chunk)
        log.info("TRACE _dispatch: raw output=%r", output)
        # Flush remaining buffered text (incomplete trailing line)
        if self._llm_buf:
            rest = self._llm_buf.strip()
            log.info("TRACE _dispatch: flush buf=%r", self._llm_buf)
            if rest:
                parsed = _parse_json_line(rest)
                if isinstance(parsed, str) and parsed.strip():
                    if not _PROMPT_PATTERN.match(parsed.strip()):
                        self._chan.write(parsed + "\r\n")
                elif parsed is None:
                    if not _is_reasoning_line(rest) and not _PROMPT_PATTERN.match(rest):
                        self._chan.write(self._llm_buf.replace("\n", "\r\n"))
        self._llm_buf = ""
        self._strip_echo = ""
        # Post-hoc: strip command echo from the full response
        cmd_stripped = cmd.strip()
        if output.startswith(cmd_stripped):
            output = output[len(cmd_stripped):].lstrip("\r\n ")
        # Guard: if the LLM broke character (safety override, prose, etc.),
        # replace with static fallback
        if output and not _is_bash_output(output):
            log.warning("Guard: LLM broke character, falling back to static — cmd=%r", cmd)
            output = _static_fallback(cmd)
        self.cmds[-1]["response"] = output
        if not is_exec:
            if output and not output.endswith("\n"):
                self._chan.write("\r\n")
            self._chan.write(self._ps.current())

        log.info("EXEC-DEBUG: closing chan, output_len=%d", len(output))
        if cmd.strip() in ("exit", "logout", "quit") or is_exec:
            log.info("EXEC-DEBUG: calling close()")
            self._chan.close()

    def _save_session(self, dur: float, narrative: str) -> None:
        self._sdir.mkdir(exist_ok=True)
        ts_end = datetime.now(timezone.utc).isoformat()
        data = {
            "session_id":  self.sid,
            "peer":        self.peer,
            "username":    self.username,
            "password":    self.password,
            "persona":     self.persona.id,
            "connected_at": self._t0_iso,
            "ended_at":    ts_end,
            "duration_s":  dur,
            "cmd_count":   len(self.cmds),
            "ttp_count":   len(self.ttps),
            "unique_ttps": list({t["mitre"] for t in self.ttps}),
            "narrative":   narrative,
            "commands":    self.cmds,
        }
        sess_file = self._sdir / f"{self.sid}.json"
        sess_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def connection_lost(self, exc):
        global _active
        _active = max(0, _active - 1)
        dur = round(time.time() - self._t0, 1)

        narrative = _build_narrative(self.cmds, self.peer, self.username, dur)
        self._save_session(dur, narrative)

        record = {
            "event":       "session_end",
            "sid":         self.sid,
            "peer":        self.peer,
            "user":        self.username,
            "persona":     self.persona.id,
            "duration_s":  dur,
            "cmd_count":   len(self.cmds),
            "ttp_count":   len(self.ttps),
            "unique_ttps": list({t["mitre"] for t in self.ttps}),
            "narrative":   narrative,
            "ts":          datetime.now(timezone.utc).isoformat(),
        }
        jlog(record)
        log.info("Session %s [%s] closed — %d cmds, %d TTPs, %.0fs",
                 self.sid[:8], self.persona.id,
                 len(self.cmds), len(self.ttps), dur)
        if narrative:
            log.info("📋 Attack narrative: %s", narrative)


# ── Attack narrative ──────────────────────────────────────────────────────────
def _build_narrative(cmds: list[dict], peer: str, user: str, dur: float) -> str:
    if not cmds:
        return "No commands issued."
    all_ttps = {t["label"] for c in cmds for t in c.get("ttps", [])}
    all_cmds = [c["cmd"] for c in cmds]
    phases   = []

    if any(re.search(r'\b(id|whoami|uname|hostname|cat /etc/passwd|show version)', c)
           for c in all_cmds):
        phases.append("Recon")
    if any(re.search(r'(wget|curl)', c, re.I) for c in all_cmds):
        phases.append("Tool download")
    if any(re.search(r'chmod\s+\+x', c, re.I) for c in all_cmds):
        phases.append("Staged execution")
    if "Scheduled Task/Job" in all_ttps or "Create/Modify System Process" in all_ttps:
        phases.append("Persistence")
    if "Resource Hijacking" in all_ttps:
        phases.append("Crypto-mining")
    if "OS Credential Dumping" in all_ttps:
        phases.append("Credential access")
    if "Account Manipulation" in all_ttps:
        phases.append("Backdoor account")
    if "Config Disclosure" in all_ttps or "Config Exfiltration via TFTP" in all_ttps:
        phases.append("Config exfiltration")
    if "Crypto Key Exposure" in all_ttps:
        phases.append("Crypto key theft")

    phase_str = " → ".join(phases) if phases else "Exploration"
    return (f"{peer} ({user}) | {len(cmds)} cmds over {dur:.0f}s | "
            f"Kill chain: {phase_str}")


def _fake_last_login() -> str:
    days   = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
    months = ["Jan","Feb","Mar","Apr","May","Jun",
              "Jul","Aug","Sep","Oct","Nov","Dec"]
    ip = (f"185.{random.randint(100,220)}.{random.randint(1,254)}"
          f".{random.randint(1,254)}")
    return (f"{random.choice(days)} {random.choice(months)} {random.randint(1,28):2d} "
            f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} "
            f"2025 from {ip}")


# ── SSH server ────────────────────────────────────────────────────────────────
class HoneypotServer(asyncssh.SSHServer):

    def connection_made(self, conn):
        global _active
        peer       = conn.get_extra_info("peername", ("?", 0))
        self._peer = f"{peer[0]}:{peer[1]}"
        self._sid  = str(uuid.uuid4())
        self._user = "unknown"
        self._password = ""
        self._conn  = conn
        # Assign persona at connection time (before auth, so same persona
        # persists for the whole session regardless of supplied username)
        self._persona = pick_persona()
        if _active >= MAX_SESSIONS:
            log.warning("Session cap reached, dropping %s", self._peer)
            conn.abort()
            return
        _active += 1
        log.info("CONNECT %s [%s] persona=%s",
                 self._peer, self._sid[:8], self._persona.id)
        jlog({"event": "connect", "sid": self._sid, "peer": self._peer,
              "persona": self._persona.id,
              "ts": datetime.now(timezone.utc).isoformat()})

    def connection_lost(self, exc):
        pass

    def begin_auth(self, username):
        self._user = username
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self._password = password
        log.info("AUTH  user=%-12s pass=%s  from %s  [%s]",
                 username, password, self._peer, self._persona.id)
        jlog({"event": "auth", "sid": self._sid, "peer": self._peer,
              "user": username, "password": password,
              "persona": self._persona.id,
              "ts": datetime.now(timezone.utc).isoformat()})
        return True

    def public_key_auth_supported(self):
        return False

    def session_requested(self):
        return ShellSession(self._sid, self._peer, self._user, self._persona,
                            password=self._password, sessions_dir=_sessions_dir)


# ── Host key ──────────────────────────────────────────────────────────────────
def ensure_host_key():
    if not SSH_KEY_FILE.exists():
        log.info("Generating RSA host key → %s", SSH_KEY_FILE)
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(str(SSH_KEY_FILE))


# ── Main ──────────────────────────────────────────────────────────────────────
async def run(port: int):
    ensure_host_key()
    server = await asyncssh.create_server(
        HoneypotServer,
        host="0.0.0.0",
        port=port,
        server_host_keys=[str(SSH_KEY_FILE)],
        login_timeout=30,
        keepalive_interval=60,
    )
    log.info("🍯  Honeypot listening on 0.0.0.0:%d", port)
    log.info("📄  Session log     → %s", _log_file)
    log.info("📁  Per-session dir → %s", _sessions_dir)
    log.info("🗂   Quarantine dir  → %s", _quarantine_dir)
    log.info("🎭  Persona mode    → %s", _selected_persona)
    log.info("🤖  Model chain     → %s", _model_chain)
    if not alive_models():
        log.warning("⚠️   No API keys configured — static fallback only")
    async with server:
        await asyncio.Future()


def main():
    global _log_file, _quarantine_dir, _sessions_dir, _selected_persona, _model_chain, _override_base, _override_key
    global _auto_discover
    p = argparse.ArgumentParser(description="LLM SSH Honeypot")
    p.add_argument("--port",        type=int,  default=DEFAULT_PORT)
    p.add_argument("--log",         type=Path, default=DEFAULT_LOG)
    p.add_argument("--quarantine",  type=Path, default=DEFAULT_QUARANTINE)
    p.add_argument("--sessions-dir", type=Path, default=DEFAULT_SESSIONS_DIR,
                   help="Directory for per-session JSON files (default: ./sessions)")
    p.add_argument(
        "--persona",
        default="random",
        choices=list(ALL_PERSONAS.keys()) + ["random"],
        help="Persona to simulate (default: random per connection)",
    )
    p.add_argument("--api-base",    default=None,
                   help="Override base URL for ALL models in the chain (default: per-provider)")
    p.add_argument("--model",       action="append", dest="model_override",
                   help="Model ID (provider:name). Repeat for fallback chain. "
                        "(default: free OpenRouter models)")
    p.add_argument("--api-key",     default=None,
                   help="API key override for ALL models in the chain")
    p.add_argument("--auto-discover", action="store_true", default=False,
                   help="Auto-discover free models from OpenRouter on startup")
    args = p.parse_args()
    _log_file        = args.log
    _quarantine_dir  = args.quarantine
    _sessions_dir    = args.sessions_dir
    _selected_persona = args.persona
    _auto_discover   = args.auto_discover
    if args.api_key:
        _override_key = args.api_key
    if args.api_base:
        _override_base = args.api_base
    if args.model_override:
        _model_chain = args.model_override
    try:
        async def _startup():
            if _auto_discover:
                fetched = await _fetch_free_models()
                if fetched:
                    _model_chain[:] = fetched
                    log.info("Model chain replaced with %d auto-discovered free models", len(fetched))
            if not _load_health_cache():
                await _run_health_check()
                _save_health_cache()
        asyncio.run(_startup())
        asyncio.run(run(args.port))
    except KeyboardInterrupt:
        log.info("Stopped.")


if __name__ == "__main__":
    main()

