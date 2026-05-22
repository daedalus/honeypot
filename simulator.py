"""Quarantined-file analysis & execution simulation.

Exports
  quarantine_dir  — set by honeypot startup (Path)
  llm_ask         — set by honeypot startup (async fn(msg: list[dict]) -> str)
  analyze_file()  — fire-and-forget analysis → .sim.json
  simulate_exec() — lookup sim-pack by command filename, return output or None
"""

import hashlib
import json
import logging
from pathlib import Path

log = logging.getLogger("simulator")

quarantine_dir: Path | None = None
llm_ask = None  # set externally: async fn(messages) -> str


# ── helpers ────────────────────────────────────────────────────────────────────

def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _extract_strings(data: bytes, min_len: int = 10) -> list[str]:
    out: list[str] = []
    cur: list[int] = []
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode())
            cur = []
    if len(cur) >= min_len:
        out.append(bytes(cur).decode())
    return out


def _is_binary(data: bytes) -> bool:
    return data[:4] == b"\x7fELF" or b"\x00" in data[:1024]


# ── analysis ───────────────────────────────────────────────────────────────────

def _build_prompt(data: bytes, fhash: str, fname: str, is_binary: bool) -> str:
    size = len(data)
    if is_binary:
        strings = _extract_strings(data)
        # deduplicate and limit
        seen: set[str] = set()
        uniq: list[str] = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        strings_str = json.dumps(uniq[:60], indent=2)
        hex_preview = data[:512].hex()
        return (
            f"You are analyzing a quarantined file ({size} bytes, hash {fhash}) "
            f"downloaded from the internet in a Linux honeypot.\n"
            f"Filename: {fname}\n"
            f"Extracted strings (>=10 chars, first 60):\n{strings_str}\n"
            f"First 512 bytes (hex):\n{hex_preview}\n\n"
            f"1. Identify this binary: architecture, format, purpose (reverse shell, "
            f"scanner, dropper, rootkit, etc.).\n"
            f"2. Describe what its execution would produce on a modern Linux system "
            f"with NO internet access. Be specific — crashes from missing libraries, "
            f"connection failures, permission errors, etc.\n"
            f"3. Provide the exact terminal output (multi-line) that a user would see.\n\n"
            f"Respond ONLY with valid JSON, no markdown:\n"
            f'{{"label":"<10-word summary>",\n'
            f' "reasoning":"<2-3 sentence analysis>",\n'
            f' "simulated_output":"<exact terminal output with \\n for line breaks>"}}'
        )
    else:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        preview = text[:2500]
        return (
            f"You are analyzing a quarantined script ({size} bytes, hash {fhash}) "
            f"downloaded from the internet in a Linux honeypot.\n"
            f"Filename: {fname}\n"
            f"Content:\n{preview}\n\n"
            f"1. Identify this script: language, purpose.\n"
            f"2. Describe what its execution would produce on a modern Linux system "
            f"with NO internet access.\n"
            f"3. Provide the exact terminal output (multi-line) a user would see.\n\n"
            f"Respond ONLY with valid JSON, no markdown:\n"
            f'{{"label":"<10-word summary>",\n'
            f' "reasoning":"<2-3 sentence analysis>",\n'
            f' "simulated_output":"<exact terminal output with \\n for line breaks>"}}'
        )


async def analyze_file(filepath: Path, fname_hint: str) -> dict:
    """Analyze a quarantined file: hash, strings, LLM identify → .sim.json.

    Returns the analysis pack (dict). Safe to call multiple times — skips if
    .sim.json already exists.
    """
    sim_path = filepath.with_name(filepath.name + ".sim.json")
    if sim_path.exists():
        return json.loads(sim_path.read_text())

    data = filepath.read_bytes()
    fhash = _file_hash(filepath)
    is_binary = _is_binary(data)
    kind = "binary" if is_binary else "text"
    pack: dict = {
        "hash": fhash,
        "file": fname_hint,
        "quarantine_file": filepath.name,
        "size": len(data),
        "kind": kind,
        "strings": _extract_strings(data)[:100] if is_binary else [],
        "label": "pending",
        "reasoning": "",
        "simulated_output": "",
    }

    if llm_ask:
        prompt = _build_prompt(data, fhash, fname_hint, is_binary)
        messages = [{"role": "user", "content": prompt}]
        try:
            out = await llm_ask(messages)
        except Exception as exc:
            log.warning("LLM analysis failed for %s: %s", filepath.name, exc)
            out = ""
        try:
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                pack["label"] = str(parsed.get("label") or pack["label"])
                pack["reasoning"] = str(parsed.get("reasoning") or "")
                pack["simulated_output"] = str(parsed.get("simulated_output") or "")
        except (json.JSONDecodeError, TypeError):
            log.warning("LLM returned non-JSON for %s: %.200s", filepath.name, out)

    sim_path.write_text(json.dumps(pack, indent=2, default=str))
    log.info("SIM %s — %s", fname_hint, pack["label"])
    return pack


# ── execution lookup ──────────────────────────────────────────────────────────

def _find_sim_pack(substr: str) -> dict | None:
    """Search quarantine for a .sim.json whose *file* or *quarantine_file* contains *substr*."""
    if not quarantine_dir or not quarantine_dir.exists():
        return None
    for f in quarantine_dir.glob("*.sim.json"):
        try:
            pack = json.loads(f.read_text())
            if substr in pack.get("file", "") or substr in pack.get("quarantine_file", ""):
                return pack
        except (json.JSONDecodeError, OSError):
            continue
    return None


def simulate_exec(cmd: str) -> str | None:
    """Return simulated output if *cmd* references a known quarantined file."""
    tokens = cmd.strip().split()
    if not tokens:
        return None
    fname = tokens[-1].rstrip("/").split("/")[-1]
    if not fname:
        return None
    pack = _find_sim_pack(fname)
    if pack:
        so = pack.get("simulated_output") or ""
        return so if so and so != "pending" else None
    return None
