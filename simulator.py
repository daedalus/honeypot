"""Quarantined-file analysis & execution simulation.

Exports
  quarantine_dir  — set by honeypot startup (Path)
  llm_ask         — set by honeypot startup (async fn(msg: list[dict]) -> str)
  analyze_file()  — fire-and-forget analysis → .sim.json
  simulate_exec() — lookup sim-pack by command filename, return output or None
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path

import vt

log = logging.getLogger("simulator")

quarantine_dir: Path | None = None
llm_ask = None  # set externally: async fn(messages) -> str

# ── VirusTotal ─────────────────────────────────────────────────────────────────
_VT_API_KEY = os.environ.get("VT_API_KEY") or ""
_VT_UPLOAD_LIMIT = 32 * 1024 * 1024  # 32 MB
_VT_RATE_LIMIT = 3  # requests per window
_VT_RATE_WINDOW = 61  # seconds (free tier: 4/min, we use 3/61s to be safe)
_vt_reqs: list[float] = []  # timestamps of recent VT requests


async def _vt_throttle() -> None:
    """Sleep if we've hit the VT rate limit."""
    now = time.monotonic()
    window_start = now - _VT_RATE_WINDOW
    # drop old timestamps
    while _vt_reqs and _vt_reqs[0] < window_start:
        _vt_reqs.pop(0)
    if len(_vt_reqs) >= _VT_RATE_LIMIT:
        sleep_for = _vt_reqs[0] + _VT_RATE_WINDOW - now
        if sleep_for > 0:
            log.info("VT rate limit hit — sleeping %.1fs", sleep_for)
            await asyncio.sleep(sleep_for)
            # retry: drop expired and re-check
            return await _vt_throttle()
    _vt_reqs.append(time.monotonic())


async def _vt_enrich(fhash: str, filepath: Path) -> dict:
    """Query VirusTotal by hash; if not found, upload the binary.

    Returns a dict with VT findings (or empty on error / no key).
    """
    if not _VT_API_KEY:
        return {}

    await _vt_throttle()
    try:
        async with vt.Client(_VT_API_KEY) as client:
            # ── query by hash ───────────────────────────────────────────
            try:
                obj = await client.get_object(f"/files/{fhash}")
            except vt.APIError as e:
                if "NotFoundError" not in str(e):
                    log.warning("VT API error on hash query: %s", e)
                    return {"vt_error": str(e)[:200]}
                # ── not found — upload ──────────────────────────────────
                size = filepath.stat().st_size
                if size > _VT_UPLOAD_LIMIT:
                    return {"vt_error": f"file too large ({size} > {_VT_UPLOAD_LIMIT}B)"}
                await _vt_throttle()
                try:
                    with open(filepath, "rb") as f:
                        analysis = await client.scan_file_async(f, wait_for_completion=True)
                    stats = analysis.get("stats", {}) if hasattr(analysis, "get") else {}
                    log.info("VT upload complete for %s", filepath.name)
                    return {
                        "vt_source": "upload",
                        "vt_stats": stats,
                        "vt_analysis_id": str(getattr(analysis, "id", "")),
                    }
                except Exception as exc:
                    log.warning("VT upload failed for %s: %s", filepath.name, exc)
                    return {"vt_error": f"upload failed: {exc}"}

            # ── hash hit — extract findings ─────────────────────────────
            stats = obj.get("last_analysis_stats", {}) if hasattr(obj, "get") else {}
            results = obj.get("last_analysis_results", {}) if hasattr(obj, "get") else {}
            detections: list[str] = []
            if isinstance(results, dict):
                for engine, r in results.items():
                    if isinstance(r, dict) and r.get("category") == "malicious":
                        detections.append(f"{engine}: {r.get('result', 'malicious')}")

            names = obj.get("names", []) if hasattr(obj, "get") else []
            tags = obj.get("tags", []) if hasattr(obj, "get") else []
            type_desc = obj.get("type_description", "") if hasattr(obj, "get") else ""

            log.info("VT hash hit for %s — %d malicious", filepath.name,
                      stats.get("malicious", 0) if isinstance(stats, dict) else 0)
            return {
                "vt_source": "hash_query",
                "vt_stats": stats,
                "vt_detections": detections[:25],
                "vt_type": type_desc,
                "vt_tags": tags,
                "vt_names": names,
            }
    except Exception as exc:
        log.warning("VT enrichment failed for %s: %s", filepath.name, exc)
        return {"vt_error": str(exc)[:200]}


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

def _build_prompt(data: bytes, fhash: str, fname: str, is_binary: bool,
                  vt_data: dict | None = None) -> str:
    size = len(data)
    vt_section = ""
    if vt_data and vt_data.get("vt_source"):
        parts: list[str] = []
        vt_source = vt_data.get("vt_source", "")
        vt_source = "hash lookup" if vt_source == "hash_query" else vt_source
        parts.append(f"VirusTotal source: {vt_source}")

        stats = vt_data.get("vt_stats")
        if isinstance(stats, dict) and stats:
            parts.append(f"VT detection stats: {json.dumps(stats)}")

        dets = vt_data.get("vt_detections")
        if dets:
            parts.append(f"Top engine detections:\n" + "\n".join(dets[:15]))

        t = vt_data.get("vt_type", "")
        if t:
            parts.append(f"VT type description: {t}")

        tags = vt_data.get("vt_tags")
        if tags:
            parts.append(f"VT tags: {', '.join(tags[:15])}")

        names = vt_data.get("vt_names")
        if names:
            parts.append(f"VT known names: {', '.join(names[:5])}")

        vt_section = "\n\n" + "\n".join(parts)

    if is_binary:
        strings = _extract_strings(data)
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
            f"First 512 bytes (hex):\n{hex_preview}"
            f"{vt_section}\n\n"
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
            f"Content:\n{preview}"
            f"{vt_section}\n\n"
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
    """Analyze a quarantined file: hash, strings, VT enrichment, LLM identify → .sim.json.

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
        "vt": {},
        "label": "pending",
        "reasoning": "",
        "simulated_output": "",
    }

    # VT enrichment (runs whether or not LLM is available)
    if is_binary:
        vt_data = await _vt_enrich(fhash, filepath)
        if vt_data:
            pack["vt"] = vt_data

    if llm_ask:
        prompt = _build_prompt(data, fhash, fname_hint, is_binary, pack.get("vt"))
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
    log.info("SIM %s — %s  VT=%s", fname_hint, pack["label"],
             "yes" if pack.get("vt") else "no")
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
