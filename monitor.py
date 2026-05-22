#!/usr/bin/env python3
"""
Honeypot Monitor — TTP dashboard with quarantine viewer and attack timelines.

Usage:
    python monitor.py [--log sessions.jsonl] [--quarantine ./quarantine] [--watch]
"""

import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── ANSI ──────────────────────────────────────────────────────────────────────
R   = "\033[0m";  B  = "\033[1m";  DIM = "\033[2m"
RED = "\033[31m"; YEL= "\033[33m"; GRN = "\033[32m"
CYN = "\033[36m"; MAG= "\033[35m"; BLU = "\033[34m"
WHT = "\033[97m"; ORG= "\033[38;5;208m"

SEV_COLOR = {
    "CRIT": f"{RED}{B}CRIT{R}",
    "HIGH": f"{ORG}HIGH{R}",
    "MED":  f"{YEL} MED{R}",
    "LOW":  f"{GRN} LOW{R}",
}
SEV_ICON = {"CRIT": "🔴", "HIGH": "🟠", "MED": "🟡", "LOW": "🟢"}
SEV_RANK = {"LOW": 0, "MED": 1, "HIGH": 2, "CRIT": 3}

# Inline MITRE mapping (label → ID) — mirrors honeypot.py TTP_PATTERNS
MITRE_MAP = {
    "Ingress Tool Transfer":         "T1105",
    "File Permission Modification":  "T1222",
    "Scheduled Task/Job":            "T1053",
    "Create Account":                "T1136",
    "Account Manipulation":          "T1098",
    "OS Credential Dumping":         "T1003",
    "Command & Scripting: Netcat":   "T1059",
    "Deobfuscate/Decode":            "T1140",
    "Resource Hijacking":            "T1496",
    "Unsecured Credentials":         "T1552",
    "Impair Defenses":               "T1562",
    "Indicator Removal":             "T1070",
    "Data from Local System":        "T1005",
    "Command & Scripting: Interp":   "T1059",
    "Create/Modify System Process":  "T1543",
    "Masquerading":                  "T1036",
    "Remote Services: SSH":          "T1021",
    "Data Staged for Exfil":         "T1005",
    "Obfuscated Files/Info":         "T1027",
}

W = 82

def cl(color, s):  return f"{color}{s}{R}"
def bold(s):       return f"{B}{s}{R}"
def hr(ch="─"):    return cl(DIM, ch * W)

def box_top(title):
    inner = f"[ {title} ]"
    pad   = (W - len(inner) - 2) // 2
    right = W - 2 - pad - len(inner)
    print(cl(YEL, "┌" + "─"*pad + inner + "─"*right + "┐"))

def box_bot():
    print(cl(YEL, "└" + "─"*(W-2) + "┘"))

def row(s):
    print(f"  {s}")

def pbar(val, total, width=28, color=GRN):
    filled = int(width * val / total) if total else 0
    return cl(color, "█"*filled) + cl(DIM, "░"*(width-filled))

# ── Load & analyse ────────────────────────────────────────────────────────────
def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def analyse(rows: list[dict]) -> dict:
    connects   = [r for r in rows if r["event"] == "connect"]
    auths      = [r for r in rows if r["event"] == "auth"]
    cmds       = [r for r in rows if r["event"] == "cmd"]
    ends       = [r for r in rows if r["event"] == "session_end"]
    quarantine = [r for r in rows if r["event"] == "quarantine"]

    unique_ips  = {r["peer"].rsplit(":", 1)[0] for r in connects}
    cred_pairs  = Counter((r["user"], r["password"]) for r in auths)
    cmd_counter = Counter(
        r["cmd"].strip().split()[0] for r in cmds if r["cmd"].strip()
    )
    full_cmds   = Counter(r["cmd"].strip() for r in cmds)

    # TTP aggregation
    ttp_counter:   Counter = Counter()
    sev_counter:   Counter = Counter()

    for r in cmds:
        for t in r.get("ttps", []):
            ttp_counter[t["label"]] += 1
            sev_counter[t["severity"]] += 1

    # URL captures
    urls_seen: Counter = Counter()
    for r in cmds:
        for u in r.get("urls", []):
            urls_seen[u] += 1

    # Session narratives
    narratives = [
        (r.get("narrative", ""), r.get("peer", ""), r.get("duration_s", 0))
        for r in ends if r.get("narrative")
    ]

    durations = [r["duration_s"] for r in ends if "duration_s" in r]
    avg_dur   = sum(durations) / len(durations) if durations else 0
    max_dur   = max(durations) if durations else 0

    recent_events = sorted(
        [r for r in rows if r["event"] in ("connect", "auth", "cmd")],
        key=lambda x: x.get("ts", ""),
        reverse=True,
    )[:18]

    return dict(
        total_connects = len(connects),
        unique_ips     = len(unique_ips),
        total_auths    = len(auths),
        total_cmds     = len(cmds),
        total_sessions = len(ends),
        avg_dur        = avg_dur,
        max_dur        = max_dur,
        top_creds      = cred_pairs.most_common(6),
        top_binaries   = cmd_counter.most_common(14),
        top_full_cmds  = full_cmds.most_common(8),
        ttp_counter    = ttp_counter,
        sev_counter    = sev_counter,
        urls_seen      = urls_seen,
        narratives     = narratives,
        quarantine     = quarantine,
        recent_events  = recent_events,
    )


# ── Render ────────────────────────────────────────────────────────────────────
def render(a: dict, log_file: Path, q_dir: Path):
    print("\033[2J\033[H", end="")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print()
    print(bold(cl(YEL, "  🍯  LLM SSH HONEYPOT  ·  THREAT INTELLIGENCE DASHBOARD")))
    print(cl(DIM, f"  {log_file}  ·  {now}"))
    print()

    # ── Overview ──────────────────────────────────────────────────────────────
    box_top("OVERVIEW")
    stats = [
        ("Connections",   str(a["total_connects"]), CYN),
        ("Unique IPs",    str(a["unique_ips"]),      MAG),
        ("Auth attempts", str(a["total_auths"]),     YEL),
        ("Commands",      str(a["total_cmds"]),      GRN),
        ("Avg session",   f"{a['avg_dur']:.0f}s",   BLU),
        ("Max session",   f"{a['max_dur']:.0f}s",   ORG),
    ]
    print("  " + "   ".join(f"{cl(col,bold(v))} {cl(DIM,lbl)}" for lbl,v,col in stats))
    box_bot()
    print()

    # ── Severity summary ──────────────────────────────────────────────────────
    sv = a["sev_counter"]
    if sv:
        box_top("ALERT SEVERITY")
        total_sv = sum(sv.values()) or 1
        for sev in ("CRIT", "HIGH", "MED", "LOW"):
            n = sv.get(sev, 0)
            if n:
                row(f"{SEV_ICON[sev]} {SEV_COLOR[sev]}  {pbar(n, total_sv, 24)}  {cl(WHT, str(n))}")
        box_bot()
        print()

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    if a["ttp_counter"]:
        box_top("MITRE ATT&CK  (top techniques)")
        total_t = sum(a["ttp_counter"].values()) or 1
        for label, count in a["ttp_counter"].most_common(10):
            mid = MITRE_MAP.get(label, "      ")
            bar = pbar(count, total_t, 20, RED)
            row(f"{cl(DIM,f'{mid:<7}')} {cl(WHT,f'{label:<36}')} {bar}  {cl(YEL,str(count))}")
        box_bot()
        print()

    # ── Captured URLs / quarantine ────────────────────────────────────────────
    if a["urls_seen"]:
        box_top("CAPTURED PAYLOAD URLs")
        for url, n in a["urls_seen"].most_common(8):
            trunc = (url[:68] + "…") if len(url) > 69 else url
            row(f"{cl(YEL,f'{n:>3}x')}  {cl(RED, trunc)}")
        if q_dir.exists():
            qfiles = sorted(
                q_dir.glob("*.meta.json"),
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            )[:4]
            if qfiles:
                row(cl(DIM, "── quarantined samples ──"))
                for qf in qfiles:
                    try:
                        m   = json.loads(qf.read_text())
                        sz  = m.get("size", "?")
                        ct  = m.get("content_type", "")[:28]
                        st  = m.get("status", "?")
                        url = m.get("url", "")[:52]
                        row(f"  {cl(GRN,'saved')}  HTTP {st}  {sz}B  {cl(DIM,ct)}  {cl(CYN,url)}")
                    except Exception:
                        pass
        box_bot()
        print()

    # ── Top credentials ───────────────────────────────────────────────────────
    box_top("TOP CREDENTIAL ATTEMPTS")
    row(f"{cl(DIM,'USERNAME'):<30}{cl(DIM,'PASSWORD'):<30}{cl(DIM,'COUNT')}")
    row(hr("·"))
    for (u, p), n in a["top_creds"]:
        row(f"{cl(CYN,f'{u:<28}')} {cl(MAG,f'{p:<28}')} {cl(YEL,str(n))}")
    box_bot()
    print()

    # ── Top commands ──────────────────────────────────────────────────────────
    box_top("TOP COMMANDS")
    total_c = sum(cnt for _, cnt in a["top_binaries"]) or 1
    for cmd, count in a["top_binaries"][:10]:
        row(f"{cl(WHT,f'{cmd:<22}')}{pbar(count, total_c, 20, GRN)}  {cl(GRN,str(count))}")
    box_bot()
    print()

    # ── Attack narratives ─────────────────────────────────────────────────────
    if a["narratives"]:
        box_top("ATTACK NARRATIVES  (kill chain per session)")
        for narr, peer, dur in a["narratives"][-7:]:
            trunc = (narr[:76] + "…") if len(narr) > 77 else narr
            row(cl(DIM, trunc))
        box_bot()
        print()

    # ── Live feed ─────────────────────────────────────────────────────────────
    box_top("LIVE FEED")
    for r in a["recent_events"][:14]:
        ts     = r.get("ts", "")
        ts_fmt = ts[11:19] if len(ts) >= 19 else "        "
        ev     = r["event"]
        ip     = r.get("peer", "").rsplit(":", 1)[0]
        ttps   = r.get("ttps", [])

        ttp_tag = ""
        if ttps:
            worst = max(ttps, key=lambda t: SEV_RANK.get(t["severity"], 0))
            ttp_tag = f"  {SEV_ICON[worst['severity']]} {cl(DIM, worst['label'])}"

        if ev == "connect":
            msg = f"{cl(BLU,'CONNECT')}  {cl(WHT, ip)}"
        elif ev == "auth":
            msg = (f"{cl(YEL,'AUTH   ')}  {cl(CYN, ip):<22} "
                   f"{cl(MAG, r.get('user',''))}:{cl(ORG, r.get('password',''))}")
        else:
            cmd   = r.get("cmd", "")
            trunc = (cmd[:46] + "…") if len(cmd) > 47 else cmd
            msg   = f"{cl(GRN,'CMD    ')}  {cl(CYN, ip):<22} {cl(WHT, trunc)}{ttp_tag}"

        row(f"{cl(DIM, ts_fmt)}  {msg}")
    box_bot()
    print()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="Honeypot monitor")
    p.add_argument("--log",        type=Path, default=Path("sessions.jsonl"))
    p.add_argument("--quarantine", type=Path, default=Path("quarantine"))
    p.add_argument("--watch",      action="store_true", help="Refresh every 5s")
    args = p.parse_args()
    try:
        while True:
            rows = load(args.log)
            a    = analyse(rows)
            render(a, args.log, args.quarantine)
            if not args.watch:
                break
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
