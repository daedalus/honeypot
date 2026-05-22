#!/usr/bin/env python3
"""Test SSH honeypot auth — in-process server + asyncssh client."""
import asyncio
import logging
import sys
from pathlib import Path

import asyncssh

sys.path.insert(0, str(Path(__file__).parent))
import honeypot  # noqa: E402

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("test_login")
logging.getLogger("asyncssh").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

PORT = 14804


async def test_auth(user: str, password: str) -> tuple[str, str, bool, str]:
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                "127.0.0.1", port=PORT, username=user, password=password,
                known_hosts=None, client_keys=None,
            ),
            timeout=5,
        )
        conn.close()
        return user, password, True, ""
    except asyncssh.PermissionDenied as e:
        return user, password, False, f"PermissionDenied: {e}"
    except asyncio.TimeoutError:
        return user, password, False, "Timeout"
    except Exception as e:
        return user, password, False, f"{type(e).__name__}: {e}"


async def main():
    honeypot._auto_discover = False
    honeypot._model_chain = list(honeypot.DEFAULT_MODEL_CHAIN)

    server_coro = honeypot.run(PORT)
    task = asyncio.create_task(server_coro)
    await asyncio.sleep(3)

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", PORT), timeout=2)
        w.close()
    except (OSError, asyncio.TimeoutError):
        log.error("Server not listening!")
        task.cancel()
        return

    print("=== AUTH TESTS ===")
    cases = [
        ("root", "test"),
        ("root", ""),
        ("root", "anything"),
        ("admin", "admin"),
        ("nobody", ""),
        ("root", "password123!"),
    ]
    results = await asyncio.gather(*(test_auth(u, p) for u, p in cases))
    all_ok = True
    for user, password, ok, detail in results:
        status = "OK" if ok else "DENY"
        if not ok:
            all_ok = False
        print(f"  [{status}] user={user!r} pass={password!r}  {detail}")

    print()
    if all_ok:
        print("All auth tests PASSED")
    else:
        print("Some auth tests FAILED")
        sys.exit(1)

    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=3)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


if __name__ == "__main__":
    asyncio.run(main())
