─── quarantine record ──────────────────────────────────────────────────────────
url:  https://www.exploit-db.com/download/52572
from: 127.0.0.1:50996 (root) | session: 1afb9886-3ded-42fc-855b-855c9e9318dc
ts:   2026-05-22T18:31:29 UTC
file: quarantine/20260522T183129_https___www.exploit-db.com_download_52572

─── .meta.json ────────────────────────────────────────────────────────────────
{
  "url": "https://www.exploit-db.com/download/52572",
  "sid": "1afb9886-3ded-42fc-855b-855c9e9318dc",
  "peer": "127.0.0.1:50996",
  "ts": "2026-05-22T18:31:29.460216+00:00",
  "status": 403,
  "size": 2312,
  "content_type": "text/html",
  "saved": "quarantine/20260522T183129_https___www.exploit-db.com_download_52572"
}

─── file content (first 20 lines) ─────────────────────────────────────────────
(skipped — 403, HTML error page, not actual exploit content)

─── quarantine_dir listing ────────────────────────────────────────────────────
quarantine/
├── 20260522T175437_https___www.exploit-db.com_download_52572        (8.0K, text)
├── 20260522T175437_https___www.exploit-db.com_download_52572.meta.json
├── 20260522T175438_https___www.exploit-db.com_download_52572        (8.0K, text)
├── 20260522T175438_https___www.exploit-db.com_download_52572.meta.json
├── 20260522T175452_https___www.exploit-db.com_download_52572        (8.0K, text)
├── 20260522T175452_https___www.exploit-db.com_download_52572.meta.json
├── 20260522T183129_https___www.exploit-db.com_download_52572        (2.3K, HTML)
└── 20260522T183129_https___www.exploit-db.com_download_52572.meta.json

note: files 175437–175452 were downloaded during earlier sessions
      before exploit-db started returning 403; they contain real exploit code.
