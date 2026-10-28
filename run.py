"""Start Mini SIEM.  In your IDE just press Run on this file (or:  python run.py).

Dashboard: http://127.0.0.1:8000   API docs: /docs
Runs ONE server process on purpose: the log hash-chain lock is per-process, so never add workers/reload here.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

import uvicorn  # noqa: E402

from app.main import app  # noqa: E402

if __name__ == "__main__":
    cert, key = os.getenv("SSL_CERTFILE"), os.getenv("SSL_KEYFILE")
    ssl = {"ssl_certfile": cert, "ssl_keyfile": key} if cert and key else {}
    uvicorn.run(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")), **ssl)
