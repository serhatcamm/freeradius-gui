#!/usr/bin/env python3
"""Probe the static-file routes in a clean process.

Run as a subprocess from the test suite so FRW_STATIC_DIR is set *before*
app.main is imported: the static routes are only registered at import time when
the directory already exists, and the rest of the suite imports app.main long
before any test runs.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

STATIC = Path(tempfile.mkdtemp(prefix="frw-static-"))
(STATIC / "assets").mkdir()
(STATIC / "index.html").write_text("<!doctype html><title>panel</title>", encoding="utf-8")
(STATIC / "assets" / "index-abc123.js").write_text("export const x = 1", encoding="utf-8")
# A file that must never be reachable through the SPA fallback.
SECRET = STATIC.parent / "frw-outside-secret.txt"
SECRET.write_text("TOP-SECRET-VALUE", encoding="utf-8")

os.environ["FRW_STATIC_DIR"] = str(STATIC)
os.environ["FRW_ENABLE_DOCS"] = "false"
os.environ["FRW_COOKIE_SECURE"] = "false"
os.environ["FRW_DATABASE_URL"] = f"sqlite:///{STATIC / 'probe.db'}"
os.environ["FRW_SECRET_KEY_FILE"] = str(STATIC / "probe.key")
os.environ["FRW_LOGIN_MAX_ATTEMPTS"] = "5"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def get(client: TestClient, path: str) -> tuple[int, str]:
    resp = client.get(path)
    return resp.status_code, resp.text


results: dict[str, dict] = {}

with TestClient(app) as client:
    status, text = get(client, "/")
    results["index"] = {"status": status, "is_index": "panel" in text}

    status, text = get(client, "/users")
    results["spa_route"] = {"status": status, "is_index": "panel" in text}

    status, text = get(client, "/assets/index-abc123.js")
    results["asset"] = {"status": status, "body": text.strip()}

    status, text = get(client, "/api/definitely-missing")
    results["api_404"] = {"status": status, "is_json": text.strip().startswith("{")}

    # Traversal attempts. The SPA fallback joins the path onto STATIC_DIR, so
    # these must not escape it.
    traversal_paths = [
        "/../frw-outside-secret.txt",
        "/../../frw-outside-secret.txt",
        "/assets/../../frw-outside-secret.txt",
        "/%2e%2e/frw-outside-secret.txt",
        "/%2e%2e%2f%2e%2e%2ffrw-outside-secret.txt",
        "/..%2ffrw-outside-secret.txt",
    ]
    traversal = []
    for path in traversal_paths:
        status, text = get(client, path)
        leaked = "TOP-SECRET-VALUE" in text
        traversal.append({"path": path, "status": status, "leaked": leaked})
    results["traversal"] = traversal

    # A file that exists inside STATIC_DIR but outside assets must still be
    # served only if it is genuinely a file under the root; nothing else.
    status, _ = get(client, "/index.html")
    results["explicit_file"] = {"status": status}

json.dump(results, sys.stdout)