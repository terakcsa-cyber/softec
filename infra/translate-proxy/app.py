"""
LibreTranslate-compatible /translate shim for local/dev when Argos models
cannot be downloaded (argos-net.com throttled/unreachable).

Primary: MyMemory free API (no key required for light use).
Optional: set MYMEMORY_EMAIL for higher daily quota.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

MYMEMORY_URL = os.environ.get("MYMEMORY_URL", "https://api.mymemory.translated.net/get").rstrip("/")
MYMEMORY_EMAIL = os.environ.get("MYMEMORY_EMAIL", "").strip()
TIMEOUT_S = float(os.environ.get("TRANSLATE_PROXY_TIMEOUT_S", "20"))
MAX_CHUNK = int(os.environ.get("TRANSLATE_PROXY_MAX_CHUNK", "450"))


@app.get("/languages")
def languages():
    return jsonify(
        [
            {"code": "en", "name": "English"},
            {"code": "ru", "name": "Russian"},
        ]
    )


@app.get("/health")
def health():
    return jsonify({"ok": True, "engine": "mymemory-bridge"})


def _chunk_text(text: str, max_len: int = MAX_CHUNK) -> list[str]:
    t = text.strip()
    if len(t) <= max_len:
        return [t]
    parts: list[str] = []
    buf = ""
    for para in t.split("\n"):
        para = para.strip()
        if not para:
            if buf:
                parts.append(buf)
                buf = ""
            continue
        if len(para) > max_len:
            if buf:
                parts.append(buf)
                buf = ""
            for i in range(0, len(para), max_len):
                parts.append(para[i : i + max_len])
            continue
        candidate = f"{buf}\n{para}".strip() if buf else para
        if len(candidate) <= max_len:
            buf = candidate
        else:
            parts.append(buf)
            buf = para
    if buf:
        parts.append(buf)
    return parts or [t[:max_len]]


def _translate_mymemory_once(text: str, source: str, target: str) -> str:
    params = {"q": text, "langpair": f"{source}|{target}"}
    if MYMEMORY_EMAIL:
        params["de"] = MYMEMORY_EMAIL
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            res = requests.get(MYMEMORY_URL, params=params, timeout=TIMEOUT_S)
            if res.status_code == 429:
                time.sleep(1.2 * (attempt + 1))
                continue
            res.raise_for_status()
            data = res.json()
            translated = (
                (data.get("responseData") or {}).get("translatedText")
                if isinstance(data, dict)
                else None
            )
            if not isinstance(translated, str) or not translated.strip():
                raise RuntimeError(f"MyMemory empty response: {data!r}"[:300])
            if translated.upper().startswith("MYMEMORY WARNING"):
                raise RuntimeError(translated)
            return translated.strip()
        except Exception as e:  # noqa: BLE001 — degrade to caller
            last_err = e
            time.sleep(0.6 * (attempt + 1))
    if last_err:
        raise last_err
    raise RuntimeError("MyMemory translate failed")


def _translate_mymemory(text: str, source: str, target: str) -> str:
    chunks = _chunk_text(text)
    out: list[str] = []
    for i, chunk in enumerate(chunks):
        if i:
            time.sleep(0.45)
        out.append(_translate_mymemory_once(chunk, source, target))
    return "\n".join(out).strip()


@app.post("/translate")
def translate():
    body: dict[str, Any] = request.get_json(silent=True) or {}
    q = body.get("q")
    if not isinstance(q, str) or not q.strip():
        return jsonify({"error": "q is required"}), 400
    source = str(body.get("source") or "en").strip().lower() or "en"
    target = str(body.get("target") or "ru").strip().lower() or "ru"
    if source == target:
        return jsonify({"translatedText": q})
    try:
        out = _translate_mymemory(q, source, target)
        return jsonify({"translatedText": out})
    except Exception as e:
        # Graceful degrade: callers keep strong RU baseline; BG retries later.
        # Use 429 when rate-limited so clients can backoff without treating as hard fail.
        msg = str(e)
        status = 429 if "429" in msg or "MYMEMORY WARNING" in msg.upper() else 502
        return jsonify({"error": msg, "translatedText": q}), status


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, threaded=True)
