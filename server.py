"""
server.py
─────────
Lightweight FastAPI bridge between the browser frontend and the
agentic pentest system.  Serves static assets, exposes a WebSocket
endpoint that streams stdout from main.py in real-time, and provides
a REST endpoint to fetch generated reports.
"""

import asyncio
import json
import os
import sys
import glob as globmod
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv

load_dotenv()

# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(title="PASS — Agentic Penetration Testing")

# Use the same Python interpreter that is running this server
PYTHON = sys.executable

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
REPORTS_DIR = BASE_DIR / "output" / "reports"

# ── Serve frontend assets ────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
async def root():
    """Serve the main SPA page."""
    return FileResponse(str(FRONTEND_DIR / "index.html"))


# ── Report endpoints ─────────────────────────────────────────────────────────
@app.get("/api/reports")
async def list_reports():
    """Return list of available report files sorted newest-first."""
    if not REPORTS_DIR.exists():
        return JSONResponse({"reports": []})
    files = sorted(REPORTS_DIR.glob("*.md"), key=os.path.getmtime, reverse=True)
    return JSONResponse({"reports": [f.name for f in files]})


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    """Return the raw markdown content of a specific report."""
    path = REPORTS_DIR / filename
    if not path.exists() or not path.suffix == ".md":
        return JSONResponse({"error": "Report not found"}, status_code=404)
    return JSONResponse({"content": path.read_text(encoding="utf-8")})


# ── WebSocket — stream pentest stdout ────────────────────────────────────────
class ConnectionManager:
    """Track active WebSocket clients."""

    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: str):
        for ws in list(self.active):
            try:
                await ws.send_text(message)
            except Exception:
                self.active.remove(ws)


manager = ConnectionManager()


async def _stream_process(cmd: list[str], ws: WebSocket):
    """
    Launch a subprocess and stream its combined stdout/stderr
    line-by-line over the WebSocket.

    Uses subprocess.Popen with a reader thread for Windows compatibility
    (asyncio subprocess can fail under uvicorn's event loop on Windows).
    """
    import subprocess
    import threading
    import queue

    await ws.send_text(json.dumps({"type": "log", "data": f"[PASS] Executing: {cmd[0]} {' '.join(cmd[1:])}"}))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(BASE_DIR),
            env={**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"},
            bufsize=1,
        )
    except Exception as exc:
        import traceback
        await ws.send_text(json.dumps({
            "type": "error",
            "data": f"Failed to start process: {type(exc).__name__}: {exc}",
        }))
        return 1

    # Read lines in a background thread so we don't block the event loop
    line_queue: queue.Queue = queue.Queue()
    _SENTINEL = None

    def _reader():
        try:
            for raw_line in proc.stdout:
                line_queue.put(raw_line)
        finally:
            line_queue.put(_SENTINEL)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    try:
        while True:
            # Poll the queue without blocking the event loop
            try:
                raw = line_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.05)
                continue

            if raw is _SENTINEL:
                break

            text = raw.decode("utf-8", errors="replace").rstrip("\n\r")
            await ws.send_text(json.dumps({"type": "log", "data": text}))
    except WebSocketDisconnect:
        proc.kill()
        raise
    except Exception as exc:
        await ws.send_text(json.dumps({"type": "error", "data": f"Stream error: {exc}"}))
        proc.kill()

    proc.wait()
    return proc.returncode


@app.websocket("/ws/scan")
async def scan_websocket(ws: WebSocket):
    """
    Accept a scan configuration via WebSocket, launch main.py
    as a subprocess, and stream all output back in real-time.

    Expected initial JSON message:
    {
        "target": "http://localhost:8888",
        "app": "dvwa",
        "mode": "active",
        "username": "",          (optional)
        "password": "",          (optional)
        "rate_limit": 5,         (optional)
        "no_auth": false         (optional)
    }
    """
    await manager.connect(ws)
    try:
        # Wait for the configuration payload
        raw = await ws.receive_text()
        config = json.loads(raw)

        target = config.get("target", "").strip()
        app_type = config.get("app", "dvwa")
        mode = config.get("mode", "active")
        username = config.get("username", "").strip()
        password = config.get("password", "").strip()
        rate_limit = config.get("rate_limit", 5)
        no_auth = config.get("no_auth", False)

        if not target:
            await ws.send_text(json.dumps({"type": "error", "data": "No target URL provided"}))
            return

        # Build the command using the same interpreter running this server
        cmd = [
            PYTHON, "main_headless.py",
            "--target", target,
            "--app", app_type,
            "--mode", mode,
            "--rate-limit", str(rate_limit),
        ]

        if username and password:
            cmd += ["--username", username, "--password", password]

        if no_auth:
            cmd.append("--no-auth")

        # Snapshot existing reports so we only return NEW ones
        existing_reports = set()
        if REPORTS_DIR.exists():
            existing_reports = {f.name for f in REPORTS_DIR.glob("*.md")}

        # Signal scan start
        await ws.send_text(json.dumps({
            "type": "status",
            "data": "scan_started",
            "config": {
                "target": target,
                "app": app_type,
                "mode": mode,
            }
        }))

        # Stream the process
        returncode = await _stream_process(cmd, ws)

        # Find only reports created DURING this scan
        new_report = None
        if REPORTS_DIR.exists():
            for f in sorted(REPORTS_DIR.glob("*.md"), key=os.path.getmtime, reverse=True):
                if f.name not in existing_reports:
                    new_report = f.name
                    break

        # Signal completion
        await ws.send_text(json.dumps({
            "type": "status",
            "data": "scan_complete",
            "returncode": returncode,
            "report": new_report,
        }))

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await ws.send_text(json.dumps({"type": "error", "data": str(exc)}))
        except Exception:
            pass
    finally:
        manager.disconnect(ws)


# ── Run with: uvicorn server:app --reload ─────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8501, reload=True)
