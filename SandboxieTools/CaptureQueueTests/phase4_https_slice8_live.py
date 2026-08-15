"""
Phase 4 Slice 8 preflight + live isolation harness.

Capability bits must stay off until items 1-11 pass against the *new*
loaded images. This script refuses to treat mismatched/old binaries as
evidence and does not flip bits.

Usage:
  python phase4_https_slice8_live.py preflight
  python phase4_https_slice8_live.py live   # requires elevated reload first
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEPLOY = r"C:\Sandboxie-Plus"
EVIDENCE = os.path.join(
    os.environ.get("LOCALAPPDATA", r"C:\Users\wulda\AppData\Local"),
    "Temp", "hermes-sandbox-capture-red")
MCP = os.path.join(DEPLOY, "SbieMcp.exe")
CURL = r"C:\Windows\System32\curl.exe"

PAIRS = [
    ("SbieDrv.sys",
     os.path.join(REPO, r"Sandboxie\Bin\x64\SbieRelease\SbieDrv.sys"),
     os.path.join(DEPLOY, "SbieDrv.sys")),
    ("SbieSvc.exe",
     os.path.join(REPO, r"Sandboxie\Bin\x64\SbieRelease\SbieSvc.exe"),
     os.path.join(DEPLOY, "SbieSvc.exe")),
    ("SbieCapture.exe",
     os.path.join(REPO,
                  r"SandboxieTools\SandboxiePlus\Bin\x64\Release\SbieCapture.exe"),
     os.path.join(DEPLOY, "SbieCapture.exe")),
]


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elevated() -> bool:
    try:
        return subprocess.call(
            ["net", "session"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL) == 0
    except OSError:
        return False


def service_state(name: str) -> str:
    text = subprocess.check_output(
        ["sc", "query", name], text=True, encoding="mbcs", errors="replace")
    for line in text.splitlines():
        if "STATE" in line:
            return line.strip()
    return text.strip()


def preflight() -> dict:
    report = {
        "elevated": elevated(),
        "services": {
            "SbieDrv": service_state("SbieDrv"),
            "SbieSvc": service_state("SbieSvc"),
        },
        "files": [],
        "all_match": True,
        "ready_for_live": False,
    }
    for name, src, dst in PAIRS:
        item = {"name": name, "src": src, "dst": dst,
                "src_exists": os.path.exists(src),
                "dst_exists": os.path.exists(dst),
                "match": False}
        if item["src_exists"] and item["dst_exists"]:
            item["src_sha256"] = sha256(src)
            item["dst_sha256"] = sha256(dst)
            item["match"] = item["src_sha256"] == item["dst_sha256"]
        if not item["match"]:
            report["all_match"] = False
        report["files"].append(item)
    report["ready_for_live"] = report["elevated"] and report["all_match"]
    report["notes"] = [
        "Do not flip httpsInspection/harExport until live items 1-11 pass.",
        "QSbieAPI StartCapture(eHttps) is still STATUS_NOT_SUPPORTED.",
        "Reload requires elevated KmdUtil: stop SbieSvc, unload SbieDrv, "
        "copy, hash, start SbieDrv, start SbieSvc.",
    ]
    return report


class Mcp:
    def __init__(self) -> None:
        self.p = subprocess.Popen(
            [MCP], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
            cwd=DEPLOY, bufsize=1)
        self.n = 1
        self.call("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "phase4-slice8", "version": "1.0"},
        })
        self.notify("notifications/initialized", {})

    def notify(self, method: str, params: dict) -> None:
        assert self.p.stdin is not None
        self.p.stdin.write(json.dumps({
            "jsonrpc": "2.0", "method": method, "params": params
        }, separators=(",", ":")) + "\n")
        self.p.stdin.flush()

    def call(self, method: str, params: dict) -> dict:
        assert self.p.stdin is not None and self.p.stdout is not None
        ident = self.n
        self.n += 1
        self.p.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": ident, "method": method, "params": params
        }, separators=(",", ":")) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            err = self.p.stderr.read() if self.p.stderr else ""
            raise RuntimeError("SbieMcp exited: " + err)
        return json.loads(line)

    def value(self, reply: dict) -> dict:
        result = reply.get("result", {})
        if "structuredContent" in result:
            return result["structuredContent"]
        content = result.get("content", [])
        if content and isinstance(content[0], dict):
            text = content[0].get("text", "")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
        if "error" in reply:
            return {"error": reply["error"]}
        return result

    def tool(self, name: str, args: dict) -> dict:
        reply = self.call("tools/call", {"name": name, "arguments": args})
        value = self.value(reply)
        if reply.get("result", {}).get("isError") or "error" in reply:
            raise RuntimeError(f"{name}: {value}")
        return value

    def close(self) -> None:
        if self.p.poll() is None:
            try:
                if self.p.stdin:
                    self.p.stdin.close()
            except Exception:
                pass
            try:
                self.p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.p.kill()


def live(report: dict) -> dict:
    if not report["ready_for_live"]:
        report["live"] = {
            "skipped": True,
            "reason": "preflight failed: elevate and reload matching images first",
        }
        return report
    os.makedirs(EVIDENCE, exist_ok=True)
    mcp = Mcp()
    try:
        caps = mcp.tool("capture_capabilities", {})
        report["live"] = {
            "capabilities": caps,
            "httpsInspection": bool(caps.get("httpsInspection")),
            "harExport": bool(caps.get("harExport")),
            "public_https_still_off":
                not caps.get("httpsInspection") and not caps.get("harExport"),
        }
        try:
            started = mcp.tool("capture_start", {
                "box": "DefaultBox",
                "mode": "https",
                "outputPath": os.path.join(EVIDENCE, "slice8.pcapng"),
                "outputHarPath": os.path.join(EVIDENCE, "slice8.har"),
                "includeFutureProcesses": True,
            })
            report["live"]["https_start"] = started
        except RuntimeError as exc:
            report["live"]["https_start"] = {"error": str(exc)}
            report["live"]["items"] = {
                "note": "HTTPS start still blocked; isolation items 2-11 not run",
            }
    finally:
        mcp.close()
    return report


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "preflight"
    report = preflight()
    if mode == "live":
        report = live(report)
    os.makedirs(EVIDENCE, exist_ok=True)
    out = os.path.join(EVIDENCE, "phase4-slice8-preflight.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))
    print("wrote", out)
    if mode == "live" and not report.get("ready_for_live"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
