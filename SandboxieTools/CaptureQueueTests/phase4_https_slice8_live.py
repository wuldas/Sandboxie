"""
Phase 4 Slice 8 preflight + live isolation harness.

Capability bits must stay off until items 1-11 pass against the *new*
loaded images. This script refuses to treat mismatched/old binaries as
evidence and does not flip bits.

Usage:
  python phase4_https_slice8_live.py preflight
  python phase4_https_slice8_live.py live
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
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
RUNNER = os.path.join(
    REPO, r"SandboxieTools\CaptureQueueTests\run_boxed_silent.exe")

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
    drv_running = "RUNNING" in report["services"]["SbieDrv"]
    svc_running = "RUNNING" in report["services"]["SbieSvc"]
    report["ready_for_live"] = report["all_match"] and drv_running and svc_running
    report["notes"] = [
        "Do not flip httpsInspection/harExport until live items 1-11 pass.",
        "This process does not need to be elevated if images were already reloaded.",
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
        if result.get("isError"):
            content = result.get("content", [])
            text = content[0].get("text", "") if content else ""
            try:
                parsed = json.loads(text) if text else {}
            except json.JSONDecodeError:
                parsed = {"text": text}
            parsed["isError"] = True
            return parsed
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
            return {"error": reply["error"], "isError": True}
        return result

    def tool(self, name: str, args: dict) -> dict:
        reply = self.call("tools/call", {"name": name, "arguments": args})
        value = self.value(reply)
        if value.get("isError") or "error" in reply:
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


def boxed(box: str, command: str, timeout: int = 25) -> dict:
    result = subprocess.run(
        [RUNNER, box, "wait", command],
        cwd=DEPLOY, capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace")
    payload = {}
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{") and "pid" in line:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                pass
    payload["returncode"] = result.returncode
    payload["stdout"] = result.stdout
    payload["stderr"] = result.stderr
    return payload


def host_curl(url: str, extra: list[str] | None = None, timeout: int = 20) -> dict:
    args = [CURL, "-sS", "-I", "--max-time", "12"]
    if extra:
        args.extend(extra)
    args.append(url)
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace")
    return {
        "returncode": result.returncode,
        "stdout": result.stdout[-800:],
        "stderr": result.stderr[-400:],
    }


def har_hosts(path: str) -> list[str]:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    hosts = []
    for entry in data.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url", "")
        if "://" in url:
            hosts.append(url.split("/")[2].split(":")[0].lower())
        comment = json.dumps(entry.get("_sbie", entry), ensure_ascii=False)
        if "pinningFailed" in comment or entry.get("_pinningFailed"):
            hosts.append("pinningFailed")
    return hosts


def har_has_pinning(path: str) -> bool:
    if not os.path.exists(path):
        return False
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    return '"pinningFailed": true' in text or '"pinningFailed":true' in text


def store_fingerprint(store: str) -> str:
    digest = hashlib.sha256()
    opened = subprocess.run(
        ["certutil", "-user", "-store", store],
        capture_output=True, text=True, timeout=20,
        encoding="mbcs", errors="replace")
    digest.update((opened.stdout or "").encode("utf-8", "replace"))
    return digest.hexdigest()


SBIE_INI = os.path.join(DEPLOY, "SbieIni.exe")
BOX_TEMP = r"C:\Sandbox\wulda\DefaultBox\user\current\AppData\Local\Temp"
WINHTTP_PS1 = os.path.join(EVIDENCE, "winhttp-probe.ps1")
WINHTTP_BOX_OUT = os.path.join(BOX_TEMP, "winhttp-result.txt")
CROSSSID_IN = r"C:\Windows\Temp\p4-crosssid-in.txt"
CROSSSID_OUT = r"C:\Windows\Temp\p4-crosssid-out.txt"
CROSSSID_DRIVER = r"C:\Windows\Temp\p4-crosssid-driver.ps1"
CROSSSID_CMD = os.path.join(EVIDENCE, "crosssid-run.cmd")
CROSSSID_OUT_COPY = os.path.join(EVIDENCE, "crosssid-out.txt")
CROSSSID_TASK = "P4CrossSidMcp"
CROSSSID_USER = "sbie-p4test"
CROSSSID_PASS = "P4slice8temp"


def certutil_count(text: str) -> int:
    return (text or "").count("SbieCapture")


def boxed_certutil(box: str) -> str:
    result = subprocess.run(
        [RUNNER, box, "wait", "certutil -user -store Root"],
        cwd=DEPLOY, capture_output=True, text=True, timeout=40,
        encoding="mbcs", errors="replace")
    return (result.stdout or "") + (result.stderr or "")


def host_root_ca_count() -> int:
    result = subprocess.run(
        ["certutil", "-user", "-store", "Root"],
        capture_output=True, text=True, timeout=20,
        encoding="mbcs", errors="replace")
    return certutil_count(result.stdout)


def sbie_ini_set(box: str, setting: str, value: str) -> None:
    args = [SBIE_INI, "set", box, setting]
    if value:
        args.append(value)
    subprocess.run(args, cwd=DEPLOY, capture_output=True,
                   text=True, timeout=20)


def broker_listen_port() -> int | None:
    ps = ("(Get-Process SbieCapture -ErrorAction SilentlyContinue | "
          "Select-Object -First 1).Id")
    got = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=20,
        encoding="utf-8", errors="replace")
    text = (got.stdout or "").strip()
    if not text.isdigit():
        return None
    pid = int(text)
    ps2 = ("(Get-NetTCPConnection -State Listen -OwningProcess " + str(pid) +
           " -ErrorAction SilentlyContinue | Where-Object " +
           "{$_.LocalAddress -eq '127.0.0.1'} | "
           "Select-Object -First 1).LocalPort")
    got2 = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps2],
        capture_output=True, text=True, timeout=20,
        encoding="utf-8", errors="replace")
    text2 = (got2.stdout or "").strip()
    return int(text2) if text2.isdigit() else None


def run_winhttp_probe() -> tuple[bool, dict]:
    os.makedirs(EVIDENCE, exist_ok=True)
    with open(WINHTTP_PS1, "w", encoding="ascii") as handle:
        handle.write(
            "$out = \"$env:TEMP\\winhttp-result.txt\"\n"
            "try {\n"
            "  $h = New-Object -ComObject WinHttp.WinHttpRequest.5.1\n"
            "  $h.SetTimeouts(8000,8000,8000,8000)\n"
            "  $h.Open('HEAD','https://example.com/',$false)\n"
            "  $h.Send()\n"
            "  (\"OK \" + $h.Status) | Out-File $out -Encoding ascii\n"
            "} catch {\n"
            "  (\"FAIL \" + $_.Exception.Message) | Out-File $out "
            "-Encoding ascii\n"
            "}\n")
    try:
        os.remove(WINHTTP_BOX_OUT)
    except OSError:
        pass
    boxed("DefaultBox",
          f"powershell -NoProfile -ExecutionPolicy Bypass -File {WINHTTP_PS1}",
          timeout=90)
    time.sleep(0.5)
    try:
        text = open(WINHTTP_BOX_OUT, encoding="ascii", errors="replace").read()
        return text.strip().startswith("OK"), {"result": text.strip()[:160]}
    except OSError as exc:
        return False, {"error": f"no result file: {exc}"}


def write_crosssid_in(target_pid: int) -> None:
    #
    # process-scoped capture_start targeting a boxed process owned by the
    # interactive user (wulda).  When sbie-p4test runs this, the service
    # hits CaptureServer.cpp:1045 (targetSid != ownerSid) and returns
    # 0xC0000022.  process scope must not carry includeFutureProcesses.
    #
    # the driver is a PowerShell .NET Process wrapper: SbieMcp reads stdin
    # with QFile::readLine, which needs a real pipe/redirect; plain
    # `cmd /c type | SbieMcp` breaks under schtasks, but the .NET Process
    # class with RedirectStandardInput works reliably.
    #
    lines = [
        '{"jsonrpc":"2.0","id":1,"method":"initialize",'
        '"params":{"protocolVersion":"2025-06-18","capabilities":{},'
        '"clientInfo":{"name":"p4-crosssid","version":"1"}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'
        '{"name":"capture_start","arguments":{"box":"DefaultBox",'
        '"mode":"https","processId":' + str(target_pid) +
        ',"outputPath":"C:\\\\Windows\\\\Temp\\\\p4-x.pcapng",'
        '"outputHarPath":"C:\\\\Windows\\\\Temp\\\\p4-x.har"}}}',
    ]
    with open(CROSSSID_IN, "wb") as handle:
        handle.write(("\n".join(lines) + "\n").encode("ascii"))

    #
    # grant the schtasks principal (Users group) read access WITHOUT
    # removing the owner's existing ACEs.  icacls /grant on an inherited
    # file drops inheritance, so grant both the current user and Users in
    # a single invocation.
    #
    current_user = os.environ.get("USERNAME") or "wulda"
    subprocess.run(
        ["cmd", "/c", "icacls", CROSSSID_IN, "/grant",
         f"{current_user}:(F)", "Users:(R)"],
        capture_output=True, text=True, timeout=20,
        encoding="gbk", errors="replace")

    driver = (
        '$ErrorActionPreference = "SilentlyContinue"\n'
        '$psi = New-Object System.Diagnostics.ProcessStartInfo\n'
        '$psi.FileName = "C:\\Sandboxie-Plus\\SbieMcp.exe"\n'
        '$psi.WorkingDirectory = "C:\\Sandboxie-Plus"\n'
        '$psi.UseShellExecute = $false\n'
        '$psi.RedirectStandardInput = $true\n'
        '$psi.RedirectStandardOutput = $true\n'
        '$psi.RedirectStandardError = $true\n'
        '$psi.CreateNoWindow = $true\n'
        '$p = New-Object System.Diagnostics.Process\n'
        '$p.StartInfo = $psi\n'
        '$p.Start() | Out-Null\n'
        '$input = Get-Content -Raw "C:\\Windows\\Temp\\p4-crosssid-in.txt"\n'
        '$p.StandardInput.Write($input)\n'
        '$p.StandardInput.Close()\n'
        '$out = $p.StandardOutput.ReadToEnd()\n'
        '$err = $p.StandardError.ReadToEnd()\n'
        '$p.WaitForExit(25000) | Out-Null\n'
        '"exit=$($p.ExitCode)" | Out-File '
        '"C:\\Windows\\Temp\\p4-crosssid-out.txt" -Encoding ascii\n'
        '$out | Out-File "C:\\Windows\\Temp\\p4-crosssid-out.txt" '
        '-Append -Encoding ascii\n'
        '$err | Out-File "C:\\Windows\\Temp\\p4-crosssid-out.txt" '
        '-Append -Encoding ascii\n'
    )
    with open(CROSSSID_DRIVER, "w", encoding="ascii") as handle:
        handle.write(driver)

    #
    # elevated batch: a non-elevated schtasks "succeeds" but the foreign-
    # user task never runs, so create/run/delete the scheduled task from an
    # elevated cmd (one UAC prompt).  the batch copies the driver output
    # back into EVIDENCE where the non-elevated harness can read it.
    #
    batch = (
        "@echo off\r\n"
        f"schtasks /delete /tn {CROSSSID_TASK} /f >nul 2>&1\r\n"
        f"schtasks /create /tn {CROSSSID_TASK} /tr "
        f"\"powershell -NoProfile -ExecutionPolicy Bypass "
        f"-File {CROSSSID_DRIVER}\" /sc once /st 23:59 "
        f"/RU {CROSSSID_USER} /RP {CROSSSID_PASS} /f\r\n"
        f"schtasks /run /tn {CROSSSID_TASK}\r\n"
        f"ping -n 15 127.0.0.1 >nul\r\n"
        f"copy /y {CROSSSID_OUT} \"{CROSSSID_OUT_COPY}\" >nul 2>&1\r\n"
        f"schtasks /delete /tn {CROSSSID_TASK} /f\r\n"
    )
    with open(CROSSSID_CMD, "w", encoding="ascii") as handle:
        handle.write(batch)


def item(name: str, passed: bool, detail: dict) -> dict:
    return {"item": name, "pass": passed, "detail": detail}


def live(report: dict) -> dict:
    if not report["ready_for_live"]:
        report["live"] = {
            "skipped": True,
            "reason": "preflight failed: matching loaded images required",
        }
        return report
    os.makedirs(EVIDENCE, exist_ok=True)
    items = []
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

        conn = mcp.tool("capture_start", {
            "box": "DefaultBox", "mode": "connections",
            "includeFutureProcesses": True,
        })
        mcp.tool("capture_stop", {"captureId": conn["captureId"]})
        pkt_path = os.path.join(EVIDENCE, "slice8-item1.pcapng")
        pkt = mcp.tool("capture_start", {
            "box": "DefaultBox", "mode": "packets",
            "outputPath": pkt_path, "includeFutureProcesses": True,
        })
        mcp.tool("capture_stop", {"captureId": pkt["captureId"]})
        items.append(item("1-regression",
                          conn.get("state") in (3, 4) and pkt.get("state") in (3, 4),
                          {"connections": conn, "packets": pkt}))

        host_root_before = store_fingerprint("Root")
        a_pcap = os.path.join(EVIDENCE, "slice8-a.pcapng")
        a_har = os.path.join(EVIDENCE, "slice8-a.har")
        b_pcap = os.path.join(EVIDENCE, "slice8-b.pcapng")
        b_har = os.path.join(EVIDENCE, "slice8-b.har")
        sess_a = mcp.tool("capture_start", {
            "box": "DefaultBox", "mode": "https",
            "outputPath": a_pcap, "outputHarPath": a_har,
            "includeFutureProcesses": True,
        })
        sess_b = mcp.tool("capture_start", {
            "box": "BoxB", "mode": "https",
            "outputPath": b_pcap, "outputHarPath": b_har,
            "includeFutureProcesses": True,
        })
        curl_a = boxed(
            "DefaultBox",
            f'"{CURL}" -sS -I --http1.1 --max-time 12 -o NUL https://example.com')
        curl_b = boxed(
            "BoxB",
            f'"{CURL}" -sS -I --http1.1 --max-time 12 -o NUL '
            f'https://one.one.one.one')
        curl_host = host_curl("https://9.9.9.9")
        time.sleep(1)
        stop_a = mcp.tool("capture_stop", {"captureId": sess_a["captureId"]})
        stop_b = mcp.tool("capture_stop", {"captureId": sess_b["captureId"]})
        hosts_a = har_hosts(a_har)
        hosts_b = har_hosts(b_har)
        host_in_a = any(h.startswith("9.9.9.9") for h in hosts_a)
        example_in_b = any("example.com" in h for h in hosts_b)
        example_in_a = any("example.com" in h for h in hosts_a)
        one_in_b = any("one.one.one.one" in h for h in hosts_b)
        curl_b_exit = curl_b.get("exitCode", curl_b.get("returncode"))
        items.append(item("2-isolation",
                          bool(example_in_a) and not example_in_b and
                          not host_in_a and bool(one_in_b) and
                          curl_b_exit == 0,
                          {
                              "sessA": sess_a.get("state"),
                              "sessB": sess_b.get("state"),
                              "curlA": curl_a.get("exitCode", curl_a.get("returncode")),
                              "curlB": curl_b_exit,
                              "curlHost": curl_host["returncode"],
                              "hostsA": hosts_a, "hostsB": hosts_b,
                              "harABytes": os.path.getsize(a_har) if os.path.exists(a_har) else 0,
                              "harBBytes": os.path.getsize(b_har) if os.path.exists(b_har) else 0,
                              "pcapABytes": os.path.getsize(a_pcap) if os.path.exists(a_pcap) else 0,
                          }))

        hold = boxed(
            "DefaultBox",
            "C:\\Windows\\System32\\ping.exe -n 20 127.0.0.1",
            timeout=5) if False else None
        started = subprocess.Popen(
            [RUNNER, "DefaultBox", "nowait",
             "C:\\Windows\\System32\\ping.exe -n 25 127.0.0.1"],
            cwd=DEPLOY, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace")
        time.sleep(1)
        first_line = (started.stdout.readline() if started.stdout else "") or ""
        try:
            hold_info = json.loads(first_line.strip()) if first_line.strip().startswith("{") else {}
        except json.JSONDecodeError:
            hold_info = {"raw": first_line}
        proc_har = os.path.join(EVIDENCE, "slice8-proc.har")
        proc_pcap = os.path.join(EVIDENCE, "slice8-proc.pcapng")
        proc_ok = False
        proc_detail = {"holder": hold_info}
        if hold_info.get("pid"):
            try:
                proc_sess = mcp.tool("capture_start", {
                    "box": "DefaultBox", "mode": "https",
                    "processId": int(hold_info["pid"]),
                    "outputPath": proc_pcap, "outputHarPath": proc_har,
                })
                child = boxed(
                    "DefaultBox",
                    f'"{CURL}" -sS -I --http1.1 --max-time 12 -o NUL https://example.com')
                time.sleep(1)
                mcp.tool("capture_stop", {"captureId": proc_sess["captureId"]})
                child_hosts = har_hosts(proc_har)
                proc_ok = "example.com" not in "".join(child_hosts)
                proc_detail.update({
                    "childExit": child.get("exitCode", child.get("returncode")),
                    "hosts": child_hosts,
                    "session": proc_sess.get("state"),
                })
            except RuntimeError as exc:
                proc_detail["error"] = str(exc)
        items.append(item("3-process-scope", proc_ok, proc_detail))
        try:
            started.terminate()
        except Exception:
            pass

        box_har = os.path.join(EVIDENCE, "slice8-boxchild.har")
        box_pcap = os.path.join(EVIDENCE, "slice8-boxchild.pcapng")
        box_sess = mcp.tool("capture_start", {
            "box": "DefaultBox", "mode": "https",
            "outputPath": box_pcap, "outputHarPath": box_har,
            "includeFutureProcesses": True,
        })
        child2 = boxed(
            "DefaultBox",
            f'"{CURL}" -sS -I --http1.1 --max-time 12 -o NUL https://example.com')
        time.sleep(1)
        mcp.tool("capture_stop", {"captureId": box_sess["captureId"]})
        box_hosts = har_hosts(box_har)
        items.append(item("4-box-scope-children",
                          any("example.com" in h for h in box_hosts),
                          {"hosts": box_hosts,
                           "childExit": child2.get("exitCode", child2.get("returncode"))}))

        wh_pcap = os.path.join(EVIDENCE, "slice8-winhttp.pcapng")
        wh_har = os.path.join(EVIDENCE, "slice8-winhttp.har")
        wh_detail: dict = {"chromium": "not run on this host; curl + WinHTTP required"}
        wh_ok = False
        try:
            wh_sess = mcp.tool("capture_start", {
                "box": "DefaultBox", "mode": "https",
                "outputPath": wh_pcap, "outputHarPath": wh_har,
                "includeFutureProcesses": True,
            })
            winhttp_ok, winhttp_detail = run_winhttp_probe()
            time.sleep(1)
            mcp.tool("capture_stop", {"captureId": wh_sess["captureId"]})
            wh_hosts = har_hosts(wh_har)
            wh_detail["winhttp"] = winhttp_detail
            wh_detail["winhttpHarHosts"] = wh_hosts
            wh_ok = (winhttp_ok and
                     any("example.com" in h for h in wh_hosts))
        except RuntimeError as exc:
            wh_detail["error"] = str(exc)
        items.append(item("5-http11-clients", wh_ok, wh_detail))

        pin_har = os.path.join(EVIDENCE, "slice8-pin.har")
        pin_pcap = os.path.join(EVIDENCE, "slice8-pin.pcapng")
        pin_sess = mcp.tool("capture_start", {
            "box": "DefaultBox", "mode": "https",
            "outputPath": pin_pcap, "outputHarPath": pin_har,
            "includeFutureProcesses": True,
        })
        pin_curl = boxed(
            "DefaultBox",
            f'"{CURL}" -sS -I --http1.1 --max-time 12 -o NUL '
            f'--pinnedpubkey "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" '
            f'https://example.com')
        time.sleep(1)
        pin_status = mcp.tool("capture_status", {"captureId": pin_sess["captureId"]})
        mcp.tool("capture_stop", {"captureId": pin_sess["captureId"]})
        items.append(item("6-pinning",
                          pin_curl.get("exitCode", pin_curl.get("returncode")) not in (0,)
                          and pin_status.get("state") in (3, 4)
                          and os.path.getsize(pin_pcap) > 0,
                          {
                              "curlExit": pin_curl.get("exitCode", pin_curl.get("returncode")),
                              "state": pin_status.get("state"),
                              "harPinning": har_has_pinning(pin_har),
                              "pcapBytes": os.path.getsize(pin_pcap) if os.path.exists(pin_pcap) else 0,
                          }))

        kill_har = os.path.join(EVIDENCE, "slice8-kill.har")
        kill_pcap = os.path.join(EVIDENCE, "slice8-kill.pcapng")
        kill_sess = mcp.tool("capture_start", {
            "box": "DefaultBox", "mode": "https",
            "outputPath": kill_pcap, "outputHarPath": kill_har,
            "includeFutureProcesses": True,
        })
        before_kill = boxed(
            "DefaultBox",
            f'"{CURL}" -sS -I --http1.1 --max-time 8 -o NUL https://example.com')
        subprocess.run(["taskkill", "/F", "/IM", "SbieCapture.exe"],
                       capture_output=True, text=True)
        time.sleep(1)
        try:
            after_status = mcp.tool("capture_status", {"captureId": kill_sess["captureId"]})
        except RuntimeError as exc:
            after_status = {"error": str(exc)}
        boxed_after = boxed(
            "DefaultBox",
            f'"{CURL}" -sS -I --http1.1 --max-time 8 -o NUL https://example.com')
        host_after = host_curl("https://example.com")
        try:
            mcp.tool("capture_stop", {"captureId": kill_sess["captureId"]})
        except RuntimeError:
            pass
        boxed_restored = boxed(
            "DefaultBox",
            f'"{CURL}" -sS -I --http1.1 --max-time 12 -o NUL https://example.com')
        failed_state = after_status.get("state") == 5 or after_status.get("backendStatus") not in (
            None, "0x00000000", 0)
        items.append(item("7-broker-kill-fail-closed",
                          bool(failed_state) and host_after["returncode"] == 0,
                          {
                              "before": before_kill.get("exitCode", before_kill.get("returncode")),
                              "afterBoxed": boxed_after.get("exitCode", boxed_after.get("returncode")),
                              "afterHost": host_after["returncode"],
                              "status": after_status,
                              "restored": boxed_restored.get("exitCode", boxed_restored.get("returncode")),
                          }))

        refuse = {"skipped": True, "reason": "no active HTTPS broker"}
        host_root_during = None
        refuse_detail: dict = {"skipped": True}
        refuse_ok = False
        try:
            refuse_har = os.path.join(EVIDENCE, "slice8-refuse.har")
            refuse_pcap = os.path.join(EVIDENCE, "slice8-refuse.pcapng")
            refuse_sess = mcp.tool("capture_start", {
                "box": "DefaultBox", "mode": "https",
                "outputPath": refuse_pcap, "outputHarPath": refuse_har,
                "includeFutureProcesses": True,
            })
            time.sleep(1)
            port = broker_listen_port()
            host_root_during = host_root_ca_count()
            refuse_detail = {"listenPort": port,
                             "hostRootDuring": host_root_during,
                             "skipped": False}
            if port:
                try:
                    with socket.create_connection(("127.0.0.1", port),
                                                  timeout=3) as probe:
                        probe.settimeout(3)
                        # no redirect context: the broker must drop the
                        # connection, so reading returns EOF immediately
                        try:
                            data = probe.recv(1)
                        except (ConnectionResetError, socket.timeout):
                            data = b"reset"
                        refuse_detail["direct"] = (
                            "eof" if data == b"" else
                            "reset" if data == b"reset" else "data")
                        refuse_ok = data == b"" or data == b"reset"
                except (ConnectionRefusedError, socket.timeout, OSError) as exc:
                    refuse_detail["direct"] = f"refused:{exc}"
                    refuse_ok = True
            mcp.tool("capture_stop", {"captureId": refuse_sess["captureId"]})
        except RuntimeError as exc:
            refuse_detail["error"] = str(exc)
        items.append(item("8-direct-listener-refuse", refuse_ok, refuse_detail))

        deny_detail: dict = {"skipped": True}
        deny_ok = False
        try:
            deny_har = os.path.join(EVIDENCE, "slice8-deny.har")
            deny_pcap = os.path.join(EVIDENCE, "slice8-deny.pcapng")
            sbie_ini_set("DefaultBox", "NetworkAccess", "curl.exe,deny")
            time.sleep(0.5)
            try:
                deny_sess = mcp.tool("capture_start", {
                    "box": "DefaultBox", "mode": "https",
                    "outputPath": deny_pcap, "outputHarPath": deny_har,
                    "includeFutureProcesses": True,
                })
                deny_curl = boxed(
                    "DefaultBox",
                    f'"{CURL}" -sS -I --http1.1 --max-time 8 -o NUL '
                    f'https://example.com')
                time.sleep(0.5)
                deny_hosts = har_hosts(deny_har)
                mcp.tool("capture_stop", {"captureId": deny_sess["captureId"]})
                deny_detail = {
                    "skipped": False,
                    "curlExit": deny_curl.get("exitCode",
                                              deny_curl.get("returncode")),
                    "harHosts": deny_hosts,
                }
                deny_ok = (deny_curl.get("exitCode",
                                         deny_curl.get("returncode")) not in (0,)
                           and not any("example.com" in h
                                       for h in deny_hosts))
            finally:
                sbie_ini_set("DefaultBox", "NetworkAccess", "")
        except RuntimeError as exc:
            deny_detail["error"] = str(exc)
        items.append(item("9-networkaccess-deny", deny_ok, deny_detail))

        host_root_after_count = host_root_ca_count()
        # Persistent-CA design: the session CA is installed in the HOST
        # user Root once (first-use prompt) and REUSED across sessions, so
        # it persists after stop.  Isolation is proven by: the CA is present
        # during the run, the count is unchanged by stop (persistent, not
        # deleted), and the other box's virtual Root is untouched.
        boxb_root = boxed_certutil("BoxB")
        items.append(item("10-store-isolation",
                          host_root_during is not None and
                          host_root_during > 0 and
                          host_root_after_count == host_root_during and
                          certutil_count(boxb_root) == 0,
                          {
                              "hostRootPersistent": host_root_after_count == host_root_during,
                              "hostRootDuring": host_root_during,
                              "hostRootAfter": host_root_after_count,
                              "otherBoxClean": certutil_count(boxb_root) == 0,
                          }))

        crosssid_detail: dict = {"skipped": True}
        crosssid_ok = False
        holder_proc = None
        try:
            #
            # start a long-lived boxed process owned by wulda (the target
            # for a process-scoped cross-SID start)
            #
            holder_proc = subprocess.Popen(
                [RUNNER, "DefaultBox", "nowait",
                 "C:\\Windows\\System32\\ping.exe -n 180 127.0.0.1"],
                cwd=DEPLOY, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace")
            first_line = ""
            try:
                first_line = (holder_proc.stdout.readline()
                              if holder_proc.stdout else "") or ""
            except Exception:
                first_line = ""
            hold_info = {}
            try:
                hold_info = json.loads(first_line.strip()) \
                    if first_line.strip().startswith("{") else {}
            except json.JSONDecodeError:
                hold_info = {"raw": first_line}

            target_pid = int(hold_info.get("pid", 0)) \
                if hold_info.get("pid") else 0
            crosssid_detail = {"holder": hold_info, "targetPid": target_pid}
            if target_pid:
                write_crosssid_in(target_pid)
                for p in (CROSSSID_OUT, CROSSSID_OUT_COPY):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                #
                # the driver script is written fresh each run (inherits the
                # current user's ACEs); grant Users read so the schtasks
                # principal can run it, keeping the owner's ACEs intact
                #
                current_user = os.environ.get("USERNAME") or "wulda"
                subprocess.run(
                    ["cmd", "/c", "icacls", CROSSSID_DRIVER, "/grant",
                     f"{current_user}:(F)", "Users:(R)"],
                    capture_output=True, text=True, timeout=20,
                    encoding="gbk", errors="replace")
                #
                # run the elevated batch (one UAC prompt) that creates the
                # cross-user scheduled task, runs it, and copies the driver
                # output back into EVIDENCE for the non-elevated harness
                #
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Start-Process cmd -Verb RunAs -Wait "
                     f"-ArgumentList '/c','{CROSSSID_CMD}'"],
                    capture_output=True, text=True, timeout=90)
                time.sleep(2)
                crosssid_detail["resultFileExists"] = \
                    os.path.exists(CROSSSID_OUT_COPY)
                if os.path.exists(CROSSSID_OUT_COPY):
                    lines = open(CROSSSID_OUT_COPY, encoding="utf-8",
                                 errors="replace").read()
                    crosssid_detail["raw"] = lines[-2000:]
                    crosssid_ok = "0xc0000022" in lines.lower()
                else:
                    crosssid_detail["error"] = \
                        "no output copy after elevated scheduled task"
            else:
                crosssid_detail["error"] = "no holder pid from nowait runner"
        except Exception as exc:
            crosssid_detail["error"] = str(exc)
        finally:
            if holder_proc and holder_proc.poll() is None:
                try:
                    holder_proc.terminate()
                except Exception:
                    pass
        items.append(item("11-cross-sid", crosssid_ok, crosssid_detail))

        report["live"]["items"] = items
        report["live"]["passed"] = [row["item"] for row in items if row["pass"]]
        report["live"]["failed"] = [
            row["item"] for row in items if not row["pass"] and not row["detail"].get("skipped")
        ]
        report["live"]["skipped"] = [
            row["item"] for row in items if row["detail"].get("skipped")
        ]
        stop_a = stop_a if "stop_a" in locals() else None
        report["live"]["hold"] = hold
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
