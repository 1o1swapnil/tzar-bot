#!/usr/bin/env python3
"""
burp-playwright-capture.py — fully-automated web evidence capture.

Combines two engines, no manual clicks and no desktop screenshots:

  * Playwright  — renders the target page in a real browser and screenshots it
                  (the same engine the "playwright" MCP server wraps).
  * Burp Suite  — issues the HTTP request through Burp's MCP server
                  (send_http1_request) and returns the request/response Burp saw.

It drops the evidence into a finding folder, writes a highlights.json so the
screenshots are annotated by generate-report.py, and (optionally) builds the PDF.

Why no Burp-UI screenshot: Burp's MCP exposes HTTP tooling, not a screenshot of
its own Java window, and Playwright only screenshots web pages — so the Burp
evidence here is the request/response *data* Burp captured, rendered to an image.

Usage:
  python3 tools/burp-playwright-capture.py \
      --target http://zero.webappsecurity.com/ \
      --output-dir "$OUTPUT_DIR" \
      [--finding-id finding-001] [--burp-url http://127.0.0.1:9876] \
      [--chrome /path/to/chrome] [--report] [--client NAME]

Requires: playwright (pip) + a chromium (playwright install chromium, or --chrome),
and Burp running with the MCP server enabled.
"""
import argparse, json, os, re, sys, threading, time, uuid, urllib.request, urllib.parse
from pathlib import Path

# ───────────────────────────── Burp MCP (SSE) client ─────────────────────────
class BurpMCP:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.responses = {}
        self.endpoint = None
        self._done = threading.Event()
        self._rid = 0

    def _reader(self):
        req = urllib.request.Request(self.base, headers={"Accept": "text/event-stream"})
        with urllib.request.urlopen(req, timeout=30) as r:
            event = None
            for raw in r:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line.startswith("event:"):
                    event = line.split(":", 1)[1].strip()
                elif line.startswith("data:"):
                    data = line.split(":", 1)[1].strip()
                    if event == "endpoint":
                        self.endpoint = urllib.parse.urljoin(self.base + "/", data)
                    else:
                        try:
                            m = json.loads(data)
                            if "id" in m:
                                self.responses[m["id"]] = m
                        except Exception:
                            pass
                    event = None
                if self._done.is_set():
                    break

    def _post(self, payload):
        req = urllib.request.Request(self.endpoint, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=20).read()

    def _wait(self, rid, t=25):
        end = time.time() + t
        while time.time() < end:
            if rid in self.responses:
                return self.responses[rid]
            time.sleep(0.05)
        return None

    def connect(self):
        threading.Thread(target=self._reader, daemon=True).start()
        for _ in range(120):
            if self.endpoint:
                break
            time.sleep(0.05)
        if not self.endpoint:
            raise RuntimeError("Burp MCP: no SSE endpoint (is Burp running with MCP enabled?)")
        self._rid += 1
        self._post({"jsonrpc": "2.0", "id": self._rid, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "tzar-capture", "version": "1.0"}}})
        self._wait(self._rid)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call(self, name, arguments):
        self._rid += 1
        self._post({"jsonrpc": "2.0", "id": self._rid, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments}})
        res = self._wait(self._rid)
        text = ""
        for c in (res or {}).get("result", {}).get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        return text

    def close(self):
        self._done.set()


def burp_capture(mcp, host, port, https, path="/"):
    """Issue the request via Burp and return (request_text, response_text, marker)."""
    marker = "tzar-" + uuid.uuid4().hex[:10]
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: BURP-MCP-ISSUED\r\nX-Tzar-Proof: {marker}\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n")
    out = mcp.call("send_http1_request",
                   {"content": req, "targetHostname": host, "targetPort": port, "usesHttps": https})
    m = re.search(r"httpRequest=(.*?), httpResponse=(.*)}\s*$", out, re.S)
    reqtxt = (m.group(1) if m else req).strip("\r\n")
    resptxt = (m.group(2) if m else out).strip("\r\n")
    return reqtxt, resptxt, marker


# ───────────────────────────── Playwright screenshot ────────────────────────
def playwright_screenshot(url, out_png, chrome=None, width=1280, height=900):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        launch = {"headless": True}
        if chrome:
            launch["executable_path"] = chrome
        browser = p.chromium.launch(**launch)
        page = browser.new_page(viewport={"width": width, "height": height})
        page.goto(url, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(1200)
        page.screenshot(path=out_png, full_page=False)
        title = page.title()
        browser.close()
    return title


# ───────────────────────────── evidence rendering ───────────────────────────
def render_http_image(reqtxt, resptxt, out_png):
    """Render request + response headers to an image; return highlight boxes."""
    from PIL import Image, ImageDraw, ImageFont
    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", 22)
    except Exception:
        font = ImageFont.load_default()
    resp_headers = re.split(r"\r?\n\r?\n", resptxt, maxsplit=1)[0]
    rows = (["# Request issued by Burp (send_http1_request)"]
            + reqtxt.splitlines()
            + ["", "# Response captured by Burp"]
            + resp_headers.splitlines())
    pad, lh, W = 24, 30, 1000
    H = pad * 2 + lh * len(rows)
    im = Image.new("RGB", (W, H), (13, 17, 23))
    d = ImageDraw.Draw(im)
    boxes = []
    for i, line in enumerate(rows):
        y = pad + lh * i
        low = line.lower()
        if line.startswith("#"):
            col = (120, 200, 120)
        elif low.startswith("server:"):
            col = (255, 210, 120)
        elif low.startswith("x-tzar-proof:"):
            col = (150, 230, 170)
        else:
            col = (220, 227, 234)
        d.text((pad, y), line, fill=col, font=font)
        if low.startswith("server:"):
            tb = d.textbbox((pad, y), line, font=font)
            boxes.append({"x": pad - 8, "y": y - 5, "w": tb[2] - tb[0] + 16, "h": lh,
                          "label": "Server banner (version disclosure)", "color": "red"})
        if low.startswith("x-tzar-proof:"):
            tb = d.textbbox((pad, y), line, font=font)
            boxes.append({"x": pad - 8, "y": y - 5, "w": tb[2] - tb[0] + 16, "h": lh,
                          "label": "Proof marker - request issued by Burp", "color": "green"})
    im.save(out_png)
    return boxes


def scan_components(resptxt):
    """Find <lib>-<version> references in the response body (outdated-component hints)."""
    found = {}
    for m in re.finditer(r'/([a-zA-Z][\w.-]*?)-(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', resptxt):
        found.setdefault(m.group(1).lower(), m.group(2))
    return found


# ───────────────────────────── finding writer ───────────────────────────────
def write_finding(fdir, host, target, server, components, marker):
    comp_lines = "\n".join(f"  - **{k} {v}** referenced in the page." for k, v in components.items()) \
        or "  - (no versioned client-side components detected)"
    md = f"""# Finding: Server and Component Version Disclosure (Passive)

| Field | Value |
|-------|-------|
| Severity | Low |
| CVSS Score | 3.7 |
| CVSS Vector | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N |
| CWE | CWE-200: Exposure of Sensitive Information |
| OWASP | A05:2021 - Security Misconfiguration |
| Affected Component | {target} |

## Description
Passive analysis of the HTTP response captured by Burp Suite shows the application
discloses server/technology versions. The request was issued by Burp
(`send_http1_request`) and the page was rendered by Playwright for visual context.
No active or intrusive testing was performed.

- **Server banner:** `Server: {server or 'n/a'}`.
{comp_lines}

## Steps to Reproduce
1. Issue `GET /` to the target through Burp Suite.
2. Inspect the response `Server` header and the referenced client-side scripts.

## Business Impact
Version/technology disclosure lowers the effort to fingerprint the stack and select
known exploits; low on its own but compounds other weaknesses.

## Remediation
- Suppress or genericise the `Server` header.
- Upgrade outdated client-side libraries to current, supported releases.
- Review third-party components for known-vulnerable versions.

## Evidence
Captured automatically: Burp issued the request (marker `X-Tzar-Proof: {marker}`),
Playwright rendered the page.

- `burp-http-evidence.png` - Burp-issued request + response; `Server` (red) and the
  proof marker (green) highlighted.
- `page-screenshot.png` - the target page rendered by Playwright.
- `burp-capture.txt` - raw Burp request/response headers.
"""
    (fdir / "description.md").write_text(md)


# ───────────────────────────── main ─────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="Target URL, e.g. http://host/")
    ap.add_argument("--output-dir", required=True, help="Engagement OUTPUT_DIR")
    ap.add_argument("--finding-id", default="finding-001")
    ap.add_argument("--burp-url", default="http://127.0.0.1:9876")
    ap.add_argument("--chrome", default=None, help="Chrome/Chromium path (else Playwright's own)")
    ap.add_argument("--report", action="store_true", help="Also run generate-report.py")
    ap.add_argument("--client", default="", help="Client name for the report")
    args = ap.parse_args()

    u = urllib.parse.urlparse(args.target if "://" in args.target else "http://" + args.target)
    host = u.hostname
    https = (u.scheme == "https")
    port = u.port or (443 if https else 80)
    path = u.path or "/"

    out = Path(args.output_dir)
    fdir = out / "findings" / args.finding_id / "evidence"
    fdir.mkdir(parents=True, exist_ok=True)

    # 1) Burp issues the request and returns what it captured
    print(f"[*] Burp MCP ({args.burp_url}): issuing GET {path} to {host}:{port} ...")
    mcp = BurpMCP(args.burp_url)
    mcp.connect()
    reqtxt, resptxt, marker = burp_capture(mcp, host, port, https, path)
    mcp.close()
    server = ""
    m = re.search(r"(?im)^Server:\s*(.+)$", resptxt)
    if m:
        server = m.group(1).strip()
    components = scan_components(resptxt)
    print(f"    Server: {server or 'n/a'} | components: {components or 'none'}")
    (fdir / "burp-capture.txt").write_text(
        "### Issued by Burp Suite via send_http1_request ###\n\n--- REQUEST ---\n"
        + reqtxt + "\n\n--- RESPONSE (headers) ---\n"
        + re.split(r'\r?\n\r?\n', resptxt, maxsplit=1)[0] + "\n")

    # 2) render the Burp HTTP evidence image (with highlights)
    burp_boxes = render_http_image(reqtxt, resptxt, str(fdir / "burp-http-evidence.png"))

    # 3) Playwright screenshots the page
    print(f"[*] Playwright: rendering {args.target} ...")
    try:
        title = playwright_screenshot(args.target, str(fdir / "page-screenshot.png"), chrome=args.chrome)
        print(f"    page title: {title}")
        page_ok = True
    except Exception as e:
        print(f"[!] Playwright screenshot failed: {e}")
        page_ok = False

    # 4) highlights.json
    highlights = {"burp-http-evidence.png": burp_boxes}
    if page_ok:
        highlights["page-screenshot.png"] = [
            {"x": 0.01, "y": 0.012, "w": 0.975, "h": 0.07,
             "label": f"Live target rendered by Playwright", "color": "green", "norm": True}]
    (fdir / "highlights.json").write_text(json.dumps(highlights, indent=2))

    # 5) finding (description.md lives in the finding dir, beside evidence/)
    write_finding(fdir.parent, host, args.target, server, components, marker)
    print(f"[+] evidence written to {fdir}")

    # 6) optional report
    if args.report:
        import subprocess
        here = Path(__file__).parent
        cmd = [sys.executable, str(here / "generate-report.py"), str(out),
               "--target", args.target]
        if args.client:
            cmd += ["--client", args.client]
        print("[*] generating report ...")
        subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
