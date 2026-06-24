#!/usr/bin/env python3
"""
playwright-mcp-server.py — MCP server exposing Playwright browser automation
for authenticated session testing, OAuth flows, multi-step workflows, and
evidence capture.

Registered in .mcp.json as "playwright". Maintains a single stateful browser
session for the lifetime of the server process.

Install prerequisites:
    sudo apt-get install -y python3-playwright
    python3 -m playwright install chromium

Tools exposed:
    browser_navigate       Navigate to a URL, return title + final URL
    browser_click          Click element by text, role, or CSS selector
    browser_fill           Fill input field by label, placeholder, or selector
    browser_type           Type text character-by-character (for complex inputs)
    browser_screenshot     Save screenshot to OUTPUT_DIR/screenshots/<name>.png
    browser_get_text       Return visible text content of page or element
    browser_get_cookies    Export session cookies as JSON (for reuse in curl)
    browser_set_cookies    Inject cookies (restore a captured session)
    browser_evaluate       Run JavaScript and return result
    browser_export_session Export cookies + localStorage as curl-ready headers
    browser_export_har     Save HAR file of all network requests to OUTPUT_DIR
    browser_launch         Launch / reset the browser (call first or to reset)
    browser_close          Close the browser and end the session
"""

import sys
import os
import json
import traceback
from pathlib import Path
from urllib.parse import urlparse

TOOLS_DIR = Path(__file__).parent.resolve()
REPO_DIR  = TOOLS_DIR.parent

# Reuse the single code-enforced scope authority (same module the Bash
# PreToolUse hook uses) so the browser is a first-class scope citizen.
sys.path.insert(0, str(TOOLS_DIR))
from scope import Scope, host_of  # noqa: E402

# Web-only: every other scheme (file:, chrome:, data:, ftp:, …) is a local
# file-read / internal-resource vector and is never a legitimate target here.
_ALLOWED_SCHEMES = {"http", "https", "about"}

# Cloud-metadata endpoints — never a legitimate browser target unless the
# engagement explicitly scopes them in.
_METADATA_HOSTS = {
    "169.254.169.254", "fd00:ec2::254",          # AWS / GCP / Azure IMDS
    "100.100.200.200",                            # Alibaba
    "metadata", "metadata.google.internal",       # GCP by name
}


def _load_scope() -> Scope:
    """Load engagement scope from $OUTPUT_DIR/engagement.json (same as the hook)."""
    output_dir = os.environ.get("OUTPUT_DIR", "")
    if output_dir:
        meta = Path(output_dir) / "engagement.json"
        if meta.exists():
            try:
                return Scope.load(meta)
            except Exception:
                pass
    return Scope()


def _guard_url(url: str):
    """Return None if the browser may visit `url`, else a human-readable reason.

    Deny-wins / default-deny, delegated to scope.py — identical semantics to the
    Bash scope-check hook, which does NOT see MCP calls. Hard blocks (non-web
    schemes, cloud-metadata IPs) apply even when no engagement scope is active.
    """
    if not url or not url.strip():
        return "empty URL"
    parsed = urlparse(url if "://" in url else "//" + url)
    scheme = (parsed.scheme or "").lower()
    if scheme and scheme not in _ALLOWED_SCHEMES:
        return f"non-web scheme '{scheme}:' is blocked (only http/https allowed)"
    host = host_of(url)
    if not host:
        return "could not parse host from URL"
    scope = _load_scope()
    if host in _METADATA_HOSTS and not scope.in_scope_host(url):
        return f"{host} is a cloud-metadata endpoint — blocked"
    if scope.active:
        return scope.reject_reason(url)   # None when in scope
    return None


# ── Browser state (lives for the lifetime of the server process) ──────────────
_playwright = None
_browser    = None
_context    = None
_page       = None


def _ensure_browser(headless: bool = True):
    global _playwright, _browser, _context, _page
    if _page is not None:
        return
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "Playwright not installed. Run:\n"
            "  sudo apt-get install -y python3-playwright\n"
            "  python3 -m playwright install chromium"
        )
    _playwright = sync_playwright().start()
    _browser    = _playwright.chromium.launch(headless=headless)
    _context    = _browser.new_context(
        viewport={"width": 1280, "height": 800},
        record_har_path=None,
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
    )
    _page = _context.new_page()


def _resolve_selector(target: str) -> str:
    """If target looks like a CSS selector, use it directly; otherwise use text."""
    if target.startswith(("#", ".", "[", "//", "xpath=", "css=", "text=")):
        return target
    return f"text={target}"


# ── Tool implementations ──────────────────────────────────────────────────────

def tool_browser_launch(args: dict) -> tuple[str, bool]:
    global _playwright, _browser, _context, _page
    # Close existing session if any
    try:
        if _page:
            _page.close()
        if _context:
            _context.close()
        if _browser:
            _browser.close()
        if _playwright:
            _playwright.stop()
    except Exception:
        pass
    _playwright = _browser = _context = _page = None

    url = args.get("url", "")
    if url:
        reason = _guard_url(url)
        if reason:
            return f"BLOCKED (scope): {reason}", True

    headless = args.get("headless", True)
    _ensure_browser(headless=headless)
    if url:
        _page.goto(url, wait_until="domcontentloaded", timeout=30000)
        return f"Browser launched. Navigated to: {_page.url}\nTitle: {_page.title()}", False
    return f"Browser launched (headless={headless}). No initial URL.", False


def tool_browser_navigate(args: dict) -> tuple[str, bool]:
    url      = args["url"]
    reason = _guard_url(url)
    if reason:
        return f"BLOCKED (scope): {reason}", True
    _ensure_browser()
    wait_for = args.get("wait_for", "domcontentloaded")
    _page.goto(url, wait_until=wait_for, timeout=30000)
    return f"Navigated to: {_page.url}\nTitle: {_page.title()}", False


def tool_browser_click(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    target  = args["target"]
    timeout = args.get("timeout", 10000)
    sel = _resolve_selector(target)
    _page.click(sel, timeout=timeout)
    _page.wait_for_load_state("domcontentloaded")
    return f"Clicked: {target!r}\nCurrent URL: {_page.url}", False


def tool_browser_fill(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    target = args["target"]   # label text, placeholder, or CSS selector
    value  = args["value"]
    sel    = _resolve_selector(target)
    _page.fill(sel, value, timeout=10000)
    return f"Filled {target!r} with value (length {len(value)})", False


def tool_browser_type(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    target = args["target"]
    text   = args["text"]
    delay  = args.get("delay", 50)  # ms between keystrokes
    sel    = _resolve_selector(target)
    _page.type(sel, text, delay=delay, timeout=10000)
    return f"Typed into {target!r} (length {len(text)})", False


def tool_browser_screenshot(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    name       = args.get("name", "screenshot")
    output_dir = args.get("output_dir", "")
    full_page  = args.get("full_page", False)

    if output_dir:
        save_dir = Path(output_dir) / "screenshots"
    else:
        save_dir = REPO_DIR / "screenshots"
    save_dir.mkdir(parents=True, exist_ok=True)

    path = save_dir / f"{name}.png"
    _page.screenshot(path=str(path), full_page=full_page)
    return f"Screenshot saved: {path}\nURL: {_page.url}", False


def tool_browser_get_text(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    selector = args.get("selector", "body")
    try:
        element = _page.locator(selector).first
        text    = element.inner_text(timeout=5000)
    except Exception:
        text = _page.inner_text("body")
    # Trim very long pages
    if len(text) > 8000:
        text = text[:8000] + "\n...[truncated]"
    return text, False


def tool_browser_get_cookies(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    cookies = _context.cookies()
    # Produce both JSON (for programmatic use) and curl format
    curl_cookies = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    result = {
        "count":        len(cookies),
        "cookies":      cookies,
        "curl_header":  f"Cookie: {curl_cookies}",
        "curl_flag":    f"-H 'Cookie: {curl_cookies}'",
    }
    return json.dumps(result, indent=2), False


def tool_browser_set_cookies(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    cookies = args["cookies"]  # list of {name, value, domain, path, ...}
    _context.add_cookies(cookies)
    return f"Injected {len(cookies)} cookie(s) into browser context.", False


def tool_browser_evaluate(args: dict) -> tuple[str, bool]:
    _ensure_browser()
    script = args["script"]
    result = _page.evaluate(script)
    return json.dumps(result, default=str), False


def tool_browser_export_session(args: dict) -> tuple[str, bool]:
    """Export cookies + localStorage as curl-ready headers and raw values."""
    _ensure_browser()
    cookies     = _context.cookies()
    curl_cookie = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    local_storage = _page.evaluate("""() => {
        const items = {};
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            items[key] = localStorage.getItem(key);
        }
        return items;
    }""")
    session_storage = _page.evaluate("""() => {
        const items = {};
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            items[key] = sessionStorage.getItem(key);
        }
        return items;
    }""")

    output_dir = args.get("output_dir", "")
    if output_dir:
        session_file = Path(output_dir) / "artifacts" / "browser-session.json"
        session_file.parent.mkdir(parents=True, exist_ok=True)
        session_file.write_text(json.dumps({
            "cookies": cookies,
            "local_storage": local_storage,
            "session_storage": session_storage,
        }, indent=2))
        saved_msg = f"\nSaved to: {session_file}"
    else:
        saved_msg = ""

    result = {
        "curl_cookie_header": f"-H 'Cookie: {curl_cookie}'",
        "cookies":            cookies,
        "local_storage":      local_storage,
        "session_storage":    session_storage,
    }
    return json.dumps(result, indent=2) + saved_msg, False


def tool_browser_export_har(args: dict) -> tuple[str, bool]:
    """
    Re-navigate with HAR recording enabled and export network traffic.
    Starts a fresh page with HAR recording.
    """
    global _context, _page
    _ensure_browser()

    output_dir = args.get("output_dir", "")
    name       = args.get("name", "capture")
    url        = args.get("url", _page.url)

    reason = _guard_url(url)
    if reason:
        return f"BLOCKED (scope): {reason}", True

    if output_dir:
        har_path = Path(output_dir) / "artifacts" / f"{name}.har"
        har_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        har_path = REPO_DIR / f"{name}.har"

    # Open a new page with HAR recording
    har_page = _context.new_page()
    har_page.route_from_har(str(har_path), not_found="fallback") if har_path.exists() else None
    with _context.expect_page() if False else _context.new_page() as _:
        pass
    # Use record_har context manager pattern
    har_ctx = _browser.new_context(record_har_path=str(har_path))
    har_pg  = har_ctx.new_page()
    har_pg.goto(url, wait_until="networkidle", timeout=30000)
    har_ctx.close()  # closing context flushes HAR

    return f"HAR exported to: {har_path}\nURL captured: {url}", False


def tool_browser_close(args: dict) -> tuple[str, bool]:
    global _playwright, _browser, _context, _page
    try:
        if _page:    _page.close()
        if _context: _context.close()
        if _browser: _browser.close()
        if _playwright: _playwright.stop()
    except Exception as e:
        return f"Close error (non-fatal): {e}", False
    finally:
        _playwright = _browser = _context = _page = None
    return "Browser closed.", False


# ── MCP tool schemas ──────────────────────────────────────────────────────────

TOOL_DEFS = [
    {
        "name": "browser_launch",
        "description": "Launch (or reset) the browser. Call this first, or to start a fresh session. Optionally navigate to an initial URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":      {"type": "string", "description": "Initial URL to navigate to (optional)"},
                "headless": {"type": "boolean", "description": "Run headless (default true)", "default": True},
            },
        },
    },
    {
        "name": "browser_navigate",
        "description": "Navigate the browser to a URL. Returns page title and final URL after any redirects.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":      {"type": "string", "description": "URL to navigate to"},
                "wait_for": {"type": "string", "description": "Wait condition: domcontentloaded | load | networkidle", "default": "domcontentloaded"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "browser_click",
        "description": "Click an element. Use visible text, role (e.g. 'button[name=Submit]'), or CSS selector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":  {"type": "string", "description": "Visible text, CSS selector, or XPath"},
                "timeout": {"type": "integer", "description": "Timeout in ms (default 10000)"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "browser_fill",
        "description": "Fill a form input field with a value. Use the visible label text, placeholder text, or CSS selector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Label text, placeholder, or CSS selector of the input"},
                "value":  {"type": "string", "description": "Value to fill in"},
            },
            "required": ["target", "value"],
        },
    },
    {
        "name": "browser_type",
        "description": "Type text character-by-character into an element (use for autocomplete/dynamic inputs).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "CSS selector or text of the input"},
                "text":   {"type": "string", "description": "Text to type"},
                "delay":  {"type": "integer", "description": "Delay between keystrokes in ms (default 50)"},
            },
            "required": ["target", "text"],
        },
    },
    {
        "name": "browser_screenshot",
        "description": "Take a screenshot of the current page and save it to OUTPUT_DIR/screenshots/<name>.png.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name":       {"type": "string", "description": "Filename (without .png)", "default": "screenshot"},
                "output_dir": {"type": "string", "description": "Engagement OUTPUT_DIR"},
                "full_page":  {"type": "boolean", "description": "Capture full scrollable page (default false)"},
            },
        },
    },
    {
        "name": "browser_get_text",
        "description": "Return visible text content of the page or a specific element.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS selector (default: body)", "default": "body"},
            },
        },
    },
    {
        "name": "browser_get_cookies",
        "description": "Export current browser cookies as JSON and as a curl-ready Cookie header.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "browser_set_cookies",
        "description": "Inject cookies into the browser context to restore a captured session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cookies": {
                    "type": "array",
                    "description": "Array of cookie objects with name, value, domain, path",
                    "items": {"type": "object"},
                },
            },
            "required": ["cookies"],
        },
    },
    {
        "name": "browser_evaluate",
        "description": "Execute JavaScript in the browser page context and return the result.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "JavaScript to evaluate (use return for values)"},
            },
            "required": ["script"],
        },
    },
    {
        "name": "browser_export_session",
        "description": "Export cookies + localStorage + sessionStorage as curl-ready headers. Saves to OUTPUT_DIR/artifacts/browser-session.json.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string", "description": "Engagement OUTPUT_DIR"},
            },
        },
    },
    {
        "name": "browser_export_har",
        "description": "Record a page load with full network capture and export as a HAR file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":        {"type": "string", "description": "URL to capture (defaults to current page)"},
                "name":       {"type": "string", "description": "HAR filename prefix", "default": "capture"},
                "output_dir": {"type": "string", "description": "Engagement OUTPUT_DIR"},
            },
        },
    },
    {
        "name": "browser_close",
        "description": "Close the browser and end the session. Call when done with browser testing.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

HANDLERS = {
    "browser_launch":         tool_browser_launch,
    "browser_navigate":       tool_browser_navigate,
    "browser_click":          tool_browser_click,
    "browser_fill":           tool_browser_fill,
    "browser_type":           tool_browser_type,
    "browser_screenshot":     tool_browser_screenshot,
    "browser_get_text":       tool_browser_get_text,
    "browser_get_cookies":    tool_browser_get_cookies,
    "browser_set_cookies":    tool_browser_set_cookies,
    "browser_evaluate":       tool_browser_evaluate,
    "browser_export_session": tool_browser_export_session,
    "browser_export_har":     tool_browser_export_har,
    "browser_close":          tool_browser_close,
}


# ── MCP stdio framing ─────────────────────────────────────────────────────────

def read_message():
    """Read one newline-delimited JSON-RPC message from stdin (MCP stdio transport)."""
    while True:
        raw = sys.stdin.buffer.readline()
        if not raw:
            return None
        line = raw.strip()
        if not line:
            continue  # skip blank lines between messages
        try:
            return json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # A malformed line must not crash the server — skip and keep serving.
            sys.stderr.write("[playwright-mcp] skipping malformed JSON-RPC line\n")
            sys.stderr.flush()
            continue


def send_message(obj):
    """Write one newline-delimited JSON-RPC message to stdout (MCP stdio transport)."""
    body = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(body + b"\n")
    sys.stdout.buffer.flush()


def dispatch(msg):
    method = msg.get("method", "")
    msg_id = msg.get("id")
    params = msg.get("params", {})

    if msg_id is None:
        return None

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "playwright", "version": "1.0.0"},
        }}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOL_DEFS}}

    if method == "tools/call":
        name    = params.get("name", "")
        handler = HANDLERS.get(name)
        if not handler:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
        try:
            text, is_error = handler(params.get("arguments", {}))
        except Exception as exc:
            text, is_error = f"Error: {exc}\n{traceback.format_exc()}", True
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }}

    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main():
    while True:
        msg = read_message()
        if msg is None:
            break
        response = dispatch(msg)
        if response is not None:
            send_message(response)
    # Clean up on exit
    tool_browser_close({})


if __name__ == "__main__":
    main()
