#!/usr/bin/env python3
"""
env-reader.py — The ONLY approved way to read environment variables in the pentest-bot project.
Usage: python3 tools/env-reader.py VAR1 VAR2 VAR3
"""

import sys
import os
import fnmatch
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent


def find_env_file():
    home = os.path.expanduser("~")
    current = os.path.abspath(os.getcwd())
    while True:
        candidate = os.path.join(current, ".env")
        if os.path.isfile(candidate):
            return candidate
        if current == home:
            break
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def parse_env_file(path):
    env = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n\r")
                stripped = line.lstrip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "=" not in stripped:
                    continue
                key, _, rest = stripped.partition("=")
                key = key.strip()
                if not key or not all(c.isalnum() or c == "_" for c in key):
                    continue
                value = rest
                if value.startswith('"'):
                    idx = 1
                    chars = []
                    while idx < len(value):
                        ch = value[idx]
                        if ch == "\\" and idx + 1 < len(value):
                            nxt = value[idx + 1]
                            escape_map = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "r": "\r"}
                            chars.append(escape_map.get(nxt, nxt))
                            idx += 2
                        elif ch == '"':
                            break
                        else:
                            chars.append(ch)
                            idx += 1
                    value = "".join(chars)
                elif value.startswith("'"):
                    end = value.find("'", 1)
                    value = value[1:end] if end != -1 else value[1:]
                else:
                    comment_pos = value.find(" #")
                    if comment_pos != -1:
                        value = value[:comment_pos]
                    value = value.strip()
                env[key] = value
    except OSError:
        pass
    return env


def load_allowlist(base_dir):
    """Variable-name patterns that may be read. Defends env-reader (the single
    approved secret gateway for BOTH the MCP read_env tool and Bash callers)
    against prompt-injection-driven reads of arbitrary variables.

    Sources, all additive (a name matches as an exact name or an fnmatch glob):
      1. keys declared in .env.example       — the canonical legitimate set
      2. config/env-allowlist.txt            — operator-maintained, one name/glob per line
      3. $TZAR_ENV_ALLOWLIST                  — comma-separated, for one-off overrides

    Returns (patterns:set, configured:bool). When NO source exists the allowlist
    is "unconfigured" and the caller allows all (mirrors scope.py's allow-all when
    no in-scope rules are declared) — so a bare checkout still works, but the
    shipped .env.example means the allowlist is active in practice.
    """
    patterns, configured = set(), False
    search_dirs = {base_dir, str(REPO_DIR)}

    # 1. .env.example keys
    for d in search_dirs:
        example = os.path.join(d, ".env.example")
        if os.path.isfile(example):
            keys = list(parse_env_file(example).keys())
            if keys:
                patterns.update(keys)
                configured = True

    # 2. config/env-allowlist.txt (or $TZAR_ENV_ALLOWLIST_FILE)
    cfg_paths = [os.environ.get("TZAR_ENV_ALLOWLIST_FILE")] if os.environ.get("TZAR_ENV_ALLOWLIST_FILE") else []
    cfg_paths += [os.path.join(d, "config", "env-allowlist.txt") for d in search_dirs]
    for cfg in cfg_paths:
        if cfg and os.path.isfile(cfg):
            try:
                with open(cfg, "r", encoding="utf-8") as fh:
                    for line in fh:
                        s = line.strip()
                        if s and not s.startswith("#"):
                            patterns.add(s)
                            configured = True
            except OSError:
                pass

    # 3. $TZAR_ENV_ALLOWLIST
    for name in os.environ.get("TZAR_ENV_ALLOWLIST", "").split(","):
        if name.strip():
            patterns.add(name.strip())
            configured = True

    return patterns, configured


def is_allowed(var, patterns):
    return any(fnmatch.fnmatchcase(var, p) for p in patterns)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 env-reader.py VAR1 [VAR2 ...]", file=sys.stderr)
        sys.exit(0)
    requested = sys.argv[1:]
    env_path = find_env_file()
    base_dir = os.path.dirname(env_path) if env_path else str(REPO_DIR)
    env_vars = parse_env_file(env_path) if env_path else {}
    patterns, configured = load_allowlist(base_dir)

    denied = False
    for var in requested:
        if configured and not is_allowed(var, patterns):
            denied = True
            print(f"{var}=DENIED")
            print(
                f"env-reader: '{var}' is not on the approved allow-list — refused "
                f"(never read its value). Add it to .env.example or "
                f"config/env-allowlist.txt to permit.",
                file=sys.stderr,
            )
            continue
        value = env_vars.get(var)
        print(f"{var}={value}" if value is not None else f"{var}=NOT_SET")

    sys.exit(3 if denied else 0)


if __name__ == "__main__":
    main()
