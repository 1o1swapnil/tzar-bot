#!/usr/bin/env python3
"""
env-reader.py — The ONLY approved way to read environment variables in the pentest-bot project.
Usage: python3 tools/env-reader.py VAR1 VAR2 VAR3
"""

import sys
import os


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


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 env-reader.py VAR1 [VAR2 ...]", file=sys.stderr)
        sys.exit(0)
    requested = sys.argv[1:]
    env_path = find_env_file()
    env_vars = parse_env_file(env_path) if env_path else {}
    for var in requested:
        value = env_vars.get(var)
        if value is not None:
            print(f"{var}={value}")
        else:
            print(f"{var}=NOT_SET")
    sys.exit(0)


if __name__ == "__main__":
    main()
