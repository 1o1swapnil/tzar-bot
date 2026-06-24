#!/usr/bin/env python3
"""
tzar — umbrella CLI dispatcher for the tzar-bot tool collection.

The tools are standalone scripts (hyphenated filenames). This dispatcher gives
them a single installable entry point so `pip install tzar-bot` puts `tzar` on
PATH without renaming every script:

    tzar <tool> [args...]     run tools/<tool>.py with the current interpreter
    tzar list                 list available tools
    tzar --version            print the package version
    tzar --help               usage

Tool names accept either hyphens or underscores (`tzar init-engagement` or
`tzar init_engagement`). Exit code is the underlying tool's exit code.
"""
import subprocess
import sys
from pathlib import Path

try:
    from . import __version__
except ImportError:  # invoked directly as `python tools/cli.py`, not as a package
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools import __version__

TOOLS_DIR = Path(__file__).resolve().parent

# Library / non-CLI modules that are not user-facing subcommands.
_HIDDEN = {"__init__", "cli", "scope", "pathguard"}


def available_tools():
    return [p.stem for p in sorted(TOOLS_DIR.glob("*.py")) if p.stem not in _HIDDEN]


def resolve(name):
    """Map a subcommand (hyphen or underscore) to a tools/<name>.py path."""
    stem = name[:-3] if name.endswith(".py") else name
    for variant in (stem, stem.replace("_", "-"), stem.replace("-", "_")):
        candidate = TOOLS_DIR / f"{variant}.py"
        if candidate.is_file():
            return candidate
    return None


def _usage():
    print(
        "usage: tzar <tool> [args...]\n"
        "       tzar list            # list available tools\n"
        "       tzar --version\n\n"
        "Examples:\n"
        "  tzar init-engagement --type WAPT --project acme --target https://acme.com\n"
        "  tzar scope --selftest\n"
        "  tzar validate-finding --strict -- \"$OUTPUT_DIR/findings/finding-001\"\n\n"
        "Run 'tzar list' to see all tools."
    )


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        _usage()
        return 0
    if argv[0] in ("-V", "--version"):
        print(f"tzar-bot {__version__}")
        return 0
    if argv[0] == "list":
        for name in available_tools():
            print(name)
        return 0

    script = resolve(argv[0])
    if script is None:
        print(f"tzar: unknown tool {argv[0]!r}. Try 'tzar list'.", file=sys.stderr)
        return 2
    return subprocess.run([sys.executable, str(script), *argv[1:]]).returncode


if __name__ == "__main__":
    sys.exit(main())
