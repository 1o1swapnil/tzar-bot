#!/usr/bin/env python3
"""
pathguard.py — keep tool file writes inside the engagement sandbox.

Two guarantees, enforced in CODE (not by trusting tool arguments):
  1. The final path stays within the given output_dir — a malicious
     name/subpath ('../../etc/cron.d/x', '/etc/passwd') cannot escape the
     engagement folder.
  2. output_dir itself resolves within an allowed engagement root — a caller
     cannot redirect writes to ~/.ssh, /etc, or anywhere off-sandbox.

This is the code-enforced form of the "never write to repo root — always route
into the engagement folder" routing rule.

Allowed roots (any one suffices):
  - the tzar-bot repo directory
  - the active $OUTPUT_DIR
  - any path in $TZAR_ENGAGEMENT_ROOTS (os.pathsep-separated)
"""
import os
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent


def allowed_roots():
    candidates = [REPO_DIR]
    env_out = os.environ.get("OUTPUT_DIR", "").strip()
    if env_out:
        candidates.append(Path(env_out))
    for extra in os.environ.get("TZAR_ENGAGEMENT_ROOTS", "").split(os.pathsep):
        if extra.strip():
            candidates.append(Path(extra.strip()))
    roots = []
    for c in candidates:
        try:
            roots.append(c.resolve())
        except OSError:
            pass
    return roots


def _within(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def safe_output_path(output_dir, *subparts):
    """Resolve <output_dir>/<subparts> safely.

    Raises ValueError if output_dir is outside the allowed roots, or if the
    resolved path escapes output_dir. Returns the resolved Path otherwise.
    """
    if not output_dir or not str(output_dir).strip():
        raise ValueError("output_dir is required for a contained write")
    base = Path(output_dir).resolve()
    roots = allowed_roots()
    if not any(_within(base, r) for r in roots):
        raise ValueError(
            f"output_dir '{base}' is outside the allowed engagement root(s) "
            f"{[str(r) for r in roots]} — set $OUTPUT_DIR or $TZAR_ENGAGEMENT_ROOTS to permit it"
        )
    target = (base / Path(*subparts)).resolve() if subparts else base
    if not _within(target, base):
        raise ValueError(f"path '{target}' escapes output_dir '{base}' — traversal blocked")
    return target


def _selftest():
    import tempfile
    repo = str(REPO_DIR)
    # in-repo engagement dir is allowed; nested subpath is fine
    p = safe_output_path(repo + "/WAPT/x", "screenshots", "shot.png")
    assert str(p).endswith("/WAPT/x/screenshots/shot.png")
    # traversal in the subpath is blocked
    for bad in ("../../../../etc/passwd", "/etc/passwd", "../../../.ssh/authorized_keys"):
        try:
            safe_output_path(repo + "/WAPT/x", bad)
            raise AssertionError(f"traversal not blocked: {bad}")
        except ValueError:
            pass
    # output_dir outside any allowed root is blocked
    outside = tempfile.mkdtemp()  # /tmp/... — not under repo, no $OUTPUT_DIR set
    os.environ.pop("OUTPUT_DIR", None)
    os.environ.pop("TZAR_ENGAGEMENT_ROOTS", None)
    try:
        safe_output_path(outside, "artifacts", "x.json")
        raise AssertionError("out-of-root output_dir not blocked")
    except ValueError:
        pass
    # ...but allowed once it is named as a root via env
    os.environ["TZAR_ENGAGEMENT_ROOTS"] = outside
    assert safe_output_path(outside, "artifacts", "x.json")
    os.environ.pop("TZAR_ENGAGEMENT_ROOTS", None)
    print("pathguard.py self-test: PASS")


if __name__ == "__main__":
    _selftest()
