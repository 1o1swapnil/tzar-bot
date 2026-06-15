#!/usr/bin/env python3
"""
Prompt injection scrubber — strip adversarial instructions from web-sourced content
before embedding it in executor/validator agent prompts.

Usage:
    # Pipe
    cat OUTPUT_DIR/recon/response.txt | python3 tools/scrub-web-content.py

    # File
    python3 tools/scrub-web-content.py OUTPUT_DIR/recon/response.txt

    # Inline string
    python3 tools/scrub-web-content.py --text "raw content here"

Exit codes: 0 = clean, 1 = injections detected and scrubbed
"""
import re
import sys
import json
import argparse

# Patterns that indicate an injection attempt embedded in web content.
# Each entry: (compiled_regex, human_label)
_PATTERNS = [
    # Classic override phrases
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", re.I), "instruction-override"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I), "instruction-override"),
    (re.compile(r"forget\s+(everything|all)\s+(you('ve)?\s+)?(been\s+)?(told|learned|said)", re.I), "instruction-override"),
    (re.compile(r"your\s+(new|actual|real|true)\s+(instructions?|task|goal|purpose|role)\s+(is|are)", re.I), "role-override"),
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I), "role-override"),
    (re.compile(r"act\s+as\s+(a|an|the)\s+\w+\s+(with\s+no|without)\s+(restrictions?|limits?|rules?|ethics)", re.I), "jailbreak"),
    # Prompt delimiter injection
    (re.compile(r"<\s*/?\s*system\s*>", re.I), "delimiter-injection"),
    (re.compile(r"\[\s*SYSTEM\s*\]", re.I), "delimiter-injection"),
    (re.compile(r"#{3,}\s*SYSTEM\s*#{0,}", re.I), "delimiter-injection"),
    (re.compile(r"---+\s*(SYSTEM|HUMAN|ASSISTANT|USER)\s*---+", re.I), "delimiter-injection"),
    # Role/persona switches
    (re.compile(r"\b(system|assistant|user)\s*:\s*(you are|your role|your task)", re.I), "role-prefix"),
    (re.compile(r"print\s+(the\s+)?(system\s+prompt|instructions?|prompt)", re.I), "exfil-attempt"),
    (re.compile(r"reveal\s+(your\s+)?(system\s+prompt|instructions?|configuration)", re.I), "exfil-attempt"),
    (re.compile(r"output\s+(your\s+)?(full\s+)?(system\s+prompt|initial\s+prompt)", re.I), "exfil-attempt"),
    # Exfiltration / callback instructions
    (re.compile(r"(send|post|fetch|curl|wget|http\s+request)\s+(to\s+)?(http|https)://(?!target|scope)", re.I), "exfil-callback"),
    (re.compile(r"exfiltrate\s+(the\s+)?(api\s+key|secret|token|credentials?|password)", re.I), "exfil-attempt"),
    # Behavioral override
    (re.compile(r"(do\s+not|don't|never)\s+(report|document|log|write|save)\s+(this|these|the)", re.I), "suppress-logging"),
    (re.compile(r"keep\s+(this|these|the\s+following)\s+(secret|hidden|confidential)\s+from", re.I), "suppress-logging"),
    (re.compile(r"(escalate|pivot|attack|exploit)\s+(?!within scope|the target)", re.I), "out-of-scope-directive"),
]

_PLACEHOLDER = "[SCRUBBED:{}]"


def scrub(text: str) -> tuple[str, list[dict]]:
    """Return (scrubbed_text, list_of_hits). hit = {label, match, start, end}"""
    # Collect all matches across all patterns first, then replace right-to-left
    # to avoid offset drift when replacements change string length.
    raw_hits = []
    seen_spans = set()
    for pattern, label in _PATTERNS:
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            if span in seen_spans:
                continue  # deduplicate overlapping pattern matches
            seen_spans.add(span)
            raw_hits.append((m.start(), m.end(), label, m.group()))

    # Sort descending by start position so right-to-left replacement is safe
    raw_hits.sort(key=lambda h: h[0], reverse=True)

    result = text
    hits = []
    for start, end, label, match in raw_hits:
        replacement = _PLACEHOLDER.format(label)
        result = result[:start] + replacement + result[end:]
        hits.append({"label": label, "match": match, "start": start, "end": end})

    hits.sort(key=lambda h: h["start"])  # return hits in document order
    return result, hits


def main():
    parser = argparse.ArgumentParser(description="Scrub prompt injection from web content")
    parser.add_argument("file", nargs="?", help="File to scrub (default: stdin)")
    parser.add_argument("--text", help="Inline string to scrub")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Emit JSON report instead of scrubbed text")
    args = parser.parse_args()

    if args.text:
        raw = args.text
    elif args.file:
        with open(args.file, "r", errors="replace") as f:
            raw = f.read()
    else:
        raw = sys.stdin.read()

    scrubbed, hits = scrub(raw)

    if args.json_out:
        print(json.dumps({"injections_found": len(hits), "hits": hits, "scrubbed": scrubbed}, indent=2))
    else:
        if hits:
            print(f"# [scrubber] {len(hits)} injection pattern(s) removed", file=sys.stderr)
            for h in hits:
                print(f"#   [{h['label']}] {h['match']!r}", file=sys.stderr)
        print(scrubbed, end="")

    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
