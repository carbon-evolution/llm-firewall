#!/usr/bin/env python3
"""Reference rival adapter. Reads a prompt on stdin, prints '1' (malicious) or '0'.
Install the rival first, e.g.:  pip install llm-guard
Swap the scanner for Rebuff / Prompt Guard to benchmark those instead."""
import sys

def main() -> None:
    text = sys.stdin.read()
    try:
        from llm_guard.input_scanners import PromptInjection
        scanner = PromptInjection()
        _sanitized, is_valid, _score = scanner.scan(text)
        print("0" if is_valid else "1")
    except Exception:
        # If the rival isn't installed, emit benign so it's visibly under-counted,
        # never silently inflating our win.
        print("0")

if __name__ == "__main__":
    main()
