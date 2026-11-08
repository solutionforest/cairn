"""Compare a pytest junit report with allowed-failures.txt.

Usage: python3 -I compare.py junit.xml allowed-failures.txt report_dir
Writes report_dir/summary.md and report_dir/failed.txt; exits 1 on unexpected failures.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def test_id(case):
    cls = case.get("classname", "")
    mod = cls.split(".")[-1] if cls else ""
    return f"{mod}::{case.get('name')}" if mod else case.get("name")


def main(junit, allowed_path, out_dir):
    root = ET.parse(junit).getroot()
    passed, failed, skipped = [], [], []
    for case in root.iter("testcase"):
        tid = test_id(case)
        if case.find("failure") is not None or case.find("error") is not None:
            failed.append(tid)
        elif case.find("skipped") is not None:
            skipped.append(tid)
        else:
            passed.append(tid)
    allowed = set()
    for line in Path(allowed_path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            allowed.add(line)
    unexpected = sorted(set(failed) - allowed)
    fixed = sorted(allowed & set(passed))
    ran = len(passed) + len(failed)
    rate = 100.0 * len(passed) / ran if ran else 0.0
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "failed.txt").write_text("".join(f"{t}\n" for t in sorted(failed)))
    summary = [
        "# s3-tests summary",
        "",
        f"- passed: {len(passed)}",
        f"- failed: {len(failed)} (allowed: {len(failed) - len(unexpected)})",
        f"- skipped: {len(skipped)}",
        f"- pass rate: {rate:.1f}% of {ran} executed",
        "",
        "## Unexpected failures",
        *([f"- `{t}`" for t in unexpected] or ["none"]),
        "",
        "## Listed as allowed but now passing (remove from allowed-failures.txt)",
        *([f"- `{t}`" for t in fixed] or ["none"]),
        "",
    ]
    (out / "summary.md").write_text("\n".join(summary))
    print("\n".join(summary))
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
