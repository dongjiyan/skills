#!/usr/bin/env python3
"""
JFR Execution Sample Analyzer
Usage:
  analyze_jfr.py <samples_file>                  # full hotspot report
  analyze_jfr.py <samples_file> --callers <method>  # find callers of a hot method
  analyze_jfr.py <samples_file> --regex-audit     # flag regex misuse
  analyze_jfr.py <samples_file> --threads         # thread pool breakdown
"""

import re
import sys
import csv
import argparse
from collections import Counter, defaultdict

# Packages considered "JDK/framework infrastructure" — not business code
JDK_PREFIXES = (
    "java.", "sun.", "jdk.", "com.sun.", "javax.",
    "org.springframework.expression.spel",
    "net.sf.cglib",
)


def parse_samples(path):
    with open(path) as f:
        content = f.read()

    blocks = re.split(r'jdk\.(?:Execution|NativeMethod)Sample \{', content)
    samples = []
    for block in blocks[1:]:
        state_m = re.search(r'state = "([^"]+)"', block)
        thread_m = re.search(r'sampledThread = "([^"]+)"', block)
        frames = re.findall(
            r'^\s{4}([a-zA-Z][\w\.$]+\.[a-zA-Z<>][\w\.$<>]*(?:\(.*?\))?\s*(?:line:\s*\d+)?)',
            block, re.MULTILINE
        )
        samples.append({
            "state": state_m.group(1) if state_m else "UNKNOWN",
            "thread": thread_m.group(1) if thread_m else "unknown",
            "frames": [f.strip() for f in frames],
            "raw": block,
        })
    return samples


def is_biz_frame(f):
    return not any(f.startswith(p) for p in JDK_PREFIXES)


def hotspot_report(samples):
    runnable = [s for s in samples if s["state"] == "STATE_RUNNABLE"]
    total = len(runnable)
    if total == 0:
        print("No RUNNABLE samples found.")
        return

    print(f"Total samples: {len(samples)}  |  RUNNABLE: {total}\n")

    # ── Top-of-stack method counter ──────────────────────────────────────────
    top_method = Counter()
    pkg_counter = Counter()
    thread_counter = Counter()
    all_method_counter = Counter()

    for s in runnable:
        if s["frames"]:
            top = s["frames"][0]
            top_method[top] += 1
            parts = top.split(".")
            if len(parts) >= 3:
                pkg_counter[".".join(parts[:3])] += 1
        thread_counter[s["thread"]] += 1
        for f in s["frames"]:
            all_method_counter[f] += 1

    # ── Print top methods ────────────────────────────────────────────────────
    print("=" * 78)
    print("TOP 30 CPU HOTSPOT METHODS (stack top)")
    print("=" * 78)
    for method, count in top_method.most_common(30):
        pct = count / total * 100
        bar = "█" * max(1, int(pct / 2))
        print(f"  {count:4d} ({pct:5.1f}%)  {bar}")
        print(f"           {method}")
        print()

    # ── Package aggregation ─────────────────────────────────────────────────
    print("=" * 78)
    print("TOP 20 PACKAGE / MODULE HOTSPOTS")
    print("=" * 78)
    for pkg, count in pkg_counter.most_common(20):
        pct = count / total * 100
        print(f"  {count:4d} ({pct:5.1f}%)  {pkg}")

    # ── Thread pool breakdown ────────────────────────────────────────────────
    print()
    print("=" * 78)
    print("TOP 20 HOTTEST THREADS")
    print("=" * 78)
    for thread, count in thread_counter.most_common(20):
        pct = count / total * 100
        print(f"  {count:4d} ({pct:5.1f}%)  {thread}")

    # ── Business caller context for JDK hotspots ─────────────────────────────
    print()
    print("=" * 78)
    print("TOP BUSINESS CALLERS (non-JDK frames appearing most frequently)")
    print("=" * 78)
    biz_counter = Counter()
    for s in runnable:
        for f in s["frames"]:
            if is_biz_frame(f):
                biz_counter[f.split("(")[0]] += 1  # strip args for grouping
    for method, count in biz_counter.most_common(25):
        pct = count / total * 100
        print(f"  {count:4d} ({pct:5.1f}%)  {method}")

    # ── CSV export ───────────────────────────────────────────────────────────
    out_csv = "/tmp/jfr_hotspot_top_methods.csv"
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "count", "pct"])
        for method, count in top_method.most_common(100):
            w.writerow([method, count, f"{count/total*100:.2f}"])
    print(f"\nCSV saved to {out_csv}")


def caller_report(samples, target_method):
    runnable = [s for s in samples if s["state"] == "STATE_RUNNABLE"]
    total = len(runnable)
    matched = [s for s in runnable if any(target_method in f for f in s["frames"])]

    print(f"Samples containing '{target_method}': {len(matched)}/{total}\n")
    if not matched:
        print("Not found.")
        return

    # For each matching sample, find the caller chain above the target
    caller_counter = Counter()
    thread_counter = Counter()

    for s in matched:
        thread_counter[s["thread"]] += 1
        found = False
        for f in s["frames"]:
            if target_method in f:
                found = True
                continue
            if found and is_biz_frame(f):
                caller_counter[f.split("(")[0]] += 1
                break  # first biz frame above the hot method

    print("Business callers (frame immediately above the hot method):")
    for caller, count in caller_counter.most_common(20):
        pct = count / len(matched) * 100
        print(f"  {count:4d} ({pct:5.1f}%)  {caller}")

    print("\nThread distribution for these samples:")
    for t, c in thread_counter.most_common(10):
        pct = c / len(matched) * 100
        print(f"  {c:4d} ({pct:5.1f}%)  {t}")

    # Show up to 3 full stacks
    print("\nFull stack examples (up to 3):")
    seen = set()
    count = 0
    for s in matched:
        key = s["frames"][0] if s["frames"] else ""
        if key in seen:
            continue
        seen.add(key)
        print(f"\n  [thread: {s['thread']}]")
        for f in s["frames"]:
            marker = "  ★" if target_method in f else "   "
            print(f"{marker}  {f}")
        count += 1
        if count >= 3:
            break


def regex_audit(samples):
    runnable = [s for s in samples if s["state"] == "STATE_RUNNABLE"]
    total = len(runnable)

    compile_samples = []
    string_matches_samples = []
    formatter_samples = []
    pure_match_samples = []

    for s in runnable:
        raw = s["raw"]
        has_regex = "java.util.regex" in raw
        if not has_regex:
            continue

        is_compile = "Pattern.compile" in raw or "Pattern.<init>" in raw
        is_string_matches = "String.matches" in raw
        is_formatter = "Formatter.parse" in raw

        if is_compile:
            compile_samples.append(s)
        if is_string_matches:
            string_matches_samples.append(s)
        if is_formatter:
            formatter_samples.append(s)
        if not is_compile and not is_formatter:
            pure_match_samples.append(s)

    print(f"Total RUNNABLE samples: {total}")
    print(f"Regex samples breakdown:")
    print(f"  Pattern.compile() at runtime : {len(compile_samples):4d}  ← BUG (hot-path compile)")
    print(f"    of which via String.matches : {len(string_matches_samples):4d}")
    print(f"  Formatter.parse (String.format): {len(formatter_samples):4d}  ← consider pre-parsing")
    print(f"  Pure Matcher execution        : {len(pure_match_samples):4d}  (pattern pre-compiled, matching cost only)")

    if compile_samples:
        print("\n── Pattern.compile() call stacks ──")
        seen = set()
        for s in compile_samples[:5]:
            key = tuple(s["frames"][:3])
            if key in seen:
                continue
            seen.add(key)
            print(f"\n  [thread: {s['thread']}]")
            for f in s["frames"][:10]:
                print(f"    {f}")

    if formatter_samples:
        print("\n── Formatter.parse (String.format) stacks ──")
        seen = set()
        for s in formatter_samples[:3]:
            key = tuple(s["frames"][:3])
            if key in seen:
                continue
            seen.add(key)
            print(f"\n  [thread: {s['thread']}]")
            for f in s["frames"][:10]:
                print(f"    {f}")

    # Identify which business methods call regex
    print("\n── Business code calling regex ──")
    biz_caller_counter = Counter()
    for s in runnable:
        if "java.util.regex" not in s["raw"]:
            continue
        found_regex = False
        for f in s["frames"]:
            if "java.util.regex" in f:
                found_regex = True
                continue
            if found_regex and is_biz_frame(f):
                biz_caller_counter[f.split("(")[0]] += 1
                break
    for caller, count in biz_caller_counter.most_common(15):
        pct = count / total * 100
        print(f"  {count:4d} ({pct:5.1f}%)  {caller}")


def thread_report(samples):
    runnable = [s for s in samples if s["state"] == "STATE_RUNNABLE"]
    total = len(runnable)

    # Group by pool prefix (e.g., "pool-44" from "pool-44-thread-3")
    pool_biz = defaultdict(Counter)
    pool_total = Counter()

    for s in runnable:
        t = s["thread"]
        parts = t.split("-")
        pool = "-".join(parts[:2]) if len(parts) >= 3 and parts[1].isdigit() else t
        pool_total[pool] += 1
        for f in s["frames"]:
            if is_biz_frame(f):
                pool_biz[pool][f.split("(")[0]] += 1

    print(f"Total RUNNABLE samples: {total}\n")
    print("Thread pool analysis:")
    for pool, count in pool_total.most_common(20):
        pct = count / total * 100
        print(f"\n  [{pool}]  {count} samples ({pct:.1f}%)")
        for method, c in pool_biz[pool].most_common(5):
            print(f"    └─ {c:3d}  {method}")


def main():
    parser = argparse.ArgumentParser(description="JFR execution sample analyzer")
    parser.add_argument("samples_file", help="Output of: jfr print --events jdk.ExecutionSample <file>.jfr")
    parser.add_argument("--callers", metavar="METHOD", help="Find callers of a specific hot method substring")
    parser.add_argument("--regex-audit", action="store_true", help="Audit regex usage (Pattern.compile, String.matches, etc.)")
    parser.add_argument("--threads", action="store_true", help="Thread pool breakdown with business context")
    args = parser.parse_args()

    samples = parse_samples(args.samples_file)
    print(f"Parsed {len(samples)} samples from {args.samples_file}\n")

    if args.callers:
        caller_report(samples, args.callers)
    elif args.regex_audit:
        regex_audit(samples)
    elif args.threads:
        thread_report(samples)
    else:
        hotspot_report(samples)


if __name__ == "__main__":
    main()
