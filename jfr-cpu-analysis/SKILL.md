---
name: jfr-cpu-analysis
description: >
  Analyze Java Flight Recorder (JFR) files to identify CPU hotspots, categorize
  them by business domain, and locate specific source code lines causing the
  bottleneck. Use this skill whenever the user provides a .jfr file and asks
  about performance, CPU hotspots, slow code, profiling results, or thread
  analysis. Also use it when they ask "what's taking CPU", "where is the
  bottleneck", "analyze this JFR", or show flamegraph/profiling intent with a
  Java application. Always invoke this skill if a .jfr file is mentioned — even
  if the user says "just take a quick look".
---

# JFR CPU Hotspot Analysis

This skill performs a structured CPU hotspot analysis on a Java Flight Recorder
file. It extracts execution samples, aggregates them into a ranked hotspot list,
classifies them by business domain, correlates thread context, and produces a
prioritized optimization report with specific code locations.

## Prerequisites

- JDK installed with `jfr` CLI on PATH (ships with JDK 11+)
- Python 3 available
- The `.jfr` file accessible from the local filesystem

If `jfr` is not on PATH, find it: `find /Library/Java /Users -name "jfr" -type f 2>/dev/null | head -5`

## Workflow

Follow these steps in order. Each step builds on the previous one.

### Step 1 — Summarize the file

```bash
jfr summary "<path-to-file>.jfr"
```

From the output, note:
- Recording duration
- **Count of `jdk.ExecutionSample`** (Java CPU samples) — this is the sample
  budget for the entire analysis
- Count of `jdk.NativeMethodSample` (native CPU)
- Presence of GC events, lock events, socket events (scope for future analysis)

If `ExecutionSample` count is 0, the JFR was not recorded with CPU profiling
enabled. Stop and tell the user; they need to re-record with
`-XX:StartFlightRecording:settings=profile` or `settings=default`.

### Step 2 — Export execution samples

```bash
jfr print --events jdk.ExecutionSample "<path-to-file>.jfr" > /tmp/jfr_exec_samples.txt
```

Optionally export native samples too:
```bash
jfr print --events jdk.NativeMethodSample "<path-to-file>.jfr" > /tmp/jfr_native_samples.txt
```

### Step 3 — Run the bundled analysis script

The script `scripts/analyze_jfr.py` does all the heavy lifting. Run it:

```bash
python3 "<skill-dir>/scripts/analyze_jfr.py" /tmp/jfr_exec_samples.txt
```

The script produces:
1. Top 30 hottest methods by stack-top occupancy (with % and bar chart)
2. Package/module aggregation (top 20)
3. Thread pool distribution (top 20)
4. A CSV dump to `/tmp/jfr_hotspot_top_methods.csv` for further analysis

### Step 4 — Categorize by business domain

Read the top methods and package aggregation output. Group them into business
categories that make sense for the application. Common categories for Java
backend services:

| Category | Typical indicators |
|----------|-------------------|
| String/text processing | `String.charAt`, `StringUTF16`, `String.split` |
| HTTP/log parsing | `AccessLogUtil`, `tokenizeToStringArray`, `decodeNginxRequestBody` |
| Serialization | `avro`, `protobuf`, `fastjson`, `jackson` |
| Compression | `lz4`, `snappy`, `gzip` |
| IP/geo lookup | `ipdb`, `GeoIP`, `Decoder.decodeString` |
| Message queue | `kafka`, `rocketmq` |
| Caching/AOP | `spring.cache`, `SpelExpression`, `CacheAspectSupport` |
| Validation/rules | `cel`, `protovalidate`, `validator` |
| Regex | `java.util.regex`, especially `Pattern.compile` in the stack |
| DB access | `mysql`, `jdbc`, `beetl` |

Add application-specific categories based on package prefixes visible in the
output (e.g., `com.yourcompany.somemodule`).

For each category, note:
- Total sample count and percentage
- Top 3–5 caller methods (the business frames in the stack)
- Whether the hot method is a JDK primitive (indicates algorithm inefficiency)
  vs. the business method itself

### Step 5 — Deep-dive: find callers for truncated stacks

JFR default stack depth is often 64 frames but for hot JDK methods (e.g.,
`String.charAt`) the business caller may be truncated. Run the caller
correlation:

```bash
python3 "<skill-dir>/scripts/analyze_jfr.py" /tmp/jfr_exec_samples.txt --callers "<java.lang.String.charAt>"
```

This filters samples containing that method and prints all visible non-JDK
frames from those stacks, helping identify which business code is calling the
hot JDK method.

If stacks are still truncated (visible only JDK frames), correlate by thread
name: look at what the same thread pool does in *non-hot* samples to infer
business context.

### Step 6 — Identify Pattern.compile / regex issues

Regex misuse is a common but subtle hotspot. Run:

```bash
python3 "<skill-dir>/scripts/analyze_jfr.py" /tmp/jfr_exec_samples.txt --regex-audit
```

This flags:
- Samples with `Pattern.compile` or `Pattern.<init>` in the stack → runtime
  compilation (always a bug: someone called `String.matches()` or `new
  Pattern.compile()` inside a hot path)
- Samples with only `Matcher.*` → pattern already compiled, just expensive
  matching (may be acceptable)
- Samples with `Formatter.parse` → `String.format()` internal regex on format
  string (consider pre-parsing or alternative)

### Step 6b — Quick-Win Screen

Scan the top-30 method list for these patterns. Any hit with ≥ 1% sample share is a 🍎 Quick Win — typically a one-line or one-field fix.

| Pattern | Signal | Fix |
|---------|--------|-----|
| `Pattern.compile` / `Pattern.<init>` on hot path | regex compiled at runtime | declare `static final Pattern` constant |
| `String.matches(...)` | compile + match on every call | same as above |
| `Integer.valueOf` / `Long.valueOf` / `Double.valueOf` frequent | autoboxing overhead | use primitives or primitive arrays |
| `SimpleDateFormat` construction on hot path | non-thread-safe, recreated per call | use `static final DateTimeFormatter` |
| `Arrays.copyOf` / `Object.clone` frequent | unnecessary defensive copy | pass reference or `Collections.unmodifiableXxx` |
| `Logger.debug/trace` argument construction visible | string concat without level guard | wrap with `if (log.isDebugEnabled())` |

### Step 7 — Write the report

Produce a structured markdown report with these sections:

```
## JFR CPU Hotspot Report
**File:** ...  **Duration:** ...  **Total RUNNABLE samples:** ...

### Hotspot Summary Table
| Rank | Category | Samples | % | Severity |
...

### Detail per hotspot (for each category ≥ 2%)
- Root cause (1–2 sentences)
- Specific code location (class + line number from stack)
- Optimization recommendation

### 🍎 Quick Wins
Items flagged in Step 6b — each entry: pattern type / code location / estimated CPU release %

### Priority Fix List
P0 / P1 / P2 items with estimated CPU release

### Observations
Thread pool breakdown, any anomalies (lock contention, GC pressure etc.)
```

Severity guide:
- 🔴 **Severe** ≥ 10% of samples in a fixable pattern
- 🟡 **Medium** 3–10%
- 🟢 **Normal** < 3% or infrastructure overhead (Kafka, Avro, LZ4)

## Important notes

- **State filter:** Only count `STATE_RUNNABLE` samples. `STATE_SLEEPING` and
  `STATE_BLOCKED` samples are not CPU time — they're useful for lock/IO
  analysis but mislead CPU hotspot analysis if mixed in.
- **Stack depth:** JFR truncates deep stacks with `...`. When business callers
  are invisible, use thread-name correlation to infer context.
- **Pattern.compile is always a bug** on a hot path. `String.matches(regex)`
  compiles the pattern on every call. The fix is a `static final Pattern`
  field.
- **Formatter.parse regex:** `String.format("... %s ...")` internally uses a
  compiled regex to parse the format string — this shows up as
  `Formatter.parse` → `java.util.regex.*`. Consider `MessageFormat` (pre-parses
  once) or `StringBuilder` concatenation for very hot paths.
- **Netty tip:** `io.netty.util.NetUtil.isValidIpV4Address` and
  `isValidIpV6Address` are character-scan implementations with zero regex — they
  are safe drop-in replacements for any IP-validation regex.
