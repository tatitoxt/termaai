# Benchmarks

Measured with `scripts/benchmark.py` — the local safety pipeline every
generated script passes through before it can execute: shell parsing plus
all risk rules (destructive deletes, device writes, curl|sh, permission
blowouts, encoded payloads, workspace escapes). No provider or sandbox
needed.

**How to reproduce**

```sh
python scripts/benchmark.py --rounds 500   # --json for raw output
```

**Results (2026-11-21, 8,000 analyses over a 16-script corpus)**

| Metric | Value |
|---|---:|
| Safety analyses/sec | **11,527** |
| Per-script latency | 0.08 ms p50 / 0.134 ms p99 |
| Findings raised | 6,500 |

**Reading the numbers**

- Sub-millisecond analysis means the safety gate adds effectively zero
  latency to the generate → review → confirm flow — risk review is not the
  bottleneck, the provider call is.
- The corpus mixes benign, dangerous and obfuscated scripts; findings come
  from the dangerous and tricky cases.
- Machine-dependent numbers; a reproducible baseline, not a marketing figure.
