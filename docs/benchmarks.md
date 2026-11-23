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

**Results (2026-11-22, 8-vCPU Intel Xeon Linux VM, Python 3.10, 8,000 analyses over a 16-script corpus, three runs)**

| Metric | Value |
|---|---:|
| Safety analyses/sec | 3,397 – 5,045 |
| Per-script latency p50 | 0.091 ms |
| Per-script latency p99 | 0.31 – 5.6 ms (noisy on a shared VM) |
| Findings raised per run | 6,000 |

**Reading the numbers**

- Analysis is far below the latency of a provider call, so the safety gate is not the
  bottleneck of the generate → review → confirm flow.
- The corpus mixes benign, dangerous and obfuscated scripts; findings come
  from the dangerous and tricky cases.
- Machine-dependent numbers measured on one development VM; rerun the command above
  to get figures for your hardware.
- An earlier revision allocated a large list for every pipeline, which cost ~18 ms per
  script containing `|`; the figures above were measured after that fix.
