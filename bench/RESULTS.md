# Benchmark results

Append one section per run (newest last). Numbers are the median of 3 runs of `bench/run.sh`;
see [README.md](README.md) for the method. Never edit an old section; add a new one.

## Template — YYYY-MM-DD, `<git sha>`, `<host name>`

**Host**
- CPU: `<model>` (`<n>` vCPU), memory: `<GiB>`
- Disk: `<model / type>`, filesystem: `<ext4/xfs/zfs/btrfs + options>`
- Kernel / OS: `<uname -sr>`, `<distro>`
- Network: `<loopback | 10 GbE to client host>`
- Cairn: `<version>`, build: `release`, config deltas from defaults: `<none>`
- warp: `v1.8.2`, client on same host: `<yes/no>`

**Results**

| Scenario | ops/s | MiB/s | p50 | p90 | p99 | errors | vs target |
|----------|------:|------:|----:|----:|----:|-------:|-----------|
| put-small (4 KiB, c=32) | | | | | | | > 5 000 req/s, p99 < 10 ms |
| get-small (4 KiB, c=32) | | | | | | | > 5 000 req/s, p99 < 10 ms |
| mixed-small (64 KiB) | | | | | | | — |
| put-large (1 GiB, c=4) | | | | | | | saturate disk |
| get-large (1 GiB, c=4) | | | | | | | saturate disk |
| list (100k keys) | | | | | | | < 50 ms / page |

**Memory**: idle RSS `<MiB>`, peak RSS during put-large `<MiB>` (target: idle < 50 MiB, bounded).

**Notes**: bottlenecks observed (CPU-bound hashing? fsync? meta writer?), anything unusual.
