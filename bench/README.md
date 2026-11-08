# Benchmarks

`bench/run.sh` drives [MinIO warp](https://github.com/minio/warp) (pinned `v1.8.2`) against a
running Cairn and writes raw output plus a host description to `bench/results/<UTC stamp>/`
(git-ignored). Curated numbers go into [`RESULTS.md`](RESULTS.md), one section per run.

warp was chosen over a custom Rust harness: it is the de-facto S3 load generator, it reports
throughput and latency percentiles per operation, its numbers are directly comparable with
published MinIO results, and it keeps the 1-vCPU dev host from compiling another binary.

## Method

1. Release build on the host under test: `cargo build --release -p cairn-cli`.
2. Fresh data dir on the filesystem you want to measure; `cairn init` then
   `cairn serve` with default config (`fsync = true`). Record any config change in RESULTS.md.
3. Run the client on the same host for single-node numbers (`BENCH_ENDPOINT=127.0.0.1:9000`);
   for network numbers run it from a second host and record the link speed.
4. `BENCH_ENDPOINT=127.0.0.1:9000 BENCH_ACCESS_KEY=... BENCH_SECRET_KEY=... \
   BENCH_DATA_DIR=/srv/cairn bench/run.sh`
5. Repeat 3 times; report the median run. Note idle RSS (`ps -o rss= -p $(pidof cairn)`) before
   and peak RSS during the large-object scenarios (E3).

## Scenarios (DESIGN §13 targets, reference host: 4 cores, NVMe)

| Scenario | warp | Target |
|----------|------|--------|
| `put-small` | `put --obj.size 4KiB --concurrent 32` | > 5 000 req/s, p99 < 10 ms |
| `get-small` | `get --obj.size 4KiB --objects 10000` | > 5 000 req/s, p99 < 10 ms |
| `mixed-small` | `mixed --obj.size 64KiB` (warp default 45% GET / 15% PUT / 30% STAT / 10% DELETE) | informational |
| `put-large` | `put --obj.size 1GiB --concurrent 4` | saturate disk / 10 GbE |
| `get-large` | `get --obj.size 1GiB --objects 8 --concurrent 4` | saturate disk / 10 GbE |
| `list` | `list --objects 100000` | < 50 ms per 1 000-key page |

Select a subset with `BENCH_SCENARIOS="put-small get-small"`; shorten with
`BENCH_DURATION=20s` on small hosts.

## Getting warp

`go install github.com/minio/warp@v1.8.2` (needs a current Go), or let `run.sh` fall back to
the `minio/warp:v1.8.2` container (`--network host`). Point `WARP=/path/to/warp` at a
specific binary.
