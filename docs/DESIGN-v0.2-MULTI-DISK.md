# Tidemark v0.2 — Multi-disk erasure coding (draft, 2026-11-10)

Status: **proposal, not scheduled.** v0.1 stays single-disk (DESIGN §0, §4.4). This note exists
so the v0.1.0-beta.1 format freeze is checked against the next big feature before it ships.

## Why

Claim 1 (DESIGN §0) says you cannot lose data even if you configured nothing. Today that holds
for mistakes (deletes, overwrites) but not for hardware: one dead disk means restoring from
backup. Erasure coding across the disks in one box closes that gap without a cluster.

## Shape

- **One node, one pool, N disks.** A pool is `k` data + `m` parity shards per stripe,
  `k + m = N`, set when the pool is created and fixed for its life (default: 4 disks → 2+2,
  6 → 4+2, 8 → 6+2). Survives losing any `m` disks.
- **The blob layer only.** Metadata refers to content by `BlobId` (BLAKE3) and nothing else:
  `Part { blob, size, etag, offset }`, `BlobRef { refcount, size, last_unref_at }`. Placement is
  not stored in redb. A new `EcBlobStore` implements the existing `BlobStore` trait
  (`begin_write`, `open`, `exists`, `delete`, `size`, `verify`); the engine, S3 layer, IAM and MCP
  do not change (the DESIGN §12.1 promise).
- **Codec:** `reed-solomon-simd` (pure Rust, SIMD on x86_64 and aarch64).
- **Encryption unchanged.** Erasure coding runs over the bytes the store would have written (the
  plain blob or the `CRNB` `.enc` file), so shards hold ciphertext and `crypto.rs` is untouched.

## On disk (new, additive)

```
<disk_i>/tidemark-disk.json          { format: 1, pool_id, disk_index, k, m }
<disk_i>/blobs/ab/cd/<hex>.s<i>      shard i of blob <hex>
<disk_i>/tmp/                        staging, same filesystem as blobs/
```

Shard file: header `TDMS` ‖ version 1 ‖ k ‖ m ‖ shard index ‖ stripe size ‖ source length,
then per-stripe chunks each followed by its own BLAKE3, so a shard can be checked without
reading the other disks. Stripe size 1 MiB (k × 256 KiB-ish chunks; tuned by measurement).

**Small blobs** (below one stripe) are mirrored to `m + 1` disks instead of coded: same failure
tolerance, no k-fold padding waste. Same `.s<i>` naming, header says `k = 1`.

**Disk identity:** every disk has `tidemark-disk.json`. A path that is empty or carries another
`pool_id` is refused at start, never treated as a fresh disk. That catches the classic failure:
a disk that did not mount, leaving an empty directory on the root filesystem.

## Write, read, heal

- **Write.** Stream through the existing hashing writer; encode each stripe as it fills and
  stage shards in each disk's `tmp/`. At `finish` the `BlobId` is known: fsync shards, rename all
  into place, then the metadata commit runs (unchanged ordering: blob durable before metadata).
- **Write quorum.** All `k + m` shards when every disk is healthy. With disks offline, accept the
  write if at least `k + 1` shards landed and record the blob under `kv` prefix `degraded:` for
  the healer. Fewer than `k + 1` → 503 `SlowDown`, nothing committed.
- **Read.** Fetch the `k` data shards; on a chunk hash mismatch or a missing shard, read parity
  and reconstruct. A reconstructed read also enqueues the blob for healing.
- **Healer.** A background worker drains `degraded:`, and scrub (existing) checks shard chunk
  hashes. Missing or corrupt shards are rebuilt from any `k` good ones and rewritten. Only when
  fewer than `k` survive is the blob marked damaged with the existing `mark_blob_damaged`
  (also a `kv` prefix), so fsck, metrics and the `TidemarkDamagedBlobs` alert work as today.
- **Replacing a disk.** `tidemark disk replace <index> <path>` writes the identity file and the
  healer refills it. Progress shows in `/metrics` (`tidemark_ec_degraded_blobs`, rebuild bytes).

## The metadata disk is still one disk

redb is one file. Erasure coding protects blobs, not `meta/tidemark.redb`. v0.2 answer:

1. A new optional `storage.meta_dir` (config only; the file name `tidemark.redb` stays frozen).
   Docs require it on a mirror (two small SSDs, mdraid or ZFS). Metadata is small next to data.
2. Fallback without a mirror: a consistent redb snapshot copied to every pool disk on a timer
   (default 15 min, reusing the backup snapshot code). Losing the metadata disk then loses at most
   the writes since the last snapshot; their blobs become orphans and GC collects them. That
   window is stated plainly in OPERATIONS, not hidden.

## Moving from v0.1

`tidemark disks convert` re-encodes `blobs/` into a pool in the background. The reader tries the
shard layout first, then the plain `blobs/ab/cd/<hex>[.enc]` path, so the store serves throughout
and metadata is never rewritten (same `BlobId`s). Downgrading from v0.2 to v0.1 after converting
is not supported.

## Out of scope for v0.2

Multi-node, growing a pool by adding disks (add a second pool instead; new writes go to it),
rebalancing between pools, per-bucket `k + m`, tiering.

## What this means for the beta.1 freeze

**Nothing to reserve.** Checked on 2026-11-10 against DESIGN §4.5:

- Records carry no placement, so no record field or enum variant is needed.
- New shard files use a new suffix and header; old `blobs/` paths stay valid and readable.
- Degraded and damage tracking use `kv` key prefixes, which are not a schema change.
- `meta_dir` is new configuration, not a new on-disk name.

So v0.2 is additive: a reader that accepts both layouts, as §4.5 already allows for blobs.

## Testing (before it is called a feature)

- Unit: encode/decode round trip for every `k + m` we allow, every combination of `m` lost shards.
- Fault injection: remove a disk directory, flip bytes inside one shard, unmount a disk mid-write
  (simulated with a read-only bind), kill -9 between shard renames and before the metadata commit.
- Healer converges: after replacing a disk, `fsck --verify full` is clean and every shard is back.
- Soak (`scripts/soak.sh` shape) with one disk pulled for a segment and replaced in the next.
- Upgrade test gains a "convert a v0.1 store" step.

## Rough cost

About 3–4 weeks of focused work: `EcBlobStore` and the shard format (1 week), write quorum and
the degraded list (a few days), healer and `disk replace` (1 week), metadata snapshot fallback
and convert (a few days), fault-injection tests and soak (1 week). Start only after v0.1.0 ships
and someone asks for it in an issue.
