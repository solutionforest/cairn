//! Durable outbox in the `events_queue` table, per-sink cursors in `kv`, and the dead-letter
//! queue.
//!
//! Key layout (all big-endian so scans are ordered):
//! - `events_queue`: `0x01 ‖ seq:u64` → [`OutboxRecord`]; `0x02 ‖ sink ‖ 0x00 ‖ seq:u64` → [`DlqRecord`]
//! - `kv`: `events/seq` → last assigned `seq:u64`; `events/cursor/<sink>` → last processed `seq:u64`

use crate::EventsError;
use crate::event::Event;
use crate::matcher::Target;
use crate::notification;
use serde::{Deserialize, Serialize};
use std::ops::Bound;
use std::sync::Arc;
use tidemark_core::{BucketId, Ts};
use tidemark_meta::{Flow, Reader, Table, WriteTxn, decode, encode};
use tokio::sync::watch;

const OUTBOX: u8 = 0x01;
const DLQ: u8 = 0x02;
const SEQ_KEY: &[u8] = b"events/seq";
const CURSOR_PREFIX: &[u8] = b"events/cursor/";

/// One outbox row: the event and the destinations that matched at commit time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRecord {
    /// The committed event.
    pub event: Event,
    /// Matching notification destinations (empty when captured only for broadcast sinks).
    pub targets: Vec<Target>,
    /// Set on DLQ requeues: deliver only to this sink.
    pub only_sink: Option<String>,
}

/// A batch that exhausted its delivery attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlqRecord {
    /// Sink id.
    pub sink: String,
    /// Original outbox sequence.
    pub seq: u64,
    /// The event and its targets.
    pub record: OutboxRecord,
    /// Attempts made.
    pub attempts: u32,
    /// Last error (already redacted by the sink).
    pub last_error: String,
    /// When it was dead-lettered.
    pub failed_at: Ts,
}

/// Handle used by the engine to append events and by workers to wait for new ones.
#[derive(Clone, Debug)]
pub struct Outbox {
    capture_all: bool,
    wake: Arc<watch::Sender<u64>>,
}

impl Default for Outbox {
    fn default() -> Self {
        Outbox::new(false)
    }
}

fn be(seq: u64) -> [u8; 8] {
    seq.to_be_bytes()
}

fn read_u64(v: &[u8]) -> Result<u64, EventsError> {
    <[u8; 8]>::try_from(v)
        .map(u64::from_be_bytes)
        .map_err(|_| tidemark_meta::MetaError::Corrupt("bad u64 in events kv".into()).into())
}

fn outbox_key(seq: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = OUTBOX;
    k[1..].copy_from_slice(&be(seq));
    k
}

fn dlq_prefix(sink: &str) -> Vec<u8> {
    let mut k = vec![DLQ];
    k.extend_from_slice(sink.as_bytes());
    k.push(0);
    k
}

fn cursor_key(sink: &str) -> Vec<u8> {
    let mut k = CURSOR_PREFIX.to_vec();
    k.extend_from_slice(sink.as_bytes());
    k
}

/// Sink ids may not contain NUL (DLQ key separator) and must be 1..=128 bytes.
pub fn valid_sink_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

impl Outbox {
    /// New handle. `capture_all` records every event even without a matching notification rule
    /// (set it when a broadcast sink such as the SSE stream is enabled).
    pub fn new(capture_all: bool) -> Outbox {
        Outbox {
            capture_all,
            wake: Arc::new(watch::channel(0).0),
        }
    }

    /// Whether events without matching rules are recorded.
    pub fn captures_all(&self) -> bool {
        self.capture_all
    }

    /// Engine hook: call inside the commit closure of the mutation that caused `event`.
    /// Loads the bucket's notification configuration from the same transaction, records the
    /// event with its matching targets and returns its sequence, or `None` when nothing listens.
    /// Deterministic over the transaction state, so it is safe in group-commit re-runs.
    pub fn append(
        &self,
        txn: &WriteTxn,
        bucket: BucketId,
        event: &Event,
    ) -> Result<Option<u64>, EventsError> {
        let targets = notification::load(txn, bucket)?
            .map(|c| c.targets(event))
            .unwrap_or_default();
        if targets.is_empty() && !self.capture_all {
            return Ok(None);
        }
        Outbox::append_record(
            txn,
            &OutboxRecord {
                event: event.clone(),
                targets,
                only_sink: None,
            },
        )
        .map(Some)
    }

    /// Append a record unconditionally, assigning the next sequence number.
    pub fn append_record(txn: &WriteTxn, rec: &OutboxRecord) -> Result<u64, EventsError> {
        let seq = Outbox::last_seq(txn)? + 1;
        txn.put(Table::Kv, SEQ_KEY, &be(seq))?;
        txn.put(Table::EventsQueue, &outbox_key(seq), &encode(rec))?;
        Ok(seq)
    }

    /// Wake delivery workers; call after the write that appended has committed.
    pub fn notify(&self) {
        self.wake.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// A receiver that changes whenever [`Outbox::notify`] is called.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.wake.subscribe()
    }

    /// Highest sequence ever assigned (0 if none).
    pub fn last_seq(r: &(impl Reader + ?Sized)) -> Result<u64, EventsError> {
        r.get(Table::Kv, SEQ_KEY)?
            .map(|v| read_u64(&v))
            .transpose()
            .map(|o| o.unwrap_or(0))
    }

    /// Up to `max` records with sequence greater than `after`, ascending.
    pub fn read_after(
        r: &(impl Reader + ?Sized),
        after: u64,
        max: usize,
    ) -> Result<Vec<(u64, OutboxRecord)>, EventsError> {
        let mut out = Vec::new();
        if max == 0 {
            return Ok(out);
        }
        let start = outbox_key(after.saturating_add(1));
        let end = [OUTBOX + 1];
        let mut err = None;
        r.scan(
            Table::EventsQueue,
            Bound::Included(&start),
            Bound::Excluded(&end),
            &mut |k, v| {
                let seq = match read_u64(&k[1..]) {
                    Ok(s) => s,
                    Err(e) => {
                        err = Some(e);
                        return Ok(Flow::Stop);
                    }
                };
                out.push((seq, decode(v)?));
                Ok(if out.len() >= max {
                    Flow::Stop
                } else {
                    Flow::Continue
                })
            },
        )?;
        match err {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    /// Number of outbox rows with sequence greater than `after` (delivery lag for a sink).
    pub fn depth_after(r: &(impl Reader + ?Sized), after: u64) -> Result<u64, EventsError> {
        let start = outbox_key(after.saturating_add(1));
        let end = [OUTBOX + 1];
        let mut n = 0u64;
        r.scan(
            Table::EventsQueue,
            Bound::Included(&start),
            Bound::Excluded(&end),
            &mut |_, _| {
                n += 1;
                Ok(Flow::Continue)
            },
        )?;
        Ok(n)
    }

    /// A sink's cursor: the last sequence it has fully processed (0 if never run).
    pub fn cursor(r: &(impl Reader + ?Sized), sink: &str) -> Result<u64, EventsError> {
        r.get(Table::Kv, &cursor_key(sink))?
            .map(|v| read_u64(&v))
            .transpose()
            .map(|o| o.unwrap_or(0))
    }

    /// Advance a sink's cursor (never moves backwards).
    pub fn set_cursor(txn: &WriteTxn, sink: &str, seq: u64) -> Result<(), EventsError> {
        if seq > Outbox::cursor(txn, sink)? {
            txn.put(Table::Kv, &cursor_key(sink), &be(seq))?;
        }
        Ok(())
    }

    /// Start a new sink at the current end of the outbox so it does not replay history.
    pub fn init_cursor_at_end(txn: &WriteTxn, sink: &str) -> Result<u64, EventsError> {
        if let Some(v) = txn.get(Table::Kv, &cursor_key(sink))? {
            return read_u64(&v);
        }
        let end = Outbox::last_seq(txn)?;
        txn.put(Table::Kv, &cursor_key(sink), &be(end))?;
        Ok(end)
    }

    /// Forget a sink's cursor (sink removed).
    pub fn remove_cursor(txn: &WriteTxn, sink: &str) -> Result<(), EventsError> {
        txn.del(Table::Kv, &cursor_key(sink))?;
        Ok(())
    }

    /// Lowest cursor among `sinks` (rows at or below it are delivered everywhere).
    pub fn min_cursor(r: &(impl Reader + ?Sized), sinks: &[&str]) -> Result<u64, EventsError> {
        let mut min = Outbox::last_seq(r)?;
        for s in sinks {
            min = min.min(Outbox::cursor(r, s)?);
        }
        Ok(min)
    }

    /// Delete outbox rows with sequence `<= upto`, at most `limit` per call; returns the count.
    pub fn compact(txn: &WriteTxn, upto: u64, limit: usize) -> Result<usize, EventsError> {
        let mut keys = Vec::new();
        let end = outbox_key(upto);
        txn.scan(
            Table::EventsQueue,
            Bound::Included(&[OUTBOX][..]),
            Bound::Included(&end[..]),
            &mut |k, _| {
                keys.push(k.to_vec());
                Ok(if keys.len() >= limit {
                    Flow::Stop
                } else {
                    Flow::Continue
                })
            },
        )?;
        for k in &keys {
            txn.del(Table::EventsQueue, k)?;
        }
        Ok(keys.len())
    }

    /// Move a record to the sink's dead-letter queue.
    pub fn dead_letter(txn: &WriteTxn, rec: &DlqRecord) -> Result<(), EventsError> {
        let mut k = dlq_prefix(&rec.sink);
        k.extend_from_slice(&be(rec.seq));
        txn.put(Table::EventsQueue, &k, &encode(rec))?;
        Ok(())
    }

    /// Dead-lettered records of a sink, oldest first, up to `max`.
    pub fn dlq(
        r: &(impl Reader + ?Sized),
        sink: &str,
        max: usize,
    ) -> Result<Vec<DlqRecord>, EventsError> {
        let mut out = Vec::new();
        r.scan_prefix(Table::EventsQueue, &dlq_prefix(sink), &mut |_, v| {
            out.push(decode(v)?);
            Ok(if out.len() >= max {
                Flow::Stop
            } else {
                Flow::Continue
            })
        })?;
        Ok(out)
    }

    /// Drop one dead-lettered record; returns whether it existed.
    pub fn dlq_remove(txn: &WriteTxn, sink: &str, seq: u64) -> Result<bool, EventsError> {
        let mut k = dlq_prefix(sink);
        k.extend_from_slice(&be(seq));
        Ok(txn.del(Table::EventsQueue, &k)?)
    }

    /// Re-enqueue a dead-lettered record as a fresh outbox row for that sink only; returns the
    /// new sequence (the event gets a new idempotency key).
    pub fn dlq_requeue(txn: &WriteTxn, sink: &str, seq: u64) -> Result<Option<u64>, EventsError> {
        let mut k = dlq_prefix(sink);
        k.extend_from_slice(&be(seq));
        let Some(v) = txn.get(Table::EventsQueue, &k)? else {
            return Ok(None);
        };
        let rec: DlqRecord = decode(&v)?;
        txn.del(Table::EventsQueue, &k)?;
        let mut again = rec.record;
        again.only_sink = Some(sink.to_string());
        Outbox::append_record(txn, &again).map(Some)
    }
}
