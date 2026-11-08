//! Durable outbox: append inside the caller's transaction, cursors, DLQ, compaction, and the
//! crash test (exactly the committed set is delivered, deduplicated by idempotency key).

use cairn_core::BucketId;
use cairn_events::sink::{Delivery, Sink, SinkError, route};
use cairn_events::worker::compact_outbox;
use cairn_events::{
    DeliveryWorker, Event, EventName, EventsError, NotificationConfiguration, Outbox, OutboxRecord,
    WorkerOptions, notification,
};
use cairn_meta::{MetaStore, RedbMetaStore};
use futures::future::BoxFuture;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

const BUCKET: BucketId = BucketId(7);

fn config() -> NotificationConfiguration {
    NotificationConfiguration::from_xml(
        r#"<NotificationConfiguration>
          <QueueConfiguration><Id>all</Id><Queue>arn:cairn:sink::hook</Queue>
            <Event>s3:ObjectCreated:*</Event></QueueConfiguration>
        </NotificationConfiguration>"#,
    )
    .unwrap()
}

fn event(i: usize) -> Event {
    let mut e = Event::new(EventName::ObjectCreatedPut, "b", format!("k{i}"));
    e.size = Some(i as u64);
    e
}

async fn setup(dir: &std::path::Path) -> RedbMetaStore {
    let store = RedbMetaStore::open(&dir.join("meta.redb")).unwrap();
    let cfg = config();
    store
        .write(move |txn| notification::store(txn, BUCKET, &cfg))
        .await
        .unwrap();
    store
}

/// Records idempotency keys; can be told to hang forever on the Nth call (simulated crash after
/// the destination received the batch but before the cursor commit).
#[derive(Clone)]
struct RecordingSink {
    got: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<usize>>,
    hang_on_call: Option<usize>,
    fail_with: Option<SinkError>,
    batch: usize,
}

impl RecordingSink {
    fn new(got: Arc<Mutex<Vec<String>>>, batch: usize) -> RecordingSink {
        RecordingSink {
            got,
            calls: Arc::new(Mutex::new(0)),
            hang_on_call: None,
            fail_with: None,
            batch,
        }
    }
}

impl Sink for RecordingSink {
    fn id(&self) -> &str {
        "hook"
    }
    fn accepts(&self, rec: &OutboxRecord) -> Option<String> {
        route("hook", &[], rec)
    }
    fn batch_size(&self) -> usize {
        self.batch
    }
    fn deliver<'a>(&'a self, batch: &'a [Delivery]) -> BoxFuture<'a, Result<(), SinkError>> {
        Box::pin(async move {
            let n = {
                let mut c = self.calls.lock().unwrap();
                *c += 1;
                *c
            };
            if let Some(e) = &self.fail_with {
                return Err(e.clone());
            }
            self.got.lock().unwrap().extend(
                batch
                    .iter()
                    .map(|d| d.to_record()["cairn"]["id"].as_str().unwrap().to_string()),
            );
            if self.hang_on_call == Some(n) {
                futures::future::pending::<()>().await;
            }
            Ok(())
        })
    }
}

fn fast() -> WorkerOptions {
    WorkerOptions {
        max_attempts: 3,
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
        poll_interval: Duration::from_millis(10),
        scan_limit: 1000,
    }
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not reached");
}

#[tokio::test]
async fn append_is_part_of_the_callers_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let store = setup(dir.path()).await;
    let ob = Outbox::new(false);

    let o = ob.clone();
    let seqs = store
        .write(move |txn| {
            let a = o.append(txn, BUCKET, &event(1))?;
            let b = o.append(txn, BUCKET, &event(2))?;
            let none = o.append(txn, BucketId(99), &event(3))?;
            let removed = o.append(
                txn,
                BUCKET,
                &Event::new(EventName::ObjectRemovedDelete, "b", "k"),
            )?;
            Ok::<_, EventsError>((a, b, none, removed))
        })
        .await
        .unwrap();
    assert_eq!(
        seqs,
        (Some(1), Some(2), None, None),
        "no rule → nothing recorded"
    );

    let o = ob.clone();
    let failed: Result<(), EventsError> = store
        .write(move |txn| {
            o.append(txn, BUCKET, &event(10))?;
            Err(EventsError::InvalidArgument("abort".into()))
        })
        .await;
    assert!(failed.is_err());

    let r = store.read().unwrap();
    assert_eq!(
        Outbox::last_seq(&r).unwrap(),
        2,
        "aborted txn left no trace"
    );
    let rows = Outbox::read_after(&r, 0, 10).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1.targets[0].configuration_id, "all");
    assert_eq!(rows[1].1.event.key, "k2");
    assert_eq!(Outbox::read_after(&r, 1, 10).unwrap()[0].0, 2);
    assert_eq!(Outbox::depth_after(&r, 0).unwrap(), 2);

    let all = Outbox::new(true);
    let s = store
        .write(move |txn| all.append(txn, BucketId(99), &event(3)))
        .await
        .unwrap();
    assert_eq!(
        s,
        Some(3),
        "capture_all records unmatched events for broadcast sinks"
    );
}

#[tokio::test]
async fn cursors_compaction_and_dlq() {
    let dir = tempfile::tempdir().unwrap();
    let store = setup(dir.path()).await;
    let ob = Outbox::new(false);
    let o = ob.clone();
    store
        .write(move |txn| {
            for i in 0..10 {
                o.append(txn, BUCKET, &event(i))?;
            }
            Ok::<_, EventsError>(())
        })
        .await
        .unwrap();

    store
        .write(|txn| {
            Outbox::set_cursor(txn, "a", 6)?;
            Outbox::set_cursor(txn, "a", 3)?;
            Outbox::set_cursor(txn, "b", 4)?;
            let fresh = Outbox::init_cursor_at_end(txn, "late")?;
            assert_eq!(fresh, 10);
            Ok::<_, EventsError>(())
        })
        .await
        .unwrap();
    let r = store.read().unwrap();
    assert_eq!(
        Outbox::cursor(&r, "a").unwrap(),
        6,
        "cursor never moves backwards"
    );
    assert_eq!(Outbox::min_cursor(&r, &["a", "b", "late"]).unwrap(), 4);
    drop(r);

    let n = compact_outbox(&store, vec!["a".into(), "b".into()], 100)
        .await
        .unwrap();
    assert_eq!(n, 4);
    let r = store.read().unwrap();
    assert_eq!(Outbox::read_after(&r, 0, 100).unwrap()[0].0, 5);
    assert_eq!(
        Outbox::last_seq(&r).unwrap(),
        10,
        "sequence survives compaction"
    );
    drop(r);

    // Permanent failure: one attempt, straight to the DLQ, cursor still advances.
    let got = Arc::new(Mutex::new(Vec::new()));
    let mut sink = RecordingSink::new(got.clone(), 4);
    sink.fail_with = Some(SinkError::Permanent("HTTP 400".into()));
    let w =
        DeliveryWorker::new(store.clone(), ob.clone(), Arc::new(sink.clone())).with_options(fast());
    let (_tx, mut rx) = watch::channel(false);
    assert_eq!(w.run_once(&mut rx).await.unwrap(), 6);
    assert_eq!(
        *sink.calls.lock().unwrap(),
        2,
        "two batches, one attempt each"
    );
    let r = store.read().unwrap();
    assert_eq!(Outbox::cursor(&r, "hook").unwrap(), 10);
    let dlq = Outbox::dlq(&r, "hook", 100).unwrap();
    assert_eq!(dlq.len(), 6);
    assert_eq!(dlq[0].attempts, 1);
    assert_eq!(dlq[0].last_error, "HTTP 400");
    drop(r);

    // Retryable failure: max_attempts tries, then DLQ.
    let o = ob.clone();
    store
        .write(move |txn| o.append(txn, BUCKET, &event(11)))
        .await
        .unwrap();
    let mut sink = RecordingSink::new(got.clone(), 4);
    sink.fail_with = Some(SinkError::Retryable("HTTP 503".into()));
    let w =
        DeliveryWorker::new(store.clone(), ob.clone(), Arc::new(sink.clone())).with_options(fast());
    w.run_once(&mut rx).await.unwrap();
    assert_eq!(*sink.calls.lock().unwrap(), 3);
    let r = store.read().unwrap();
    let dlq = Outbox::dlq(&r, "hook", 100).unwrap();
    assert_eq!(dlq.len(), 7);
    assert_eq!(dlq[6].attempts, 3);
    drop(r);

    // Requeue a dead letter: delivered to that sink only, with a fresh sequence.
    let re = store
        .write(|txn| Outbox::dlq_requeue(txn, "hook", 11))
        .await
        .unwrap();
    assert_eq!(re, Some(12));
    let w = DeliveryWorker::new(
        store.clone(),
        ob.clone(),
        Arc::new(RecordingSink::new(got.clone(), 4)),
    )
    .with_options(fast());
    w.run_once(&mut rx).await.unwrap();
    assert_eq!(*got.lock().unwrap(), vec!["000000000000000c".to_string()]);
    let r = store.read().unwrap();
    assert_eq!(Outbox::dlq(&r, "hook", 100).unwrap().len(), 6);
    let removed = store
        .write(|txn| Outbox::dlq_remove(txn, "hook", 5))
        .await
        .unwrap();
    assert!(removed);
}

#[tokio::test]
async fn backoff_is_exponential_capped_and_jittered() {
    let o = WorkerOptions {
        base_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(1),
        ..WorkerOptions::default()
    };
    for (attempt, full) in [
        (1, 100),
        (2, 200),
        (3, 400),
        (4, 800),
        (5, 1000),
        (30, 1000),
    ] {
        for _ in 0..20 {
            let d = o.backoff(attempt).as_millis();
            assert!(
                d >= full / 2 && d <= full,
                "attempt {attempt}: {d}ms not in [{}, {full}]",
                full / 2
            );
        }
    }
}

/// Crash test (BUILD-PLAN 3a acceptance, PRODUCTION-READINESS D7).
#[tokio::test]
async fn crash_mid_batch_delivers_exactly_the_committed_set() {
    const N: usize = 50;
    let dir = tempfile::tempdir().unwrap();
    let store = setup(dir.path()).await;
    let ob = Outbox::new(false);

    let o = ob.clone();
    let committed: Vec<u64> = store
        .write(move |txn| {
            (0..N)
                .map(|i| o.append(txn, BUCKET, &event(i)).map(|s| s.unwrap()))
                .collect::<Result<Vec<_>, _>>()
        })
        .await
        .unwrap();
    let o = ob.clone();
    let _ = store
        .write(move |txn| {
            for i in 0..5 {
                o.append(txn, BUCKET, &event(1000 + i))?;
            }
            Err::<(), _>(EventsError::InvalidArgument("rolled back".into()))
        })
        .await;
    ob.notify();
    let want: BTreeSet<String> = committed.iter().map(|s| format!("{s:016x}")).collect();
    assert_eq!(want.len(), N);

    // First run: the third batch reaches the destination, then the process "dies".
    let got = Arc::new(Mutex::new(Vec::new()));
    let mut crashing = RecordingSink::new(got.clone(), 7);
    crashing.hang_on_call = Some(3);
    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = DeliveryWorker::new(store.clone(), ob.clone(), Arc::new(crashing))
        .with_options(fast())
        .spawn(stop_rx);
    wait_for(|| got.lock().unwrap().len() >= 21).await;
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    {
        let r = store.read().unwrap();
        assert_eq!(
            Outbox::cursor(&r, "hook").unwrap(),
            committed[13],
            "two batches acked"
        );
    }
    store.shutdown();
    drop(store);
    drop(stop_tx);

    // Restart from disk and drain.
    let store = RedbMetaStore::open(&dir.path().join("meta.redb")).unwrap();
    let ob = Outbox::new(false);
    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = DeliveryWorker::new(
        store.clone(),
        ob.clone(),
        Arc::new(RecordingSink::new(got.clone(), 7)),
    )
    .with_options(fast())
    .spawn(stop_rx);
    let s2 = store.clone();
    let last = *committed.last().unwrap();
    wait_for(move || Outbox::cursor(&s2.read().unwrap(), "hook").unwrap() == last).await;
    stop_tx.send(true).unwrap();
    handle.await.unwrap().unwrap();

    let got = got.lock().unwrap().clone();
    let distinct: BTreeSet<String> = got.iter().cloned().collect();
    assert_eq!(
        distinct, want,
        "exactly the committed set, nothing from the rolled-back txn"
    );
    assert_eq!(got.len(), N + 7, "only the in-flight batch was redelivered");
    let r = store.read().unwrap();
    assert!(Outbox::dlq(&r, "hook", 10).unwrap().is_empty());
}
