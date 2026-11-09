//! Notification configuration XML round-trips, validation and matcher cases.

use tidemark_events::matcher::{event_matches, key_matches};
use tidemark_events::notification::ACCEPTED_NOT_EMITTED;
use tidemark_events::{Event, EventName, FilterRule, NotificationConfiguration, TargetKind};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn round_trip(cfg: &NotificationConfiguration) {
    let xml = cfg.to_xml();
    let back = NotificationConfiguration::from_xml(&xml).unwrap();
    assert_eq!(&back, cfg, "model round-trip via {xml}");
    assert_eq!(back.to_xml(), xml, "serialisation is stable");
}

#[test]
fn aws_docs_fixture() {
    let cfg = NotificationConfiguration::from_xml(&fixture("aws-docs.xml")).unwrap();
    assert_eq!(cfg.rules.len(), 3);
    let q = &cfg.rules[0];
    assert_eq!(q.kind, TargetKind::Queue);
    assert_eq!(q.id.as_deref(), Some("1"));
    assert_eq!(
        q.arn,
        "arn:aws:sqs:us-west-2:444455556666:s3notificationqueue"
    );
    assert_eq!(q.events, vec!["s3:ObjectCreated:Put"]);
    assert_eq!(
        q.filter,
        vec![
            FilterRule {
                name: "prefix".into(),
                value: "images/".into()
            },
            FilterRule {
                name: "suffix".into(),
                value: ".jpg".into()
            },
        ]
    );
    let t = &cfg.rules[1];
    assert_eq!(t.kind, TargetKind::Topic);
    assert_eq!(t.id, None);
    assert_eq!(t.events.len(), 2);
    let l = &cfg.rules[2];
    assert_eq!(l.kind, TargetKind::Lambda);
    assert_eq!(
        l.arn,
        "arn:aws:lambda:us-west-2:35667example:function:CreateThumbnail"
    );
    assert!(!cfg.event_bridge);
    round_trip(&cfg);
}

#[test]
fn sdk_lambda_member_names_entities_cdata_eventbridge() {
    let cfg = NotificationConfiguration::from_xml(&fixture("sdk-lambda.xml")).unwrap();
    assert_eq!(cfg.rules[0].kind, TargetKind::Lambda);
    assert_eq!(
        cfg.rules[0].arn,
        "arn:aws:lambda:eu-west-1:123456789012:function:thumb"
    );
    assert_eq!(
        cfg.rules[0].filter[0].name, "suffix",
        "rule names are case-insensitive"
    );
    assert_eq!(cfg.rules[1].id.as_deref(), Some("hook & co"));
    assert_eq!(cfg.rules[1].filter[0].value, "a<b/");
    assert!(cfg.event_bridge);
    let xml = cfg.to_xml();
    assert!(xml.contains("<CloudFunctionConfiguration><Id>thumbs</Id><CloudFunction>"));
    assert!(xml.contains("<Id>hook &amp; co</Id>"));
    assert!(xml.contains("<Value>a&lt;b/</Value>"));
    round_trip(&cfg);
}

#[test]
fn empty_configuration() {
    let cfg = NotificationConfiguration::from_xml(&fixture("empty.xml")).unwrap();
    assert_eq!(cfg, NotificationConfiguration::default());
    round_trip(&cfg);
}

#[test]
fn rejects_malformed_and_invalid() {
    let cases = [
        ("<Nope/>", "unexpected root"),
        ("<NotificationConfiguration>", "unexpected end"),
        (
            "<NotificationConfiguration><Bogus/></NotificationConfiguration>",
            "unexpected element",
        ),
        (
            "<NotificationConfiguration><QueueConfiguration><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>",
            "without destination",
        ),
        (
            "<NotificationConfiguration><QueueConfiguration><Queue>q</Queue></QueueConfiguration></NotificationConfiguration>",
            "at least one Event",
        ),
        (
            "<NotificationConfiguration><QueueConfiguration><Queue>q</Queue><Event>s3:Nope</Event></QueueConfiguration></NotificationConfiguration>",
            "unsupported event",
        ),
        (
            "<NotificationConfiguration><QueueConfiguration><Queue>q</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>middle</Name><Value>x</Value></FilterRule></S3Key></Filter></QueueConfiguration></NotificationConfiguration>",
            "prefix or suffix",
        ),
        (
            "<NotificationConfiguration><QueueConfiguration><Queue>q</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>a</Value></FilterRule><FilterRule><Name>Prefix</Name><Value>b</Value></FilterRule></S3Key></Filter></QueueConfiguration></NotificationConfiguration>",
            "duplicate filter rule",
        ),
        (
            "<NotificationConfiguration><QueueConfiguration><Id>x</Id><Queue>q</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration><TopicConfiguration><Id>x</Id><Topic>t</Topic><Event>s3:ObjectCreated:*</Event></TopicConfiguration></NotificationConfiguration>",
            "duplicate configuration id",
        ),
        (
            "<!DOCTYPE x [<!ENTITY a \"b\">]><NotificationConfiguration/>",
            "DOCTYPE",
        ),
        (
            "<NotificationConfiguration><Id>&bogus;</Id></NotificationConfiguration>",
            "entity",
        ),
    ];
    for (xml, want) in cases {
        let err = NotificationConfiguration::from_xml(xml)
            .unwrap_err()
            .to_string();
        assert!(err.contains(want), "{xml}: got {err:?}, want {want:?}");
    }
}

#[test]
fn malformed_maps_to_s3_errors() {
    let e: tidemark_core::S3Error = NotificationConfiguration::from_xml("<x")
        .unwrap_err()
        .into();
    assert_eq!(e.code, tidemark_core::S3ErrorCode::MalformedXML);
}

#[test]
fn destination_validation() {
    let cfg = NotificationConfiguration::from_xml(&fixture("sdk-lambda.xml")).unwrap();
    assert!(cfg.validate_destinations(|_| true).is_ok());
    let err = cfg
        .validate_destinations(|a| a.starts_with("arn:tidemark:sink::"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("Unable to validate the following destination configurations"));
    assert!(err.contains("function:thumb"));
}

#[test]
fn event_globs() {
    use EventName::*;
    let cases: &[(&str, EventName, bool)] = &[
        ("s3:ObjectCreated:*", ObjectCreatedPut, true),
        (
            "s3:ObjectCreated:*",
            ObjectCreatedCompleteMultipartUpload,
            true,
        ),
        ("s3:ObjectCreated:*", ObjectRemovedDelete, false),
        ("s3:ObjectCreated:Put", ObjectCreatedPut, true),
        ("s3:ObjectCreated:Put", ObjectCreatedPost, false),
        ("s3:ObjectRemoved:*", ObjectRemovedDeleteMarkerCreated, true),
        ("s3:ObjectRemoved:*", LifecycleExpirationDelete, false),
        (
            "s3:LifecycleExpiration:*",
            LifecycleExpirationDeleteMarkerCreated,
            true,
        ),
        ("s3:ObjectRestore:*", ObjectRestoreCompleted, true),
        ("tidemark:*", TidemarkPitrRestore, true),
        ("tidemark:*", ObjectCreatedPut, false),
        ("tidemark:TrashRestored", TidemarkTrashRestored, true),
        ("*", TidemarkBucketDeleted, true),
        ("s3:*:Delete", ObjectRemovedDelete, true),
        ("s3:*:Delete", ObjectRestoreDelete, true),
        ("s3:*:Delete", ObjectCreatedPut, false),
        ("s3:ObjectCreated", ObjectCreatedPut, false),
    ];
    for (p, n, want) in cases {
        assert_eq!(event_matches(p, *n), *want, "{p} vs {n}");
    }
    for n in ACCEPTED_NOT_EMITTED {
        assert!(tidemark_events::notification::valid_event_pattern(n));
    }
}

#[test]
fn key_filters() {
    let f = |p: Option<&str>, s: Option<&str>| {
        let mut v = Vec::new();
        if let Some(p) = p {
            v.push(FilterRule {
                name: "prefix".into(),
                value: p.into(),
            });
        }
        if let Some(s) = s {
            v.push(FilterRule {
                name: "suffix".into(),
                value: s.into(),
            });
        }
        v
    };
    assert!(key_matches(&f(None, None), "anything"));
    assert!(key_matches(&f(Some("images/"), None), "images/a.jpg"));
    assert!(!key_matches(&f(Some("images/"), None), "img/a.jpg"));
    assert!(key_matches(&f(None, Some(".jpg")), "a.jpg"));
    assert!(!key_matches(&f(None, Some(".jpg")), "a.jpeg"));
    assert!(key_matches(&f(Some("i/"), Some(".jpg")), "i/x.jpg"));
    assert!(!key_matches(&f(Some("i/"), Some(".jpg")), "i/x.png"));
    assert!(
        !key_matches(&f(Some("I/"), None), "i/x"),
        "case-sensitive like S3"
    );
    assert!(key_matches(&f(Some(""), Some("")), ""));
}

#[test]
fn targets_and_sink_resolution() {
    let cfg = NotificationConfiguration::from_xml(
        r#"<NotificationConfiguration>
          <QueueConfiguration><Id>jpg</Id><Queue>arn:tidemark:sink::hook</Queue>
            <Event>s3:ObjectCreated:*</Event>
            <Filter><S3Key><FilterRule><Name>suffix</Name><Value>.jpg</Value></FilterRule></S3Key></Filter>
          </QueueConfiguration>
          <TopicConfiguration><Id>all-deletes</Id><Topic>arn:tidemark:sink::hook</Topic>
            <Event>s3:ObjectRemoved:*</Event></TopicConfiguration>
          <CloudFunctionConfiguration><Id>fn</Id><CloudFunction>arn:aws:lambda:us-east-1:1:function:f</CloudFunction>
            <Event>s3:ObjectCreated:Put</Event>
            <Filter><S3Key><FilterRule><Name>prefix</Name><Value>up/</Value></FilterRule></S3Key></Filter>
          </CloudFunctionConfiguration>
        </NotificationConfiguration>"#,
    )
    .unwrap();
    let ev = |n, k: &str| Event::new(n, "b", k);
    let ids = |e: &Event| {
        cfg.targets(e)
            .into_iter()
            .map(|t| t.configuration_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(&ev(EventName::ObjectCreatedPut, "up/a.jpg")),
        vec!["jpg", "fn"]
    );
    assert_eq!(
        ids(&ev(EventName::ObjectCreatedCopy, "up/a.jpg")),
        vec!["jpg"]
    );
    assert_eq!(
        ids(&ev(EventName::ObjectCreatedPut, "up/a.png")),
        vec!["fn"]
    );
    assert_eq!(
        ids(&ev(EventName::ObjectRemovedDelete, "x")),
        vec!["all-deletes"]
    );
    assert!(ids(&ev(EventName::TidemarkPitrRestore, "x")).is_empty());
    let resolve = |arn: &str| match arn {
        "arn:aws:lambda:us-east-1:1:function:f" => Some("lambda-f".to_string()),
        a => tidemark_events::matcher::tidemark_sink_id(a).map(str::to_string),
    };
    assert_eq!(
        cfg.sink_ids(&ev(EventName::ObjectCreatedPut, "up/a.jpg"), resolve),
        vec!["hook", "lambda-f"]
    );
}
