use super::*;
use crate::error::PolicyError;

fn parse(s: &str) -> Result<PolicyDocument, PolicyError> {
    PolicyDocument::parse_validated(s)
}

fn stmt(body: &str) -> String {
    format!(r#"{{"Version":"2012-10-17","Statement":[{body}]}}"#)
}

#[test]
fn parses_full_grammar() {
    let d = parse(
        r#"{"Version":"2012-10-17","Id":"P1","Statement":{"Sid":"A","Effect":"Allow",
        "Principal":{"AWS":["arn:aws:iam::000000000000:user/alice","000000000000"]},
        "Action":"s3:Get*","Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"],
        "Condition":{"StringLikeIfExists":{"s3:prefix":["a/*",1,true]},
                     "ForAllValues:StringEquals":{"aws:TagKeys":"x"},
                     "NumericLessThan":{"s3:max-keys":10},
                     "DateGreaterThan":{"aws:CurrentTime":"2020-01-01"},
                     "IpAddress":{"aws:SourceIp":["10.0.0.0/8","::1"]},
                     "Null":{"s3:x-amz-acl":"true"},
                     "ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/*"}}}}"#,
    )
    .unwrap();
    assert_eq!(d.id(), Some("P1"));
    assert_eq!(d.version(), Some("2012-10-17"));
    let st = &d.statements()[0];
    assert_eq!(st.sid.as_deref(), Some("A"));
    assert_eq!(st.conditions.len(), 7);
    let c = st.conditions.iter().find(|c| c.key == "s3:prefix").unwrap();
    assert!(c.if_exists && c.op == OpKind::StringLike && c.set == SetQualifier::None);
    let c = st
        .conditions
        .iter()
        .find(|c| c.key == "aws:tagkeys")
        .unwrap();
    assert_eq!(c.set, SetQualifier::ForAllValues);
    assert_eq!(d.to_string(), d.as_json());
    d.validate_for(PolicyKind::Bucket("b")).unwrap();
}

#[test]
fn serde_roundtrip_as_string() {
    let src = stmt(r#"{"Effect":"Allow","Action":"s3:*","Resource":"*"}"#);
    let d = parse(&src).unwrap();
    let j = serde_json::to_string(&d).unwrap();
    let back: PolicyDocument = serde_json::from_str(&j).unwrap();
    assert_eq!(back, d);
}

#[test]
fn rejects_malformed() {
    let bad = [
        "not json",
        "[]",
        r#"{"Statement":[]}"#,
        r#"{"Version":"2020-01-01","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        r#"{"Extra":1,"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        &stmt(r#"{"Effect":"Maybe","Action":"s3:*","Resource":"*"}"#),
        &stmt(r#"{"Effect":"Allow","Resource":"*"}"#),
        &stmt(r#"{"Effect":"Allow","Action":"s3:*","NotAction":"s3:Get*","Resource":"*"}"#),
        &stmt(r#"{"Effect":"Allow","Action":[],"Resource":"*"}"#),
        &stmt(r#"{"Effect":"Allow","Action":[1],"Resource":"*"}"#),
        &stmt(r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Bogus":1}"#),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringFoo":{"a:b":"c"}}}"#,
        ),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"NumericEquals":{"a:b":"x"}}}"#,
        ),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"DateEquals":{"a:b":"yesterday"}}}"#,
        ),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/33"}}}"#,
        ),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"a:b":"yes"}}}"#,
        ),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"NullIfExists":{"a:b":"true"}}}"#,
        ),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"nokey":"x"}}}"#,
        ),
        &stmt(
            r#"{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"a:b":{"x":1}}}}"#,
        ),
        &stmt(r#"{"Effect":"Allow","Principal":"alice","Action":"s3:*","Resource":"*"}"#),
        &stmt(r#"{"Effect":"Allow","Principal":{"Weird":"x"},"Action":"s3:*","Resource":"*"}"#),
    ];
    for b in bad {
        assert!(parse(b).is_err(), "accepted: {b}");
    }
}

#[test]
fn rejects_unknown_actions() {
    for a in [
        "s3:GetObjekt",
        "s3:Frob*",
        "iam:CreateUser",
        "ec2:*",
        "GetObject",
        "s3:",
        "cairn:Nuke",
    ] {
        let r = parse(&stmt(&format!(
            r#"{{"Effect":"Allow","Action":"{a}","Resource":"*"}}"#
        )));
        assert!(
            matches!(r, Err(PolicyError::UnknownAction(_))),
            "{a}: {r:?}"
        );
    }
    for a in [
        "*",
        "s3:*",
        "s3:Get*",
        "S3:getobject",
        "cairn:*",
        "cairn:Pitr*",
        "sts:AssumeRole",
        "s3:?etObject",
    ] {
        parse(&stmt(&format!(
            r#"{{"Effect":"Allow","Action":"{a}","Resource":"*"}}"#
        )))
        .unwrap();
    }
}

#[test]
fn rejects_bad_resources_and_principals() {
    for r in ["bucket/*", "arn:aws:s3:::", "arn:aws:s3:eu-west-1::b"] {
        let e = parse(&stmt(&format!(
            r#"{{"Effect":"Allow","Action":"s3:*","Resource":"{r}"}}"#
        )));
        assert!(
            matches!(e, Err(PolicyError::InvalidResource(_))),
            "{r}: {e:?}"
        );
    }
    for p in [
        "alice",
        "arn:aws:s3:::b",
        "arn:aws:iam::000000000000:group/x",
        "12345",
    ] {
        let e = parse(&stmt(&format!(
            r#"{{"Effect":"Allow","Principal":{{"AWS":"{p}"}},"Action":"s3:*","Resource":"*"}}"#
        )));
        assert!(
            matches!(e, Err(PolicyError::InvalidPrincipal(_))),
            "{p}: {e:?}"
        );
    }
}

#[test]
fn size_limit() {
    let pad = "x".repeat(MAX_POLICY_BYTES);
    let big = stmt(&format!(
        r#"{{"Sid":"{pad}","Effect":"Allow","Action":"s3:*","Resource":"*"}}"#
    ));
    assert!(matches!(parse(&big), Err(PolicyError::TooLarge(..))));
    let huge = "x".repeat(5 * MAX_POLICY_BYTES);
    assert!(matches!(
        huge.parse::<PolicyDocument>(),
        Err(PolicyError::TooLarge(..))
    ));
    let ok = stmt(&format!(
        r#"{{"Sid":"{}","Effect":"Allow","Action":"s3:*","Resource":"*"}}"#,
        "y".repeat(MAX_POLICY_BYTES - 200)
    ));
    parse(&ok).unwrap();
}

#[test]
fn duplicate_sid() {
    let d = stmt(
        r#"{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"},{"Sid":"A","Effect":"Deny","Action":"s3:*","Resource":"*"}"#,
    );
    assert!(parse(&d).is_err());
}

#[test]
fn kind_rules() {
    let id = stmt(r#"{"Effect":"Allow","Action":"s3:*","Resource":"*"}"#);
    let bp = stmt(
        r#"{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}"#,
    );
    let trust = stmt(
        r#"{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/alice"},"Action":"sts:AssumeRole"}"#,
    );
    let p = |s: &str| s.parse::<PolicyDocument>().unwrap();
    p(&id).validate_for(PolicyKind::Identity).unwrap();
    p(&id).validate_for(PolicyKind::Session).unwrap();
    assert!(p(&id).validate_for(PolicyKind::Bucket("b")).is_err());
    assert!(p(&id).validate_for(PolicyKind::Trust).is_err());
    p(&bp).validate_for(PolicyKind::Bucket("b")).unwrap();
    assert!(p(&bp).validate_for(PolicyKind::Bucket("other")).is_err());
    assert!(p(&bp).validate_for(PolicyKind::Bucket("b2")).is_err());
    assert!(p(&bp).validate_for(PolicyKind::Identity).is_err());
    p(&trust).validate_for(PolicyKind::Trust).unwrap();
    assert!(p(&trust).validate_for(PolicyKind::Identity).is_err());
    let trust_s3 = trust.replace("sts:AssumeRole", "s3:GetObject");
    assert!(p(&trust_s3).validate_for(PolicyKind::Trust).is_err());
    // identity without Resource
    let nores = stmt(r#"{"Effect":"Allow","Action":"s3:*"}"#);
    assert!(p(&nores).validate_for(PolicyKind::Identity).is_err());
}

#[test]
fn single_statement_object_and_string_forms() {
    let d = parse(r#"{"Statement":{"Effect":"Deny","NotAction":"s3:GetObject","NotResource":"arn:aws:s3:::b/*"}}"#).unwrap();
    let st = &d.statements()[0];
    assert!(st.not_action && st.not_resource);
    assert_eq!(st.effect, Effect::Deny);
    assert!(d.version().is_none());
}

#[test]
fn date_formats() {
    use condition::parse_date;
    let a = parse_date("2026-01-01T00:00:00Z").unwrap();
    assert_eq!(parse_date("2026-01-01").unwrap(), a);
    assert_eq!(parse_date("2026-01-01T00:00:00").unwrap(), a);
    assert_eq!(parse_date("1767225600").unwrap(), a);
    assert_eq!(parse_date("2026-01-01T01:00:00+01:00").unwrap(), a);
    assert!(parse_date("soon").is_none());
}
