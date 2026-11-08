//! Table-driven evaluator tests (classic AWS examples + Cairn extensions).

use crate::engine::{AuthzEngine, BucketAuthz};
use crate::eval::{ConditionContext, Decision, PublicAccessBlock};
use crate::policy::{PolicyDocument, PolicyKind};
use crate::principal::Principal;
use crate::types::ManualClock;
use std::sync::Arc;

use Decision::{Allow, Deny, Implicit};

#[derive(Clone, Copy)]
enum Who {
    Anon,
    Root,
    User(&'static str),
    /// Role session "app/s1" of role "app".
    Session,
}

struct Case {
    name: &'static str,
    who: Who,
    identity: Vec<&'static str>,
    session: Option<&'static str>,
    bucket: Option<&'static str>,
    restrict_public: bool,
    cidrs: Vec<&'static str>,
    action: &'static str,
    resource: &'static str,
    ctx: Vec<(&'static str, &'static str)>,
    want: Decision,
}

fn case(
    name: &'static str,
    who: Who,
    action: &'static str,
    resource: &'static str,
    want: Decision,
) -> Case {
    Case {
        name,
        who,
        identity: vec![],
        session: None,
        bucket: None,
        restrict_public: false,
        cidrs: vec![],
        action,
        resource,
        ctx: vec![],
        want,
    }
}

impl Case {
    fn id(mut self, p: &'static str) -> Self {
        self.identity.push(p);
        self
    }
    fn bp(mut self, p: &'static str) -> Self {
        self.bucket = Some(p);
        self
    }
    fn sess(mut self, p: &'static str) -> Self {
        self.session = Some(p);
        self
    }
    fn ctx(mut self, k: &'static str, v: &'static str) -> Self {
        self.ctx.push((k, v));
        self
    }
    fn restrict(mut self) -> Self {
        self.restrict_public = true;
        self
    }
    fn cidr(mut self, c: &'static str) -> Self {
        self.cidrs.push(c);
        self
    }
}

fn doc(s: &str, kind: PolicyKind<'_>) -> PolicyDocument {
    let d: PolicyDocument = s.parse().unwrap_or_else(|e| panic!("parse {s}: {e}"));
    d.validate_for(kind)
        .unwrap_or_else(|e| panic!("validate {s}: {e}"));
    d
}

fn run(c: &Case) -> Decision {
    let ids: Vec<PolicyDocument> = c
        .identity
        .iter()
        .map(|s| doc(s, PolicyKind::Identity))
        .collect();
    let mut p = match c.who {
        Who::Anon => None,
        Who::Root => Some(Principal::root()),
        Who::User(n) => Some(Principal::user(
            n,
            &format!("AIDA{}", n.to_uppercase()),
            ids,
        )),
        Who::Session => Some(Principal::assumed_role(
            "app",
            "AROAAPP",
            "s1",
            ids,
            c.session.map(|s| doc(s, PolicyKind::Session)),
        )),
    };
    if let Some(p) = p.as_mut() {
        p.allowed_source_cidrs = c.cidrs.iter().map(|s| s.parse().unwrap()).collect();
    }
    let bucket_name = c
        .resource
        .strip_prefix("arn:aws:s3:::")
        .map(|r| r.split('/').next().unwrap());
    let bucket = c.bucket.map(|b| BucketAuthz {
        policy: Some(doc(
            b,
            PolicyKind::Bucket(bucket_name.expect("bucket policy needs s3 resource")),
        )),
        public_access_block: PublicAccessBlock {
            restrict_public_buckets: c.restrict_public,
            ..Default::default()
        },
    });
    let mut ctx = ConditionContext::new();
    for (k, v) in &c.ctx {
        ctx.insert(k, *v);
    }
    let engine = AuthzEngine::with_clock(Arc::new(ManualClock::new(1_794_000_000))); // 2026-11-06
    engine.authorize(p.as_ref(), c.action, c.resource, &ctx, bucket.as_ref())
}

const RO: &str = r#"{"Version":"2012-10-17","Statement":[{"Sid":"ReadOnly","Effect":"Allow",
 "Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}"#;

const HOME: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Sid":"List","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::corp",
  "Condition":{"StringLike":{"s3:prefix":["","home/","home/${aws:username}/*"]}}},
 {"Sid":"RW","Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],
  "Resource":"arn:aws:s3:::corp/home/${aws:username}/*"}]}"#;

const HOME_2008: &str = r#"{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
 "Resource":"arn:aws:s3:::corp/${aws:username}/*"}]}"#;

const ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

const IP: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:*","Resource":"*",
  "Condition":{"NotIpAddress":{"aws:SourceIp":["192.0.2.0/24","2001:db8::/32"]}}}]}"#;

const TLS_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Sid":"TLS","Effect":"Deny","Principal":"*",
 "Action":"s3:*","Resource":["arn:aws:s3:::secure","arn:aws:s3:::secure/*"],
 "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}"#;

const MFA: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*",
  "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}"#;

const MFA_NULL: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"Null":{"aws:MultiFactorAuthAge":"true"}}}]}"#;

const TAGS: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*",
  "Condition":{"StringEquals":{"s3:ExistingObjectTag/classification":"public"}}},
 {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::data/*",
  "Condition":{"StringEquals":{"s3:RequestObjectTag/owner":"${aws:username}"}}}]}"#;

const TAG_KEYS: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:PutObjectTagging","Resource":"arn:aws:s3:::data/*",
  "Condition":{"ForAllValues:StringEquals":{"s3:RequestObjectTagKeys":["project","owner"]}}}]}"#;

const TAG_KEYS_DENY: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:PutObjectTagging","Resource":"*"},
 {"Effect":"Deny","Action":"s3:PutObjectTagging","Resource":"*",
  "Condition":{"ForAnyValue:StringLike":{"s3:RequestObjectTagKeys":"aws:*"}}}]}"#;

const PUBLIC_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow",
 "Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::www/*"}]}"#;

const PUBLIC_AWS_STAR_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::www/*"}]}"#;

const ALICE_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":["arn:aws:iam::000000000000:user/alice"]},"Action":["s3:GetObject","s3:PutObject"],
 "Resource":"arn:aws:s3:::shared/*"}]}"#;

const ACCOUNT_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"000000000000"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::acct/*"}]}"#;

const ACCOUNT_DENY_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
 "Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::acct/*"}]}"#;

const DENY_ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}"#;

const NOT_ACTION: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"s3:Delete*","Resource":"*"}]}"#;

const NOT_RESOURCE: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::allowed","arn:aws:s3:::allowed/*"]}]}"#;

const NOT_PRINCIPAL_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
 "NotPrincipal":{"AWS":"arn:aws:iam::000000000000:user/alice"},"Action":"s3:*","Resource":"arn:aws:s3:::vault/*"}]}"#;

const MAX_KEYS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket",
 "Resource":"arn:aws:s3:::logs","Condition":{"NumericLessThanEquals":{"s3:max-keys":"100"}}}]}"#;

const EXPIRES: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2030-01-01T00:00:00Z"}}}]}"#;

const EPOCH: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
 "Condition":{"DateLessThan":{"aws:EpochTime":1893456000}}}]}"#;

const SSE: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:PutObject","Resource":"*"},
 {"Effect":"Deny","Action":"s3:PutObject","Resource":"*",
  "Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"}}}]}"#;

const UA: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
 "Condition":{"StringEqualsIgnoreCase":{"aws:UserAgent":"AWS-CLI"}}}]}"#;

const REFERER_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
 "Action":"s3:GetObject","Resource":"arn:aws:s3:::www/*",
 "Condition":{"StringLike":{"aws:Referer":["https://example.com/*","https://www.example.com/*"]}}}]}"#;

const ARN_LIKE_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
 "Action":"s3:GetObject","Resource":"arn:aws:s3:::team/*",
 "Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/a*"}}}]}"#;

const ARN_NOT_EQUALS: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*",
  "Condition":{"ArnNotEquals":{"aws:PrincipalArn":"arn:aws:iam::000000000000:user/alice"}}}]}"#;

const ACL: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:PutObject","Resource":"*"},
 {"Effect":"Deny","Action":"s3:PutObject","Resource":"*","Condition":{"StringEquals":{"s3:x-amz-acl":["public-read","public-read-write"]}}}]}"#;

const AUTH_TYPE: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"s3:authType":"REST-HEADER"}}}]}"#;

const SIG_AGE: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"NumericGreaterThan":{"s3:signatureAge":600000}}}]}"#;

const MCP: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::docs","arn:aws:s3:::docs/*"],
  "Condition":{"StringEquals":{"cairn:McpTool":["get_object","list_objects"]}}},
 {"Effect":"Deny","Action":"cairn:Purge","Resource":"*"}]}"#;

const CAIRN_ADMIN: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"cairn:*","Resource":"*"},
 {"Effect":"Deny","Action":["cairn:Purge","cairn:SetRetention"],"Resource":"*"}]}"#;

const AS_OF: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cairn:TimeTravel",
 "Resource":"arn:aws:s3:::docs/*","Condition":{"DateGreaterThanEquals":{"cairn:AsOf":"2026-01-01T00:00:00Z"}}}]}"#;

const PREFIXES: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket",
 "Resource":"arn:aws:s3:::logs","Condition":{"StringEquals":{"s3:prefix":["a/","b/"],"s3:delimiter":"/"}}}]}"#;

const ROLE_ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
const SESS_GET: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
const SESS_DENY: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/private/*"}]}"#;
const SESSION_ARN_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:sts::000000000000:assumed-role/app/s1"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::drop/*"}]}"#;
const ROLE_ARN_BP: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:iam::000000000000:role/app"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::drop/*"}]}"#;

const GET_STAR: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}"#;
const USERID: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*",
 "Resource":"arn:aws:s3:::ids/${aws:userid}/*"}]}"#;
const QMARK: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
 "Resource":"arn:aws:s3:::logs/202?-*.log"}]}"#;
const PRINCIPAL_ARN_VAR: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject",
 "Resource":"arn:aws:s3:::audit/*","Condition":{"StringEquals":{"s3:RequestObjectTag/by":"${aws:PrincipalArn}"}}}]}"#;
const COPY_SRC: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject",
 "Resource":"arn:aws:s3:::dst/*","Condition":{"StringLike":{"s3:x-amz-copy-source":"src/public/*"}}}]}"#;
const VERSION_ID: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObjectVersion",
 "Resource":"arn:aws:s3:::v/*","Condition":{"StringEquals":{"s3:VersionId":"abc123"}}}]}"#;
const LOCK: &str = r#"{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:PutObjectRetention","Resource":"*"},
 {"Effect":"Deny","Action":"s3:PutObjectRetention","Resource":"*","Condition":{
   "StringEquals":{"s3:object-lock-mode":"GOVERNANCE"},
   "DateGreaterThan":{"s3:object-lock-retain-until-date":"2027-01-01T00:00:00Z"}}}]}"#;
const IP_IFEXISTS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
 "Condition":{"IpAddressIfExists":{"aws:SourceIp":"10.0.0.0/8"}}}]}"#;
const NULL_FALSE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
 "Condition":{"Null":{"s3:ExistingObjectTag/project":"false"}}}]}"#;
const DELIM_NOT_LIKE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket",
 "Resource":"*","Condition":{"StringNotLike":{"s3:prefix":"secret/*"}}}]}"#;

fn cases() -> Vec<Case> {
    use Who::*;
    let alice = User("alice");
    let bob = User("bob");
    vec![
        // --- read-only bucket
        case(
            "ro get",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::photos/a.jpg",
            Allow,
        )
        .id(RO),
        case(
            "ro list",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::photos",
            Allow,
        )
        .id(RO),
        case(
            "ro put denied",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::photos/a.jpg",
            Implicit,
        )
        .id(RO),
        case(
            "ro other bucket",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::other/a",
            Implicit,
        )
        .id(RO),
        case(
            "ro version not covered",
            alice,
            "s3:GetObjectVersion",
            "arn:aws:s3:::photos/a",
            Implicit,
        )
        .id(RO),
        case(
            "ro action case-insensitive",
            alice,
            "S3:GETOBJECT",
            "arn:aws:s3:::photos/a",
            Allow,
        )
        .id(RO),
        case(
            "ro bucket prefix not glob",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::photosx/a",
            Implicit,
        )
        .id(RO),
        case(
            "ro resource case-sensitive",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::Photos/a",
            Implicit,
        )
        .id(RO),
        case(
            "no policies",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            Implicit,
        ),
        // --- home directories
        case(
            "home list root",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::corp",
            Allow,
        )
        .id(HOME)
        .ctx("s3:prefix", ""),
        case(
            "home list home/",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::corp",
            Allow,
        )
        .id(HOME)
        .ctx("s3:prefix", "home/"),
        case(
            "home list own",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::corp",
            Allow,
        )
        .id(HOME)
        .ctx("s3:prefix", "home/alice/docs"),
        case(
            "home list other",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::corp",
            Implicit,
        )
        .id(HOME)
        .ctx("s3:prefix", "home/bob/"),
        case(
            "home list no prefix",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::corp",
            Implicit,
        )
        .id(HOME),
        case(
            "home get own",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::corp/home/alice/x",
            Allow,
        )
        .id(HOME),
        case(
            "home put other",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::corp/home/bob/x",
            Implicit,
        )
        .id(HOME),
        case(
            "home bob own",
            bob,
            "s3:PutObject",
            "arn:aws:s3:::corp/home/bob/x",
            Allow,
        )
        .id(HOME),
        case(
            "home dir itself",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::corp/home/alice",
            Implicit,
        )
        .id(HOME),
        case(
            "home var spoof ignored",
            bob,
            "s3:GetObject",
            "arn:aws:s3:::corp/home/alice/x",
            Implicit,
        )
        .id(HOME)
        .ctx("aws:username", "alice"),
        case(
            "home role session has no username",
            Session,
            "s3:GetObject",
            "arn:aws:s3:::corp/home/app/x",
            Implicit,
        )
        .id(HOME),
        case(
            "2008 version no vars",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::corp/alice/x",
            Implicit,
        )
        .id(HOME_2008),
        case(
            "2008 version literal",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::corp/${aws:username}/x",
            Allow,
        )
        .id(HOME_2008),
        case(
            "userid var",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::ids/AIDAALICE/f",
            Allow,
        )
        .id(USERID),
        case(
            "userid var other",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::ids/AIDABOB/f",
            Implicit,
        )
        .id(USERID),
        case(
            "principal arn var",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::audit/x",
            Allow,
        )
        .id(PRINCIPAL_ARN_VAR)
        .ctx(
            "s3:RequestObjectTag/by",
            "arn:aws:iam::000000000000:user/alice",
        ),
        // --- IP restriction
        case(
            "ip inside v4",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::any/x",
            Allow,
        )
        .id(IP)
        .ctx("aws:SourceIp", "192.0.2.10"),
        case(
            "ip outside",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::any/x",
            Deny,
        )
        .id(IP)
        .ctx("aws:SourceIp", "203.0.113.5"),
        case(
            "ip inside v6",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::any/x",
            Allow,
        )
        .id(IP)
        .ctx("aws:SourceIp", "2001:db8::1"),
        case(
            "ip missing",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::any/x",
            Deny,
        )
        .id(IP),
        case(
            "ip garbage",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::any/x",
            Deny,
        )
        .id(IP)
        .ctx("aws:SourceIp", "nope"),
        case(
            "ip ifexists missing",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::any/x",
            Allow,
        )
        .id(IP_IFEXISTS),
        case(
            "ip ifexists outside",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::any/x",
            Implicit,
        )
        .id(IP_IFEXISTS)
        .ctx("aws:SourceIp", "8.8.8.8"),
        // --- TLS-only bucket policy
        case(
            "tls insecure",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::secure/x",
            Deny,
        )
        .id(ALL)
        .bp(TLS_BP)
        .ctx("aws:SecureTransport", "false"),
        case(
            "tls secure",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::secure/x",
            Allow,
        )
        .id(ALL)
        .bp(TLS_BP)
        .ctx("aws:SecureTransport", "true"),
        case(
            "tls missing key",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::secure/x",
            Allow,
        )
        .id(ALL)
        .bp(TLS_BP),
        case(
            "tls anon insecure",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::secure/x",
            Deny,
        )
        .bp(TLS_BP)
        .ctx("aws:SecureTransport", "false"),
        // --- MFA-less deny
        case(
            "mfa missing delete",
            alice,
            "s3:DeleteObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(MFA),
        case(
            "mfa true delete",
            alice,
            "s3:DeleteObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(MFA)
        .ctx("aws:MultiFactorAuthPresent", "true"),
        case(
            "mfa false delete",
            alice,
            "s3:DeleteObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(MFA)
        .ctx("aws:MultiFactorAuthPresent", "false"),
        case(
            "mfa get unaffected",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(MFA),
        case(
            "mfa null missing",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(MFA_NULL),
        case(
            "mfa null present",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(MFA_NULL)
        .ctx("aws:MultiFactorAuthAge", "300"),
        // --- tag-based access
        case(
            "tag public",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAGS)
        .ctx("s3:ExistingObjectTag/classification", "public"),
        case(
            "tag secret",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::data/x",
            Implicit,
        )
        .id(TAGS)
        .ctx("s3:ExistingObjectTag/classification", "secret"),
        case(
            "tag missing",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::data/x",
            Implicit,
        )
        .id(TAGS),
        case(
            "tag key case-sensitive",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::data/x",
            Implicit,
        )
        .id(TAGS)
        .ctx("s3:ExistingObjectTag/Classification", "public"),
        case(
            "tag key prefix case-insensitive",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAGS)
        .ctx("S3:EXISTINGOBJECTTAG/classification", "public"),
        case(
            "request tag owner",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAGS)
        .ctx("s3:RequestObjectTag/owner", "alice"),
        case(
            "request tag other owner",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::data/x",
            Implicit,
        )
        .id(TAGS)
        .ctx("s3:RequestObjectTag/owner", "bob"),
        case(
            "null false tag present",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::d/x",
            Allow,
        )
        .id(NULL_FALSE)
        .ctx("s3:ExistingObjectTag/project", "p"),
        case(
            "null false tag absent",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::d/x",
            Implicit,
        )
        .id(NULL_FALSE),
        // --- set operators
        case(
            "forall subset",
            alice,
            "s3:PutObjectTagging",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAG_KEYS)
        .ctx("s3:RequestObjectTagKeys", "project"),
        case(
            "forall full",
            alice,
            "s3:PutObjectTagging",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAG_KEYS)
        .ctx("s3:RequestObjectTagKeys", "project")
        .ctx("s3:RequestObjectTagKeys", "owner"),
        case(
            "forall extra key",
            alice,
            "s3:PutObjectTagging",
            "arn:aws:s3:::data/x",
            Implicit,
        )
        .id(TAG_KEYS)
        .ctx("s3:RequestObjectTagKeys", "project")
        .ctx("s3:RequestObjectTagKeys", "cost"),
        case(
            "forall empty",
            alice,
            "s3:PutObjectTagging",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAG_KEYS),
        case(
            "foranyvalue deny hit",
            alice,
            "s3:PutObjectTagging",
            "arn:aws:s3:::data/x",
            Deny,
        )
        .id(TAG_KEYS_DENY)
        .ctx("s3:RequestObjectTagKeys", "project")
        .ctx("s3:RequestObjectTagKeys", "aws:foo"),
        case(
            "foranyvalue deny miss",
            alice,
            "s3:PutObjectTagging",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAG_KEYS_DENY)
        .ctx("s3:RequestObjectTagKeys", "project"),
        case(
            "foranyvalue missing",
            alice,
            "s3:PutObjectTagging",
            "arn:aws:s3:::data/x",
            Allow,
        )
        .id(TAG_KEYS_DENY),
        // --- public bucket / anonymous
        case(
            "anon public read",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::www/index.html",
            Allow,
        )
        .bp(PUBLIC_BP),
        case(
            "anon public put",
            Anon,
            "s3:PutObject",
            "arn:aws:s3:::www/x",
            Implicit,
        )
        .bp(PUBLIC_BP),
        case(
            "anon public list",
            Anon,
            "s3:ListBucket",
            "arn:aws:s3:::www",
            Implicit,
        )
        .bp(PUBLIC_BP),
        case(
            "anon PAB restrict",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::www/index.html",
            Implicit,
        )
        .bp(PUBLIC_BP)
        .restrict(),
        case(
            "user via public bp",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::www/index.html",
            Allow,
        )
        .bp(PUBLIC_BP),
        case(
            "user via public bp PAB",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::www/index.html",
            Allow,
        )
        .bp(PUBLIC_BP)
        .restrict(),
        case(
            "anon identity irrelevant",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::www/x",
            Implicit,
        )
        .id(ALL),
        case(
            "anon AWS star",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::www/x",
            Allow,
        )
        .bp(PUBLIC_AWS_STAR_BP),
        case(
            "anon referer ok",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::www/x",
            Allow,
        )
        .bp(REFERER_BP)
        .ctx("aws:Referer", "https://example.com/page"),
        case(
            "anon referer bad",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::www/x",
            Implicit,
        )
        .bp(REFERER_BP)
        .ctx("aws:Referer", "https://evil.com/"),
        case(
            "anon named principal",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::shared/x",
            Implicit,
        )
        .bp(ALICE_BP),
        case(
            "named principal alice",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::shared/x",
            Allow,
        )
        .bp(ALICE_BP),
        case(
            "named principal bob",
            bob,
            "s3:PutObject",
            "arn:aws:s3:::shared/x",
            Implicit,
        )
        .bp(ALICE_BP),
        case(
            "account principal alone",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::acct/x",
            Implicit,
        )
        .bp(ACCOUNT_BP),
        case(
            "account principal + identity",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::acct/x",
            Allow,
        )
        .bp(ACCOUNT_BP)
        .id(GET_STAR),
        case(
            "account principal deny",
            alice,
            "s3:DeleteObject",
            "arn:aws:s3:::acct/x",
            Deny,
        )
        .bp(ACCOUNT_DENY_BP)
        .id(ALL),
        case(
            "anon not in account deny",
            Anon,
            "s3:DeleteObject",
            "arn:aws:s3:::acct/x",
            Implicit,
        )
        .bp(ACCOUNT_DENY_BP),
        case(
            "bp arnlike alice",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::team/x",
            Allow,
        )
        .bp(ARN_LIKE_BP),
        case(
            "bp arnlike bob",
            bob,
            "s3:GetObject",
            "arn:aws:s3:::team/x",
            Implicit,
        )
        .bp(ARN_LIKE_BP),
        case(
            "bp arnlike anon",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::team/x",
            Implicit,
        )
        .bp(ARN_LIKE_BP),
        // --- root
        case(
            "root explicit deny ignored",
            Root,
            "s3:DeleteBucket",
            "arn:aws:s3:::any",
            Allow,
        )
        .bp(NOT_PRINCIPAL_BP.replace("vault/*", "any").leak()),
        case(
            "root no policies",
            Root,
            "cairn:Purge",
            "arn:cairn:admin:::server",
            Allow,
        ),
        case(
            "deny all beats allow",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            Deny,
        )
        .id(RO)
        .id(DENY_ALL),
        // --- Not* elements
        case(
            "notaction allow get",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(NOT_ACTION),
        case(
            "notaction excludes delete",
            alice,
            "s3:DeleteObjectVersion",
            "arn:aws:s3:::b/x",
            Implicit,
        )
        .id(NOT_ACTION),
        case(
            "notresource deny outside",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::other/x",
            Deny,
        )
        .id(NOT_RESOURCE),
        case(
            "notresource inside",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::allowed/x",
            Allow,
        )
        .id(NOT_RESOURCE),
        case(
            "notprincipal bob denied",
            bob,
            "s3:GetObject",
            "arn:aws:s3:::vault/x",
            Deny,
        )
        .id(ALL)
        .bp(NOT_PRINCIPAL_BP),
        case(
            "notprincipal alice allowed",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::vault/x",
            Allow,
        )
        .id(ALL)
        .bp(NOT_PRINCIPAL_BP),
        case(
            "notprincipal anon denied",
            Anon,
            "s3:GetObject",
            "arn:aws:s3:::vault/x",
            Deny,
        )
        .bp(NOT_PRINCIPAL_BP),
        // --- numeric / date / string ops
        case(
            "max-keys ok",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Allow,
        )
        .id(MAX_KEYS)
        .ctx("s3:max-keys", "50"),
        case(
            "max-keys too big",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Implicit,
        )
        .id(MAX_KEYS)
        .ctx("s3:max-keys", "500"),
        case(
            "max-keys garbage",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Implicit,
        )
        .id(MAX_KEYS)
        .ctx("s3:max-keys", "abc"),
        case(
            "current time before expiry",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(EXPIRES),
        case(
            "current time after expiry",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(EXPIRES)
        .ctx("aws:CurrentTime", "2031-05-01T00:00:00Z"),
        case(
            "epoch time",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(EPOCH),
        case(
            "epoch time late",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Implicit,
        )
        .id(EPOCH)
        .ctx("aws:EpochTime", "1993456000"),
        case(
            "sse missing",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(SSE),
        case(
            "sse aes256",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(SSE)
        .ctx("s3:x-amz-server-side-encryption", "AES256"),
        case("sse kms", alice, "s3:PutObject", "arn:aws:s3:::b/x", Deny)
            .id(SSE)
            .ctx("s3:x-amz-server-side-encryption", "aws:kms"),
        case(
            "user agent ignore case",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(UA)
        .ctx("aws:UserAgent", "aws-cli"),
        case(
            "user agent other",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Implicit,
        )
        .id(UA)
        .ctx("aws:UserAgent", "curl"),
        case(
            "arn not equals bob",
            bob,
            "s3:DeleteBucket",
            "arn:aws:s3:::b",
            Deny,
        )
        .id(ARN_NOT_EQUALS),
        case(
            "arn not equals alice",
            alice,
            "s3:DeleteBucket",
            "arn:aws:s3:::b",
            Allow,
        )
        .id(ARN_NOT_EQUALS),
        case(
            "acl public-read",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(ACL)
        .ctx("s3:x-amz-acl", "public-read"),
        case(
            "acl private",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(ACL)
        .ctx("s3:x-amz-acl", "private"),
        case(
            "auth type query",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(AUTH_TYPE)
        .ctx("s3:authType", "REST-QUERY-STRING"),
        case(
            "auth type header",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(AUTH_TYPE)
        .ctx("s3:authType", "REST-HEADER"),
        case(
            "signature age old",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(SIG_AGE)
        .ctx("s3:signatureAge", "700000"),
        case(
            "signature age fresh",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(SIG_AGE)
        .ctx("s3:signatureAge", "1000"),
        case(
            "prefix OR values",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Allow,
        )
        .id(PREFIXES)
        .ctx("s3:prefix", "b/")
        .ctx("s3:delimiter", "/"),
        case(
            "keys AND",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Implicit,
        )
        .id(PREFIXES)
        .ctx("s3:prefix", "b/"),
        case(
            "prefix not like ok",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Allow,
        )
        .id(DELIM_NOT_LIKE)
        .ctx("s3:prefix", "public/"),
        case(
            "prefix not like hit",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Implicit,
        )
        .id(DELIM_NOT_LIKE)
        .ctx("s3:prefix", "secret/x"),
        case(
            "prefix not like missing",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::logs",
            Allow,
        )
        .id(DELIM_NOT_LIKE),
        case(
            "copy source ok",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::dst/x",
            Allow,
        )
        .id(COPY_SRC)
        .ctx("s3:x-amz-copy-source", "src/public/a.txt"),
        case(
            "copy source bad",
            alice,
            "s3:PutObject",
            "arn:aws:s3:::dst/x",
            Implicit,
        )
        .id(COPY_SRC)
        .ctx("s3:x-amz-copy-source", "src/private/a.txt"),
        case(
            "version id ok",
            alice,
            "s3:GetObjectVersion",
            "arn:aws:s3:::v/x",
            Allow,
        )
        .id(VERSION_ID)
        .ctx("s3:VersionId", "abc123"),
        case(
            "version id other",
            alice,
            "s3:GetObjectVersion",
            "arn:aws:s3:::v/x",
            Implicit,
        )
        .id(VERSION_ID)
        .ctx("s3:VersionId", "zzz"),
        case(
            "lock governance long",
            alice,
            "s3:PutObjectRetention",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(LOCK)
        .ctx("s3:object-lock-mode", "GOVERNANCE")
        .ctx("s3:object-lock-retain-until-date", "2028-01-01T00:00:00Z"),
        case(
            "lock governance short",
            alice,
            "s3:PutObjectRetention",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(LOCK)
        .ctx("s3:object-lock-mode", "GOVERNANCE")
        .ctx("s3:object-lock-retain-until-date", "2026-12-01T00:00:00Z"),
        case(
            "lock compliance long",
            alice,
            "s3:PutObjectRetention",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(LOCK)
        .ctx("s3:object-lock-mode", "COMPLIANCE")
        .ctx("s3:object-lock-retain-until-date", "2028-01-01T00:00:00Z"),
        // --- wildcards
        case(
            "get* covers tagging",
            alice,
            "s3:GetObjectTagging",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(GET_STAR),
        case(
            "get* not list",
            alice,
            "s3:ListBucket",
            "arn:aws:s3:::b",
            Implicit,
        )
        .id(GET_STAR),
        case(
            "qmark resource",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::logs/2026-11.log",
            Allow,
        )
        .id(QMARK),
        case(
            "qmark resource miss",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::logs/20266-11.log",
            Implicit,
        )
        .id(QMARK),
        // --- Cairn: MCP and admin
        case(
            "mcp tool allowed",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::docs/a.md",
            Allow,
        )
        .id(MCP)
        .ctx("cairn:McpTool", "get_object"),
        case(
            "mcp tool other",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::docs/a.md",
            Implicit,
        )
        .id(MCP)
        .ctx("cairn:McpTool", "put_object"),
        case(
            "mcp policy not for plain s3",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::docs/a.md",
            Implicit,
        )
        .id(MCP),
        case(
            "mcp purge denied",
            alice,
            "cairn:Purge",
            "arn:aws:s3:::docs/a.md",
            Deny,
        )
        .id(MCP)
        .id(ALL)
        .ctx("cairn:McpTool", "trash_list"),
        case(
            "cairn wildcard restore",
            alice,
            "cairn:Restore",
            "arn:aws:s3:::b/x",
            Allow,
        )
        .id(CAIRN_ADMIN),
        case(
            "cairn wildcard purge denied",
            alice,
            "cairn:Purge",
            "arn:aws:s3:::b/x",
            Deny,
        )
        .id(CAIRN_ADMIN),
        case(
            "cairn wildcard not s3",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::b/x",
            Implicit,
        )
        .id(CAIRN_ADMIN),
        case(
            "as-of recent",
            alice,
            "cairn:TimeTravel",
            "arn:aws:s3:::docs/x",
            Allow,
        )
        .id(AS_OF)
        .ctx("cairn:AsOf", "2026-06-01T00:00:00Z"),
        case(
            "as-of too old",
            alice,
            "cairn:TimeTravel",
            "arn:aws:s3:::docs/x",
            Implicit,
        )
        .id(AS_OF)
        .ctx("cairn:AsOf", "2025-06-01T00:00:00Z"),
        // --- sessions
        case(
            "session intersect allow",
            Session,
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            Allow,
        )
        .id(ROLE_ALL)
        .sess(SESS_GET),
        case(
            "session intersect cut",
            Session,
            "s3:PutObject",
            "arn:aws:s3:::photos/a",
            Implicit,
        )
        .id(ROLE_ALL)
        .sess(SESS_GET),
        case(
            "session no role grant",
            Session,
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            Implicit,
        )
        .sess(SESS_GET),
        case(
            "session policy deny",
            Session,
            "s3:GetObject",
            "arn:aws:s3:::photos/private/a",
            Deny,
        )
        .id(ROLE_ALL)
        .sess(SESS_DENY),
        case(
            "session arn bp bypasses session policy",
            Session,
            "s3:PutObject",
            "arn:aws:s3:::drop/x",
            Allow,
        )
        .sess(SESS_GET)
        .bp(SESSION_ARN_BP),
        case(
            "role arn bp limited by session policy",
            Session,
            "s3:PutObject",
            "arn:aws:s3:::drop/x",
            Implicit,
        )
        .sess(SESS_GET)
        .bp(ROLE_ARN_BP),
        case(
            "role arn bp no session policy",
            Session,
            "s3:PutObject",
            "arn:aws:s3:::drop/x",
            Allow,
        )
        .bp(ROLE_ARN_BP),
        // --- allowed source CIDRs on the access key
        case(
            "cidr inside",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            Allow,
        )
        .id(RO)
        .cidr("10.0.0.0/8")
        .ctx("aws:SourceIp", "10.1.2.3"),
        case(
            "cidr outside",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            Deny,
        )
        .id(RO)
        .cidr("10.0.0.0/8")
        .ctx("aws:SourceIp", "192.168.1.1"),
        case(
            "cidr no source ip",
            alice,
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            Deny,
        )
        .id(RO)
        .cidr("10.0.0.0/8"),
    ]
}

#[test]
fn evaluator_table() {
    let cs = cases();
    assert!(cs.len() >= 60, "only {} cases", cs.len());
    let mut failures = Vec::new();
    for c in &cs {
        let got = run(c);
        if got != c.want {
            failures.push(format!("{}: want {:?}, got {:?}", c.name, c.want, got));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} failed:\n{}",
        failures.len(),
        cs.len(),
        failures.join("\n")
    );
    eprintln!("{} evaluator cases passed", cs.len());
}

#[test]
fn authorize_s3_op_names() {
    let engine = AuthzEngine::new();
    let p = Principal::user("alice", "AIDA1", vec![doc(RO, PolicyKind::Identity)]);
    let ctx = ConditionContext::new();
    assert_eq!(
        engine.authorize_s3(
            Some(&p),
            "ListObjectsV2",
            Some("photos"),
            None,
            false,
            &ctx,
            None
        ),
        Allow
    );
    assert_eq!(
        engine.authorize_s3(
            Some(&p),
            "HeadObject",
            Some("photos"),
            Some("a b"),
            false,
            &ctx,
            None
        ),
        Allow
    );
    assert_eq!(
        engine.authorize_s3(
            Some(&p),
            "GetObject",
            Some("photos"),
            Some("a"),
            true,
            &ctx,
            None
        ),
        Implicit
    );
    assert_eq!(
        engine.authorize_s3(
            Some(&p),
            "SelectObjectContent",
            Some("photos"),
            Some("a"),
            false,
            &ctx,
            None
        ),
        Deny
    );
}

#[test]
fn public_policy_detection() {
    assert!(doc(PUBLIC_BP, PolicyKind::Bucket("www")).is_public());
    assert!(!doc(ALICE_BP, PolicyKind::Bucket("shared")).is_public());
    assert!(!doc(TLS_BP, PolicyKind::Bucket("secure")).is_public());
    assert!(doc(REFERER_BP, PolicyKind::Bucket("www")).is_public());
    let ip_pinned = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
      "Resource":"arn:aws:s3:::www/*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}"#;
    assert!(!doc(ip_pinned, PolicyKind::Bucket("www")).is_public());
    let ip_wide = ip_pinned.replace("203.0.113.0/24", "0.0.0.0/0");
    assert!(doc(&ip_wide, PolicyKind::Bucket("www")).is_public());
}
