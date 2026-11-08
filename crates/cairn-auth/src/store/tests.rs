use super::*;
use crate::engine::AuthzEngine;
use crate::eval::{ConditionContext, Decision};
use crate::types::ManualClock;

const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],
 "Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}"#;
const WRITE_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject",
 "Resource":"arn:aws:s3:::photos/*"}]}"#;
const ALL_S3: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
const TRUST_ALICE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:iam::000000000000:user/alice"},"Action":"sts:AssumeRole"}]}"#;
const TRUST_ACCOUNT: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}"#;
const ALLOW_ASSUME: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
 "Resource":"arn:aws:iam::000000000000:role/*"}]}"#;

struct Fx {
    store: CredentialStore,
    backend: Arc<MemoryBackend>,
    clock: Arc<ManualClock>,
}

fn fx() -> Fx {
    let backend = Arc::new(MemoryBackend::new());
    let clock = Arc::new(ManualClock::new(1_794_000_000));
    let store =
        CredentialStore::new(backend.clone(), MasterKey::new([42; 32])).with_clock(clock.clone());
    Fx {
        store,
        backend,
        clock,
    }
}

fn engine(f: &Fx) -> AuthzEngine {
    AuthzEngine::with_clock(f.clock.clone())
}

fn allowed(f: &Fx, c: &Credential, action: &str, res: &str) -> Decision {
    engine(f).authorize(
        Some(&c.principal),
        action,
        res,
        &ConditionContext::new(),
        None,
    )
}

#[tokio::test]
async fn root_bootstrap_lookup_and_rotation() {
    let f = fx();
    assert!(
        f.store
            .lookup("AKIAIOSFODNN7EXAMPLE")
            .await
            .unwrap()
            .is_none()
    );
    let sk = SecretString::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    f.store
        .ensure_root("AKIAIOSFODNN7EXAMPLE", &sk)
        .await
        .unwrap();
    f.store
        .ensure_root("AKIAIOSFODNN7EXAMPLE", &sk)
        .await
        .unwrap();
    let c = f
        .store
        .lookup("AKIAIOSFODNN7EXAMPLE")
        .await
        .unwrap()
        .unwrap();
    assert!(c.principal.is_root);
    assert_eq!(c.secret_key, sk);
    assert!(
        c.session.is_none() && c.verify_session_token(None) && !c.verify_session_token(Some("x"))
    );
    // secrets are never stored in plaintext
    for (_, v) in f.backend.dump() {
        assert!(!v.windows(10).any(|w| w == b"wJalrXUtnF"));
    }
    let new = f.store.rotate_root().await.unwrap();
    assert!(new.access_key_id.starts_with("CAIRN") && new.access_key_id.len() == 20);
    assert!(
        f.store
            .lookup("AKIAIOSFODNN7EXAMPLE")
            .await
            .unwrap()
            .is_none()
    );
    let c = f.store.lookup(&new.access_key_id).await.unwrap().unwrap();
    assert!(c.principal.is_root && c.secret_key == new.secret_key);
    assert_eq!(
        f.store.root_access_key_id().await.unwrap(),
        Some(new.access_key_id.clone())
    );
    // config change replaces it again
    f.store
        .ensure_root("ROOTKEY", &SecretString::new("anothersecret"))
        .await
        .unwrap();
    assert!(f.store.lookup(&new.access_key_id).await.unwrap().is_none());
    assert!(f.store.revoke_access_key("ROOTKEY").await.is_err());
    assert!(
        f.store
            .set_access_key_active("ROOTKEY", false)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn wrong_master_key_fails_closed() {
    let f = fx();
    f.store
        .ensure_root("ROOTKEY", &SecretString::new("rootsecret"))
        .await
        .unwrap();
    let other = CredentialStore::new(f.backend.clone(), MasterKey::new([1; 32]));
    assert!(matches!(
        other.lookup("ROOTKEY").await,
        Err(AuthError::Crypto)
    ));
}

#[tokio::test]
async fn users_keys_policies_and_groups() {
    let f = fx();
    let u = f.store.create_user("alice").await.unwrap();
    assert!(u.user_id.starts_with("AIDA"));
    assert_eq!(u.arn, "arn:aws:iam::000000000000:user/alice");
    assert!(matches!(
        f.store.create_user("alice").await,
        Err(AuthError::AlreadyExists { .. })
    ));
    assert!(f.store.create_user("bad name").await.is_err());
    assert!(f.store.create_user("").await.is_err());

    let k = f
        .store
        .create_access_key("alice", AccessKeyOptions::default())
        .await
        .unwrap();
    assert!(k.access_key_id.starts_with("CAIRN") && k.access_key_id.len() == 20);
    assert_eq!(k.secret_key.expose().len(), 40);
    let c = f.store.lookup(&k.access_key_id).await.unwrap().unwrap();
    assert_eq!(c.principal.username(), Some("alice"));
    assert_eq!(c.principal.user_id, u.user_id);
    assert_eq!(
        allowed(&f, &c, "s3:GetObject", "arn:aws:s3:::photos/a"),
        Decision::Implicit
    );

    // inline policy
    f.store
        .put_user_policy("alice", "read", READ_PHOTOS)
        .await
        .unwrap();
    assert!(f.store.put_user_policy("alice", "bad", "{}").await.is_err());
    let bp = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}]}"#;
    assert!(
        f.store.put_user_policy("alice", "bp", bp).await.is_err(),
        "identity policy with Principal"
    );
    let c = f.store.lookup(&k.access_key_id).await.unwrap().unwrap();
    assert_eq!(
        allowed(&f, &c, "s3:GetObject", "arn:aws:s3:::photos/a"),
        Decision::Allow
    );
    assert_eq!(
        allowed(&f, &c, "s3:PutObject", "arn:aws:s3:::photos/a"),
        Decision::Implicit
    );

    // managed policy via group
    f.store
        .create_policy("photo-writer", WRITE_PHOTOS)
        .await
        .unwrap();
    assert!(
        f.store
            .attach_group_policy("nope", "photo-writer")
            .await
            .is_err()
    );
    f.store.create_group("editors").await.unwrap();
    f.store
        .attach_group_policy("editors", "photo-writer")
        .await
        .unwrap();
    assert!(
        f.store
            .attach_group_policy("editors", "missing")
            .await
            .is_err()
    );
    f.store.add_user_to_group("alice", "editors").await.unwrap();
    let g = f.store.get_group("editors").await.unwrap();
    assert_eq!(g.members, vec!["alice".to_string()]);
    let c = f.store.lookup(&k.access_key_id).await.unwrap().unwrap();
    assert_eq!(c.principal.groups, vec!["editors".to_string()]);
    assert_eq!(
        allowed(&f, &c, "s3:PutObject", "arn:aws:s3:::photos/a"),
        Decision::Allow
    );

    // policy update takes effect on next lookup; delete refused while attached
    f.store.update_policy("photo-writer", ALL_S3).await.unwrap();
    let c = f.store.lookup(&k.access_key_id).await.unwrap().unwrap();
    assert_eq!(
        allowed(&f, &c, "s3:DeleteBucket", "arn:aws:s3:::x"),
        Decision::Allow
    );
    assert!(f.store.delete_policy("photo-writer").await.is_err());
    f.store
        .remove_user_from_group("alice", "editors")
        .await
        .unwrap();
    let c = f.store.lookup(&k.access_key_id).await.unwrap().unwrap();
    assert_eq!(
        allowed(&f, &c, "s3:PutObject", "arn:aws:s3:::photos/a"),
        Decision::Implicit
    );

    // direct attachment, then group deletion cleans membership
    f.store
        .attach_user_policy("alice", "photo-writer")
        .await
        .unwrap();
    f.store.add_user_to_group("alice", "editors").await.unwrap();
    f.store.delete_group("editors").await.unwrap();
    assert!(f.store.get_user("alice").await.unwrap().groups.is_empty());
    f.store
        .detach_user_policy("alice", "photo-writer")
        .await
        .unwrap();
    f.store.delete_policy("photo-writer").await.unwrap();
    assert_eq!(f.store.list_policies().await.unwrap().len(), 0);
    f.store.delete_user_policy("alice", "read").await.unwrap();
    assert!(f.store.delete_user_policy("alice", "read").await.is_err());

    // disable
    f.store.set_user_disabled("alice", true).await.unwrap();
    assert!(f.store.lookup(&k.access_key_id).await.unwrap().is_none());
    f.store.set_user_disabled("alice", false).await.unwrap();
    assert!(f.store.lookup(&k.access_key_id).await.unwrap().is_some());

    // delete user removes keys
    f.store.delete_user("alice").await.unwrap();
    assert!(f.store.lookup(&k.access_key_id).await.unwrap().is_none());
    assert!(f.store.list_access_keys(None).await.unwrap().is_empty());
    assert!(f.store.list_users().await.unwrap().is_empty());
}

#[tokio::test]
async fn access_key_lifecycle() {
    let f = fx().store.with_max_keys_per_user(2);
    let clock = Arc::new(ManualClock::new(1_794_000_000));
    let f = Fx {
        store: f.with_clock(clock.clone()),
        backend: Arc::new(MemoryBackend::new()),
        clock,
    };
    f.store.create_user("bob").await.unwrap();
    let exp = f.store.now().plus(Duration::from_secs(3600));
    let k1 = f
        .store
        .create_access_key(
            "bob",
            AccessKeyOptions {
                expires_at: Some(exp),
                allowed_source_cidrs: vec!["10.0.0.0/8".into()],
            },
        )
        .await
        .unwrap();
    let k2 = f
        .store
        .create_access_key("bob", AccessKeyOptions::default())
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .create_access_key("bob", AccessKeyOptions::default())
            .await,
        Err(AuthError::LimitExceeded(_))
    ));
    assert!(
        f.store
            .create_access_key("nobody", AccessKeyOptions::default())
            .await
            .is_err()
    );
    assert!(
        f.store
            .create_access_key(
                "bob",
                AccessKeyOptions {
                    expires_at: None,
                    allowed_source_cidrs: vec!["nope".into()]
                }
            )
            .await
            .is_err()
    );
    let keys = f.store.list_access_keys(Some("bob")).await.unwrap();
    assert_eq!(keys.len(), 2);

    // cidr restriction travels with the credential
    let c = f.store.lookup(&k1.access_key_id).await.unwrap().unwrap();
    assert_eq!(c.principal.allowed_source_cidrs.len(), 1);
    assert_eq!(c.expires_at, Some(exp));
    let e = AuthzEngine::with_clock(f.clock.clone());
    let ctx = ConditionContext::new().with("aws:SourceIp", "8.8.8.8");
    assert_eq!(
        e.authorize(Some(&c.principal), "s3:GetObject", "*", &ctx, None),
        Decision::Deny
    );

    // expiry
    f.clock.advance(Duration::from_secs(3600));
    assert!(f.store.lookup(&k1.access_key_id).await.unwrap().is_none());
    assert!(f.store.lookup(&k2.access_key_id).await.unwrap().is_some());

    // deactivate / revoke
    f.store
        .set_access_key_active(&k2.access_key_id, false)
        .await
        .unwrap();
    assert!(f.store.lookup(&k2.access_key_id).await.unwrap().is_none());
    f.store
        .set_access_key_active(&k2.access_key_id, true)
        .await
        .unwrap();
    assert!(f.store.lookup(&k2.access_key_id).await.unwrap().is_some());
    f.store.revoke_access_key(&k2.access_key_id).await.unwrap();
    assert!(f.store.lookup(&k2.access_key_id).await.unwrap().is_none());
    assert!(f.store.revoke_access_key(&k2.access_key_id).await.is_err());
}

#[tokio::test]
async fn akia_import_for_migration() {
    let f = fx();
    f.store.create_user("legacy").await.unwrap();
    let sk = SecretString::new("legacy-secret-0123456789");
    f.store
        .import_access_key(
            "legacy",
            "AKIAIOSFODNN7EXAMPLE",
            &sk,
            AccessKeyOptions::default(),
        )
        .await
        .unwrap();
    let c = f
        .store
        .lookup("AKIAIOSFODNN7EXAMPLE")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.secret_key, sk);
    assert!(
        f.store
            .import_access_key(
                "legacy",
                "AKIAIOSFODNN7EXAMPLE",
                &sk,
                AccessKeyOptions::default()
            )
            .await
            .is_err()
    );
    assert!(
        f.store
            .import_access_key("legacy", "bad id!", &sk, AccessKeyOptions::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn assume_role_happy_path_and_intersection() {
    let f = fx();
    f.store.create_user("alice").await.unwrap();
    let k = f
        .store
        .create_access_key("alice", AccessKeyOptions::default())
        .await
        .unwrap();
    let r = f.store.create_role("app", TRUST_ALICE, None).await.unwrap();
    assert!(r.role_id.starts_with("AROA"));
    f.store.put_role_policy("app", "all", ALL_S3).await.unwrap();
    let alice = f
        .store
        .lookup(&k.access_key_id)
        .await
        .unwrap()
        .unwrap()
        .principal;
    let ctx = ConditionContext::new();
    let sess_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let creds = f
        .store
        .assume_role(
            &alice,
            AssumeRoleRequest {
                role: "arn:aws:iam::000000000000:role/app",
                session_name: "job-1",
                duration: Duration::from_secs(900),
                session_policy: Some(sess_policy),
                context: &ctx,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        creds.assumed_role_arn.as_deref(),
        Some("arn:aws:sts::000000000000:assumed-role/app/job-1")
    );
    assert_eq!(creds.assumed_role_id, Some(format!("{}:job-1", r.role_id)));
    assert!(creds.session_token.expose().len() >= 43);
    assert_eq!(
        creds.expiration,
        f.store.now().plus(Duration::from_secs(900))
    );

    let c = f.store.lookup(&creds.access_key_id).await.unwrap().unwrap();
    assert_eq!(c.secret_key, creds.secret_access_key);
    assert!(c.verify_session_token(Some(creds.session_token.expose())));
    assert!(!c.verify_session_token(Some("forged")));
    assert!(!c.verify_session_token(None));
    assert_eq!(
        c.principal.arn,
        "arn:aws:sts::000000000000:assumed-role/app/job-1"
    );
    assert_eq!(
        allowed(&f, &c, "s3:GetObject", "arn:aws:s3:::b/k"),
        Decision::Allow
    );
    assert_eq!(
        allowed(&f, &c, "s3:PutObject", "arn:aws:s3:::b/k"),
        Decision::Implicit
    );

    // expiry and purge
    f.clock.advance(Duration::from_secs(901));
    assert!(
        f.store
            .lookup(&creds.access_key_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(f.store.session_count().await.unwrap(), 1);
    assert_eq!(f.store.purge_expired_sessions().await.unwrap(), 1);
    assert_eq!(f.store.session_count().await.unwrap(), 0);
}

#[tokio::test]
async fn assume_role_denials_and_limits() {
    let f = fx();
    f.store.create_user("alice").await.unwrap();
    f.store.create_user("bob").await.unwrap();
    let ka = f
        .store
        .create_access_key("alice", AccessKeyOptions::default())
        .await
        .unwrap();
    let kb = f
        .store
        .create_access_key("bob", AccessKeyOptions::default())
        .await
        .unwrap();
    f.store
        .create_role("app", TRUST_ALICE, Some(Duration::from_secs(7200)))
        .await
        .unwrap();
    f.store
        .create_role("acct", TRUST_ACCOUNT, None)
        .await
        .unwrap();
    assert!(
        f.store.create_role("bad", READ_PHOTOS, None).await.is_err(),
        "trust policy without Principal"
    );
    assert!(
        f.store
            .create_role("short", TRUST_ALICE, Some(Duration::from_secs(60)))
            .await
            .is_err()
    );
    let alice = f
        .store
        .lookup(&ka.access_key_id)
        .await
        .unwrap()
        .unwrap()
        .principal;
    let bob = f
        .store
        .lookup(&kb.access_key_id)
        .await
        .unwrap()
        .unwrap()
        .principal;
    let ctx = ConditionContext::new();
    let req = |role: &'static str, secs: u64| AssumeRoleRequest {
        role,
        session_name: "s1",
        duration: Duration::from_secs(secs),
        session_policy: None,
        context: &ctx,
    };
    assert!(matches!(
        f.store.assume_role(&bob, req("app", 900)).await,
        Err(AuthError::AccessDenied(_))
    ));
    assert!(matches!(
        f.store.assume_role(&alice, req("missing", 900)).await,
        Err(AuthError::NotFound { .. })
    ));
    assert!(matches!(
        f.store.assume_role(&alice, req("app", 899)).await,
        Err(AuthError::Invalid(_))
    ));
    assert!(matches!(
        f.store.assume_role(&alice, req("app", 7201)).await,
        Err(AuthError::Invalid(_))
    ));
    f.store.assume_role(&alice, req("app", 7200)).await.unwrap();
    // account-principal trust needs an identity grant too
    assert!(matches!(
        f.store.assume_role(&bob, req("acct", 900)).await,
        Err(AuthError::AccessDenied(_))
    ));
    f.store
        .put_user_policy("bob", "assume", ALLOW_ASSUME)
        .await
        .unwrap();
    let bob = f
        .store
        .lookup(&kb.access_key_id)
        .await
        .unwrap()
        .unwrap()
        .principal;
    let s = f.store.assume_role(&bob, req("acct", 43200)).await.unwrap();
    // an identity grant alone is not enough: the trust policy must name the caller
    assert!(matches!(
        f.store.assume_role(&bob, req("app", 900)).await,
        Err(AuthError::AccessDenied(_))
    ));
    assert!(f.store.assume_role(&bob, req("acct", 43201)).await.is_err());
    // role chaining limited to 1h; session can't GetSessionToken
    let sess = f
        .store
        .lookup(&s.access_key_id)
        .await
        .unwrap()
        .unwrap()
        .principal;
    assert!(f.store.assume_role(&sess, req("acct", 3601)).await.is_err());
    // (session has no identity policy granting sts:AssumeRole, so even 1h is denied)
    assert!(matches!(
        f.store.assume_role(&sess, req("acct", 3600)).await,
        Err(AuthError::AccessDenied(_))
    ));
    assert!(matches!(
        f.store
            .get_session_token(&sess, Duration::from_secs(900))
            .await,
        Err(AuthError::AccessDenied(_))
    ));
    // bad session name / bad session policy
    let mut r = req("app", 900);
    r.session_name = "x";
    assert!(f.store.assume_role(&alice, r).await.is_err());
    let mut r = req("app", 900);
    r.session_policy =
        Some(r#"{"Statement":[{"Effect":"Allow","Action":"s3:Nope","Resource":"*"}]}"#);
    assert!(matches!(
        f.store.assume_role(&alice, r).await,
        Err(AuthError::Policy(_))
    ));
    // root may assume anything
    f.store
        .assume_role(&crate::principal::Principal::root(), req("app", 900))
        .await
        .unwrap();
    // deleting the role kills its sessions
    f.store.delete_role("acct").await.unwrap();
    assert!(f.store.lookup(&s.access_key_id).await.unwrap().is_none());
    // trust policy update
    f.store
        .update_assume_role_policy("app", &TRUST_ALICE.replace("alice", "bob"))
        .await
        .unwrap();
    assert!(f.store.assume_role(&alice, req("app", 900)).await.is_err());
    assert!(f.store.assume_role(&bob, req("app", 900)).await.is_ok());
    assert_eq!(f.store.list_roles().await.unwrap().len(), 1);
}

#[tokio::test]
async fn get_session_token_inherits_user() {
    let f = fx();
    f.store.create_user("alice").await.unwrap();
    f.store
        .put_user_policy("alice", "read", READ_PHOTOS)
        .await
        .unwrap();
    let k = f
        .store
        .create_access_key(
            "alice",
            AccessKeyOptions {
                expires_at: None,
                allowed_source_cidrs: vec!["10.0.0.0/8".into()],
            },
        )
        .await
        .unwrap();
    let alice = f
        .store
        .lookup(&k.access_key_id)
        .await
        .unwrap()
        .unwrap()
        .principal;
    assert!(
        f.store
            .get_session_token(&alice, Duration::from_secs(60))
            .await
            .is_err()
    );
    assert!(
        f.store
            .get_session_token(&alice, MAX_SESSION + Duration::from_secs(1))
            .await
            .is_err()
    );
    let s = f
        .store
        .get_session_token(&alice, Duration::from_secs(3600))
        .await
        .unwrap();
    assert!(s.assumed_role_arn.is_none());
    let c = f.store.lookup(&s.access_key_id).await.unwrap().unwrap();
    assert_eq!(c.principal.username(), Some("alice"));
    assert_eq!(c.principal.allowed_source_cidrs.len(), 1);
    let ctx = ConditionContext::new().with("aws:SourceIp", "10.9.9.9");
    let e = engine(&f);
    assert_eq!(
        e.authorize(
            Some(&c.principal),
            "s3:GetObject",
            "arn:aws:s3:::photos/a",
            &ctx,
            None
        ),
        Decision::Allow
    );
    // user deletion invalidates sessions
    f.store.delete_user("alice").await.unwrap();
    assert!(f.store.lookup(&s.access_key_id).await.unwrap().is_none());
    // root session
    let rs = f
        .store
        .get_session_token(&crate::principal::Principal::root(), MIN_SESSION)
        .await
        .unwrap();
    assert!(
        f.store
            .lookup(&rs.access_key_id)
            .await
            .unwrap()
            .unwrap()
            .principal
            .is_root
    );
}

#[test]
fn records_are_versioned() {
    let rec = records::PolicyRecord {
        name: "p".into(),
        document: "{}".into(),
        created_at: Ts(1),
        updated_at: Ts(2),
        version: 3,
    };
    let b = records::encode(&rec).unwrap();
    assert_eq!(b[0], records::SCHEMA_V1);
    assert_eq!(records::decode::<records::PolicyRecord>(&b).unwrap(), rec);
    let mut bad = b.clone();
    bad[0] = 99;
    assert!(records::decode::<records::PolicyRecord>(&bad).is_err());
    assert!(records::decode::<records::PolicyRecord>(&[]).is_err());
}
