//! IAM / bucket policy JSON: parsing and evaluating never panic, and an explicit
//! `Deny * on *` in any identity policy always wins, whatever else the policies say.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tidemark_auth::{
    AuthzRequest, ConditionContext, Decision, PolicyDocument, PolicySet, Principal,
};

#[derive(Arbitrary, Debug)]
struct In {
    doc: String,
    action: String,
    resource: String,
    ctx: Vec<(String, String)>,
    as_resource_policy: bool,
}

fuzz_target!(|i: In| {
    let Ok(doc) = PolicyDocument::parse_validated(&i.doc) else {
        let _ = PolicyDocument::parse_validated(&i.doc);
        return;
    };
    let mut ctx = ConditionContext::new();
    for (k, v) in i.ctx.iter().take(8) {
        ctx.insert(k, v.clone());
    }
    let req = AuthzRequest {
        principal: None,
        action: &i.action,
        resource: &i.resource,
        context: &ctx,
    };

    let mut set = PolicySet::default();
    if i.as_resource_policy {
        set.resource = Some(doc.clone());
    } else {
        set.identity.push(doc.clone());
    }
    let _ = set.evaluate(&req);
    let _ = set.resource_match(&req);

    let deny_all = PolicyDocument::parse_validated(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}"#,
    )
    .unwrap();
    // An authenticated user whose own policies include the fuzzed document, and the same
    // document as bucket policy: the Deny-all still wins, for the user and in the session slot.
    let user = Principal::user("fuzz", "AIDFUZZ", vec![doc.clone(), deny_all.clone()]);
    let req = AuthzRequest {
        principal: Some(&user),
        ..req
    };
    let mut set = PolicySet::for_principal(Some(&user), Some(doc.clone()), Default::default());
    assert_eq!(
        set.evaluate(&req),
        Decision::Deny,
        "identity deny must win: {:?}",
        i.doc
    );
    set.identity = vec![doc.clone()];
    set.session = Some(deny_all);
    assert_eq!(
        set.evaluate(&req),
        Decision::Deny,
        "session deny must win: {:?}",
        i.doc
    );
});
