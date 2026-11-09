//! Every test fixture in the workspace must be committed. An ignore rule (`*.redb`) once
//! dropped `meta-v1.redb` from git during a rename: tests passed locally and failed on CI.

use std::path::Path;
use std::process::Command;

#[test]
fn every_fixture_is_tracked_by_git() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inside = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(&root)
        .output();
    let Ok(inside) = inside else { return };
    if !inside.status.success() {
        return;
    }

    let mut untracked = Vec::new();
    for krate in std::fs::read_dir(root.join("crates")).unwrap() {
        let dir = krate.unwrap().path().join("tests/fixtures");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for f in entries {
            let path = f.unwrap().path();
            let tracked = Command::new("git")
                .args(["ls-files", "--error-unmatch"])
                .arg(&path)
                .current_dir(&root)
                .output()
                .unwrap()
                .status
                .success();
            if !tracked {
                untracked.push(path.display().to_string());
            }
        }
    }
    assert!(
        untracked.is_empty(),
        "fixtures not committed to git (check .gitignore, then `git add`): {untracked:?}"
    );
}
