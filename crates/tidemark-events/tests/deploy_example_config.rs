//! `deploy/tidemark.example.toml` documents every key at its default: it must parse (no stale or
//! unknown keys) and equal `Config::default()`.

#[test]
fn example_config_matches_defaults() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/tidemark.example.toml"
    );
    let src = std::fs::read_to_string(path).unwrap();
    let cfg = tidemark_core::Config::from_toml(&src).unwrap();
    assert_eq!(cfg, tidemark_core::Config::default());
    let commented: String = src
        .lines()
        .map(|l| l.strip_prefix("# ").unwrap_or(l))
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('[') || t.split_once(" = ").is_some_and(|(k, _)| !k.contains(' '))
        })
        .collect::<Vec<_>>()
        .join("\n");
    tidemark_core::Config::from_toml(&commented).expect("commented-out keys are valid too");
}
