//! IAM wildcard patterns (`*`, `?`) with policy variables (`${aws:username}`), compiled to
//! `globset` automata when static.

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// Normalise a condition/variable key: the namespace part before the first `/` is
/// case-insensitive (lower-cased); any suffix such as a tag key keeps its case.
pub fn normalize_key(k: &str) -> String {
    match k.split_once('/') {
        Some((a, b)) => format!("{}/{}", a.to_ascii_lowercase(), b),
        None => k.to_ascii_lowercase(),
    }
}

/// Resolves a policy variable (lower-cased key) to its value.
pub trait VarResolver {
    /// Value of `key`, if present and single-valued.
    fn var(&self, key: &str) -> Option<String>;
}

impl<F: Fn(&str) -> Option<String>> VarResolver for F {
    fn var(&self, key: &str) -> Option<String> {
        self(key)
    }
}

/// Resolver that knows no variables.
pub(crate) struct NoVars;
impl VarResolver for NoVars {
    fn var(&self, _: &str) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Lit(String),
    Star,
    Qm,
    Var { key: String, default: Option<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Ch(char),
    Star,
    Qm,
}

/// A parsed pattern.
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    parts: Vec<Part>,
    has_vars: bool,
    has_wild: bool,
    has_qm: bool,
}

impl Pattern {
    /// Parse `s`; `wildcards` enables `*`/`?`, `vars` enables `${...}` substitution.
    pub(crate) fn parse(s: &str, wildcards: bool, vars: bool) -> Self {
        let mut parts: Vec<Part> = Vec::new();
        let mut lit = String::new();
        let mut rest = s;
        let flush = |lit: &mut String, parts: &mut Vec<Part>| {
            if !lit.is_empty() {
                parts.push(Part::Lit(std::mem::take(lit)));
            }
        };
        while let Some(c) = rest.chars().next() {
            if vars && rest.starts_with("${") {
                if let Some(end) = rest.find('}') {
                    let inner = &rest[2..end];
                    rest = &rest[end + 1..];
                    match inner {
                        "*" | "?" | "$" => lit.push_str(inner),
                        _ => {
                            flush(&mut lit, &mut parts);
                            let (key, default) = match inner.split_once(',') {
                                Some((k, d)) => {
                                    let d = d.trim();
                                    let d = d
                                        .strip_prefix('\'')
                                        .and_then(|d| d.strip_suffix('\''))
                                        .unwrap_or(d);
                                    (k.trim(), Some(d.to_string()))
                                }
                                None => (inner.trim(), None),
                            };
                            parts.push(Part::Var { key: normalize_key(key), default });
                        }
                    }
                    continue;
                }
            }
            rest = &rest[c.len_utf8()..];
            match c {
                '*' if wildcards => {
                    flush(&mut lit, &mut parts);
                    if parts.last() != Some(&Part::Star) {
                        parts.push(Part::Star);
                    }
                }
                '?' if wildcards => {
                    flush(&mut lit, &mut parts);
                    parts.push(Part::Qm);
                }
                _ => lit.push(c),
            }
        }
        flush(&mut lit, &mut parts);
        let has_vars = parts.iter().any(|p| matches!(p, Part::Var { .. }));
        let has_qm = parts.iter().any(|p| matches!(p, Part::Qm));
        let has_wild = has_qm || parts.iter().any(|p| matches!(p, Part::Star));
        Pattern { parts, has_vars, has_wild, has_qm }
    }

    /// Glob source for globset, if this pattern can be compiled statically.
    fn static_glob(&self) -> Option<String> {
        if self.has_vars || self.has_qm {
            return None;
        }
        let mut g = String::new();
        for p in &self.parts {
            match p {
                Part::Lit(s) => g.push_str(&globset::escape(s)),
                Part::Star => g.push('*'),
                _ => return None,
            }
        }
        Some(g)
    }

    fn resolve(&self, vars: &dyn VarResolver) -> Option<Vec<Tok>> {
        let mut out = Vec::new();
        for p in &self.parts {
            match p {
                Part::Lit(s) => out.extend(s.chars().map(Tok::Ch)),
                Part::Star => out.push(Tok::Star),
                Part::Qm => out.push(Tok::Qm),
                Part::Var { key, default } => {
                    let v = vars.var(key).or_else(|| default.clone())?;
                    out.extend(v.chars().map(Tok::Ch));
                }
            }
        }
        Some(out)
    }

    /// Match `cand` (variables substituted literally). Missing variable → no match.
    pub(crate) fn matches(&self, cand: &str, vars: &dyn VarResolver, ignore_case: bool) -> bool {
        let Some(toks) = self.resolve(vars) else {
            return false;
        };
        if !self.has_wild {
            let lit: String = toks
                .iter()
                .map(|t| if let Tok::Ch(c) = t { *c } else { unreachable!() })
                .collect();
            return if ignore_case { lit.to_lowercase() == cand.to_lowercase() } else { lit == cand };
        }
        if ignore_case {
            let toks: Vec<Tok> = toks
                .into_iter()
                .flat_map(|t| match t {
                    Tok::Ch(c) => c.to_lowercase().map(Tok::Ch).collect::<Vec<_>>(),
                    t => vec![t],
                })
                .collect();
            let cand: Vec<char> = cand.to_lowercase().chars().collect();
            wild_match(&toks, &cand)
        } else {
            let cand: Vec<char> = cand.chars().collect();
            wild_match(&toks, &cand)
        }
    }
}

/// Iterative wildcard match with single-star backtracking (O(n·m) worst case).
fn wild_match(p: &[Tok], s: &[char]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        match p.get(pi) {
            Some(Tok::Star) => {
                star = Some((pi, si));
                pi += 1;
            }
            Some(Tok::Qm) => {
                pi += 1;
                si += 1;
            }
            Some(Tok::Ch(c)) if *c == s[si] => {
                pi += 1;
                si += 1;
            }
            _ => match star {
                Some((sp, ss)) => {
                    pi = sp + 1;
                    si = ss + 1;
                    star = Some((sp, ss + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|t| *t == Tok::Star)
}

/// A compiled set of patterns: static ones in one `GlobSet`, variable/`?` ones matched lazily.
#[derive(Debug, Clone)]
pub(crate) struct PatternSet {
    any: bool,
    set: GlobSet,
    dynamic: Vec<Pattern>,
    ignore_case: bool,
}

impl PatternSet {
    /// Compile patterns. `ignore_case` is used for actions. `vars` enables policy variables.
    pub(crate) fn compile<'a>(
        pats: impl IntoIterator<Item = &'a str>,
        ignore_case: bool,
        vars: bool,
    ) -> Result<Self, String> {
        let mut b = GlobSetBuilder::new();
        let mut dynamic = Vec::new();
        let mut any = false;
        for raw in pats {
            if raw == "*" {
                any = true;
                continue;
            }
            let p = Pattern::parse(raw, true, vars);
            match p.static_glob() {
                Some(g) => {
                    let glob = GlobBuilder::new(&g)
                        .literal_separator(false)
                        .backslash_escape(false)
                        .case_insensitive(ignore_case)
                        .build()
                        .map_err(|e| format!("{raw}: {e}"))?;
                    b.add(glob);
                }
                None => dynamic.push(p),
            }
        }
        Ok(PatternSet {
            any,
            set: b.build().map_err(|e| e.to_string())?,
            dynamic,
            ignore_case,
        })
    }

    /// True if any pattern matches `cand`.
    pub(crate) fn is_match(&self, cand: &str, vars: &dyn VarResolver) -> bool {
        self.any
            || (!self.set.is_empty() && self.set.is_match(cand))
            || self.dynamic.iter().any(|p| p.matches(cand, vars, self.ignore_case))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, s: &str) -> bool {
        let set = PatternSet::compile([p], false, true).unwrap();
        let vars = |k: &str| (k == "aws:username").then(|| "alice".to_string());
        set.is_match(s, &vars)
    }

    #[test]
    fn wildcards() {
        assert!(m("arn:aws:s3:::b/*", "arn:aws:s3:::b/x/y/z"));
        assert!(m("arn:aws:s3:::b/*", "arn:aws:s3:::b/"));
        assert!(!m("arn:aws:s3:::b/*", "arn:aws:s3:::b"));
        assert!(m("arn:aws:s3:::b?", "arn:aws:s3:::bx"));
        assert!(!m("arn:aws:s3:::b?", "arn:aws:s3:::b"));
        assert!(m("a?c", "aéc"));
        assert!(m("a**/x", "a/x"));
        assert!(m("**/x", "/x"));
        assert!(!m("**/x", "x"));
        assert!(m("a*b*c", "aXXbYYc"));
        assert!(!m("a*b*c", "aXXbYY"));
        assert!(m("a*", "a\nb"));
        assert!(m("x[1]{2}\\", "x[1]{2}\\"));
        assert!(!m("x[1]", "x1"));
        assert!(m("*", ""));
    }

    #[test]
    fn variables() {
        assert!(m("arn:aws:s3:::home/${aws:username}/*", "arn:aws:s3:::home/alice/f"));
        assert!(!m("arn:aws:s3:::home/${aws:username}/*", "arn:aws:s3:::home/bob/f"));
        assert!(!m("home/${aws:userid}/*", "home/x/f"));
        assert!(m("home/${aws:userid, 'anon'}/*", "home/anon/f"));
        assert!(m("lit${*}x", "lit*x"));
        assert!(!m("lit${*}x", "litAx"));
        let vars = |_: &str| Some("a*".to_string());
        let p = Pattern::parse("${k}", true, true);
        assert!(p.matches("a*", &vars, false));
        assert!(!p.matches("ab", &vars, false));
    }

    #[test]
    fn case_insensitive_actions() {
        let set = PatternSet::compile(["s3:Get*", "s3:Put?bject"], true, false).unwrap();
        assert!(set.is_match("s3:getobject", &NoVars));
        assert!(set.is_match("S3:PUTOBJECT", &NoVars));
        assert!(!set.is_match("s3:DeleteObject", &NoVars));
    }
}
