//! Condition operators and their evaluation.

use crate::error::PolicyError;
use crate::eval::ConditionContext;
use crate::pattern::{Pattern, VarResolver, normalize_key};
use crate::types::Ts;
use ipnet::IpNet;
use serde_json::Value;
use std::net::IpAddr;

/// Base operator family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// StringEquals.
    StringEquals,
    /// StringNotEquals.
    StringNotEquals,
    /// StringEqualsIgnoreCase.
    StringEqualsIgnoreCase,
    /// StringNotEqualsIgnoreCase.
    StringNotEqualsIgnoreCase,
    /// StringLike.
    StringLike,
    /// StringNotLike.
    StringNotLike,
    /// NumericEquals.
    NumericEquals,
    /// NumericNotEquals.
    NumericNotEquals,
    /// NumericLessThan.
    NumericLessThan,
    /// NumericLessThanEquals.
    NumericLessThanEquals,
    /// NumericGreaterThan.
    NumericGreaterThan,
    /// NumericGreaterThanEquals.
    NumericGreaterThanEquals,
    /// DateEquals.
    DateEquals,
    /// DateNotEquals.
    DateNotEquals,
    /// DateLessThan.
    DateLessThan,
    /// DateLessThanEquals.
    DateLessThanEquals,
    /// DateGreaterThan.
    DateGreaterThan,
    /// DateGreaterThanEquals.
    DateGreaterThanEquals,
    /// Bool.
    Bool,
    /// IpAddress.
    IpAddress,
    /// NotIpAddress.
    NotIpAddress,
    /// ArnEquals.
    ArnEquals,
    /// ArnLike.
    ArnLike,
    /// ArnNotEquals.
    ArnNotEquals,
    /// ArnNotLike.
    ArnNotLike,
    /// Null.
    Null,
}

impl OpKind {
    fn from_name(s: &str) -> Option<Self> {
        use OpKind::*;
        Some(match s {
            "StringEquals" => StringEquals,
            "StringNotEquals" => StringNotEquals,
            "StringEqualsIgnoreCase" => StringEqualsIgnoreCase,
            "StringNotEqualsIgnoreCase" => StringNotEqualsIgnoreCase,
            "StringLike" => StringLike,
            "StringNotLike" => StringNotLike,
            "NumericEquals" => NumericEquals,
            "NumericNotEquals" => NumericNotEquals,
            "NumericLessThan" => NumericLessThan,
            "NumericLessThanEquals" => NumericLessThanEquals,
            "NumericGreaterThan" => NumericGreaterThan,
            "NumericGreaterThanEquals" => NumericGreaterThanEquals,
            "DateEquals" => DateEquals,
            "DateNotEquals" => DateNotEquals,
            "DateLessThan" => DateLessThan,
            "DateLessThanEquals" => DateLessThanEquals,
            "DateGreaterThan" => DateGreaterThan,
            "DateGreaterThanEquals" => DateGreaterThanEquals,
            "Bool" => Bool,
            "IpAddress" => IpAddress,
            "NotIpAddress" => NotIpAddress,
            "ArnEquals" => ArnEquals,
            "ArnLike" => ArnLike,
            "ArnNotEquals" => ArnNotEquals,
            "ArnNotLike" => ArnNotLike,
            "Null" => Null,
            _ => return None,
        })
    }

    /// True for operators whose result is the negation of a positive match.
    pub fn is_negated(self) -> bool {
        use OpKind::*;
        matches!(
            self,
            StringNotEquals
                | StringNotEqualsIgnoreCase
                | StringNotLike
                | NumericNotEquals
                | DateNotEquals
                | NotIpAddress
                | ArnNotEquals
                | ArnNotLike
        )
    }
}

/// Multi-valued key qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetQualifier {
    /// Single-valued semantics.
    None,
    /// `ForAnyValue:`.
    ForAnyValue,
    /// `ForAllValues:`.
    ForAllValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
enum Cmp {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
enum Values {
    Str(Vec<Pattern>),
    Num(Vec<f64>),
    Date(Vec<Ts>),
    Bool(Vec<String>),
    Ip(Vec<IpNet>),
    Arn(Vec<Vec<Pattern>>),
    Null(Vec<bool>),
}

/// One `operator: { key: values }` entry.
#[derive(Debug, Clone)]
pub struct Condition {
    /// Operator family.
    pub op: OpKind,
    /// `ForAnyValue`/`ForAllValues` prefix.
    pub set: SetQualifier,
    /// `...IfExists` suffix.
    pub if_exists: bool,
    /// Normalised context key.
    pub key: String,
    values: Values,
}

fn scalar_strings(v: &Value) -> Result<Vec<String>, String> {
    let one = |v: &Value| -> Result<String, String> {
        match v {
            Value::String(s) => Ok(s.clone()),
            Value::Number(n) => Ok(n.to_string()),
            Value::Bool(b) => Ok(b.to_string()),
            _ => Err("condition values must be strings, numbers or booleans".into()),
        }
    };
    match v {
        Value::Array(a) if a.is_empty() => Err("empty condition value list".into()),
        Value::Array(a) => a.iter().map(one).collect(),
        v => Ok(vec![one(v)?]),
    }
}

/// Parse an IAM date: epoch seconds, RFC 3339, `YYYY-MM-DDTHH:MM:SS` (UTC) or `YYYY-MM-DD`.
pub fn parse_date(s: &str) -> Option<Ts> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(Ts::from_secs(n));
    }
    if let Ok(t) = s.parse::<jiff::Timestamp>() {
        return Some(Ts::from_jiff(t));
    }
    if let Ok(dt) = s.parse::<jiff::civil::DateTime>() {
        return dt.to_zoned(jiff::tz::TimeZone::UTC).ok().map(|z| Ts::from_jiff(z.timestamp()));
    }
    if let Ok(d) = s.parse::<jiff::civil::Date>() {
        return d.to_zoned(jiff::tz::TimeZone::UTC).ok().map(|z| Ts::from_jiff(z.timestamp()));
    }
    None
}

fn parse_net(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
}

fn split_arn(p: &str, vars: bool) -> Vec<Pattern> {
    p.splitn(6, ':').map(|c| Pattern::parse(c, true, vars)).collect()
}

/// Parse a whole `Condition` block.
pub(crate) fn parse_block(v: &Value, vars: bool) -> Result<Vec<Condition>, PolicyError> {
    let bad = |m: String| PolicyError::InvalidCondition(m);
    let obj = v.as_object().ok_or_else(|| bad("Condition must be an object".into()))?;
    let mut out = Vec::new();
    for (opname, body) in obj {
        let (set, rest) = if let Some(r) = opname.strip_prefix("ForAnyValue:") {
            (SetQualifier::ForAnyValue, r)
        } else if let Some(r) = opname.strip_prefix("ForAllValues:") {
            (SetQualifier::ForAllValues, r)
        } else {
            (SetQualifier::None, opname.as_str())
        };
        let (if_exists, base) = match rest.strip_suffix("IfExists") {
            Some(b) => (true, b),
            None => (false, rest),
        };
        let op = OpKind::from_name(base).ok_or_else(|| bad(format!("unknown operator {opname}")))?;
        if op == OpKind::Null && (if_exists || set != SetQualifier::None) {
            return Err(bad(format!("{opname}: Null takes no qualifiers")));
        }
        let body = body
            .as_object()
            .ok_or_else(|| bad(format!("{opname}: expected an object of key -> values")))?;
        if body.is_empty() {
            return Err(bad(format!("{opname}: no keys")));
        }
        for (key, vals) in body {
            if !key.contains(':') || key.starts_with(':') {
                return Err(bad(format!("{key}: condition keys look like ns:name")));
            }
            let raw = scalar_strings(vals).map_err(|e| bad(format!("{key}: {e}")))?;
            let values = build_values(op, &raw, vars).map_err(|e| bad(format!("{opname} {key}: {e}")))?;
            out.push(Condition { op, set, if_exists, key: normalize_key(key), values });
        }
    }
    Ok(out)
}

fn build_values(op: OpKind, raw: &[String], vars: bool) -> Result<Values, String> {
    use OpKind::*;
    Ok(match op {
        StringEquals | StringNotEquals | StringEqualsIgnoreCase | StringNotEqualsIgnoreCase => {
            Values::Str(raw.iter().map(|s| Pattern::parse(s, false, vars)).collect())
        }
        StringLike | StringNotLike => Values::Str(raw.iter().map(|s| Pattern::parse(s, true, vars)).collect()),
        NumericEquals | NumericNotEquals | NumericLessThan | NumericLessThanEquals
        | NumericGreaterThan | NumericGreaterThanEquals => Values::Num(
            raw.iter()
                .map(|s| s.trim().parse::<f64>().map_err(|_| format!("{s} is not a number")))
                .collect::<Result<_, _>>()?,
        ),
        DateEquals | DateNotEquals | DateLessThan | DateLessThanEquals | DateGreaterThan
        | DateGreaterThanEquals => Values::Date(
            raw.iter()
                .map(|s| parse_date(s).ok_or_else(|| format!("{s} is not a date")))
                .collect::<Result<_, _>>()?,
        ),
        Bool => Values::Bool(
            raw.iter()
                .map(|s| {
                    let l = s.to_ascii_lowercase();
                    if l == "true" || l == "false" { Ok(l) } else { Err(format!("{s} is not a boolean")) }
                })
                .collect::<Result<_, _>>()?,
        ),
        IpAddress | NotIpAddress => Values::Ip(
            raw.iter()
                .map(|s| parse_net(s).ok_or_else(|| format!("{s} is not an IP/CIDR")))
                .collect::<Result<_, _>>()?,
        ),
        ArnEquals | ArnLike | ArnNotEquals | ArnNotLike => {
            Values::Arn(raw.iter().map(|s| split_arn(s, vars)).collect())
        }
        Null => Values::Null(
            raw.iter()
                .map(|s| match s.to_ascii_lowercase().as_str() {
                    "true" => Ok(true),
                    "false" => Ok(false),
                    _ => Err(format!("{s} is not a boolean")),
                })
                .collect::<Result<_, _>>()?,
        ),
    })
}

impl Condition {
    pub(crate) fn ip_nets(&self) -> Option<&[IpNet]> {
        match &self.values {
            Values::Ip(n) => Some(n),
            _ => None,
        }
    }

    fn positive(&self, v: &str, vars: &dyn VarResolver) -> bool {
        use OpKind::*;
        let cmp = match self.op {
            NumericEquals | NumericNotEquals | DateEquals | DateNotEquals => Cmp::Eq,
            NumericLessThan | DateLessThan => Cmp::Lt,
            NumericLessThanEquals | DateLessThanEquals => Cmp::Le,
            NumericGreaterThan | DateGreaterThan => Cmp::Gt,
            NumericGreaterThanEquals | DateGreaterThanEquals => Cmp::Ge,
            _ => Cmp::Eq,
        };
        fn ord<T: PartialOrd>(req: T, pol: T, c: Cmp) -> bool {
            match c {
                Cmp::Eq => req == pol,
                Cmp::Lt => req < pol,
                Cmp::Le => req <= pol,
                Cmp::Gt => req > pol,
                Cmp::Ge => req >= pol,
            }
        }
        match &self.values {
            Values::Str(ps) => {
                let ic = matches!(self.op, StringEqualsIgnoreCase | StringNotEqualsIgnoreCase);
                ps.iter().any(|p| p.matches(v, vars, ic))
            }
            Values::Num(ns) => match v.trim().parse::<f64>() {
                Ok(x) => ns.iter().any(|n| ord(x, *n, cmp)),
                Err(_) => false,
            },
            Values::Date(ds) => match parse_date(v) {
                Some(x) => ds.iter().any(|d| ord(x, *d, cmp)),
                None => false,
            },
            Values::Bool(bs) => {
                let l = v.to_ascii_lowercase();
                bs.contains(&l)
            }
            Values::Ip(nets) => match v.trim().parse::<IpAddr>() {
                Ok(ip) => nets.iter().any(|n| n.contains(&ip)),
                Err(_) => false,
            },
            Values::Arn(arns) => {
                let req: Vec<&str> = v.splitn(6, ':').collect();
                if req.len() != 6 || req[0] != "arn" {
                    return false;
                }
                arns.iter().any(|comps| {
                    comps.len() == 6 && comps.iter().zip(&req).all(|(p, r)| p.matches(r, vars, false))
                })
            }
            Values::Null(_) => false,
        }
    }

    /// Evaluate against the request context.
    pub fn evaluate(&self, ctx: &ConditionContext, vars: &dyn VarResolver) -> bool {
        let req = ctx.get(&self.key).filter(|v| !v.is_empty());
        if let Values::Null(bs) = &self.values {
            let missing = req.is_none();
            return bs.contains(&missing);
        }
        let negated = self.op.is_negated();
        let Some(req) = req else {
            if self.if_exists {
                return true;
            }
            return match self.set {
                SetQualifier::ForAllValues => true,
                SetQualifier::ForAnyValue => false,
                SetQualifier::None => negated,
            };
        };
        let pred = |v: &String| self.positive(v, vars) != negated;
        match self.set {
            SetQualifier::None if negated => req.iter().all(pred),
            SetQualifier::None | SetQualifier::ForAnyValue => req.iter().any(pred),
            SetQualifier::ForAllValues => req.iter().all(pred),
        }
    }
}
