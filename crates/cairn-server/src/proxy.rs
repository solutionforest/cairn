//! Client address and TLS resolution behind trusted reverse proxies (PRODUCTION-READINESS B6):
//! `X-Forwarded-For` / `X-Forwarded-Proto` are honoured only when the TCP peer is inside one of
//! `server.trusted_proxies`.

use cairn_auth::RequestMeta;
use cairn_core::config::{cidr_contains, parse_cidr};
use http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// Parsed trusted-proxy list.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<(IpAddr, u8)>);

impl TrustedProxies {
    /// Parse CIDRs (invalid entries are rejected by `Config::validate`).
    pub fn new(cidrs: &[String]) -> TrustedProxies {
        TrustedProxies(cidrs.iter().filter_map(|c| parse_cidr(c)).collect())
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|n| cidr_contains(*n, ip))
    }

    /// Request facts for the auth layer: the client IP is the right-most `X-Forwarded-For`
    /// entry that is not itself a trusted proxy; `secure` follows `X-Forwarded-Proto`.
    pub fn resolve(&self, peer: SocketAddr, tls: bool, h: &HeaderMap) -> RequestMeta {
        let peer_ip = peer.ip();
        if !self.trusts(peer_ip) {
            return RequestMeta {
                source_ip: Some(peer_ip),
                secure: tls,
            };
        }
        let chain: Vec<IpAddr> = h
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        let client = chain
            .iter()
            .rev()
            .find(|ip| !self.trusts(**ip))
            .or(chain.first())
            .copied()
            .unwrap_or(peer_ip);
        let secure = match h
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
        {
            Some(p) => p.trim().eq_ignore_ascii_case("https"),
            None => tls,
        };
        RequestMeta {
            source_ip: Some(client),
            secure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_headers_only_from_trusted_peers() {
        let t = TrustedProxies::new(&["10.0.0.0/8".into(), "::1".into()]);
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.1.2.3".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        let m = t.resolve("10.0.0.1:5000".parse().unwrap(), false, &h);
        assert_eq!(m.source_ip, Some("203.0.113.7".parse().unwrap()));
        assert!(m.secure);
        let m = t.resolve("198.51.100.1:5000".parse().unwrap(), false, &h);
        assert_eq!(m.source_ip, Some("198.51.100.1".parse().unwrap()));
        assert!(!m.secure);
        let m = t.resolve("[::1]:1".parse().unwrap(), true, &HeaderMap::new());
        assert_eq!(m.source_ip, Some("::1".parse().unwrap()));
        assert!(m.secure);
    }
}
