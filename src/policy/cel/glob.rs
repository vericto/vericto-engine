// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `glob(s, pattern)` and the table globs of `applies_to` and
//! `stmt.reads()`: `*` matches any run of characters (dots included), `?`
//! any one character, everything else itself. Linear in the input times the
//! pattern (no backtracking explosion): the classic two-pointer algorithm.

pub(crate) fn glob(s: &str, pattern: &str) -> bool {
    let s: Vec<char> = s.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while i < s.len() {
        if j < p.len() && (p[j] == '?' || p[j] == s[i]) {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == '*' {
            star = Some(j);
            mark = i;
            j += 1;
        } else if let Some(st) = star {
            j = st + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while j < p.len() && p[j] == '*' {
        j += 1;
    }
    j == p.len()
}

/// Whether an IPv4 or IPv6 address is inside a CIDR (`10.20.0.0/16`,
/// `2001:db8::/32`). `None` when either does not parse.
pub(crate) fn cidr_contains(cidr: &str, ip: &str) -> Option<bool> {
    use std::net::IpAddr;
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n, Some(b.parse::<u32>().ok()?)),
        None => (cidr, None),
    };
    let net: IpAddr = net.trim().parse().ok()?;
    let ip: IpAddr = ip.trim().parse().ok()?;
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let bits = bits.unwrap_or(32);
            if bits > 32 {
                return None;
            }
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            Some(u32::from(n) & mask == u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let bits = bits.unwrap_or(128);
            if bits > 128 {
                return None;
            }
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            Some(u128::from(n) & mask == u128::from(a) & mask)
        }
        // An IPv4-mapped IPv6 address against an IPv4 network.
        (IpAddr::V4(_), IpAddr::V6(a)) => match a.to_ipv4_mapped() {
            Some(v4) => cidr_contains(cidr, &v4.to_string()),
            None => Some(false),
        },
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("public.ledger_2026", "public.ledger*"));
        assert!(glob("public.ledger", "public.ledger*"));
        assert!(!glob("reporting.ledger", "public.ledger*"));
        assert!(glob("a.b.c", "*.c"));
        assert!(glob("abc", "a?c"));
        assert!(!glob("abc", "a?d"));
        assert!(glob("", "*"));
        assert!(!glob("", "?"));
        assert!(glob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "*a*a*a*a*a*a*b"));
        assert!(!glob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "*a*a*a*a*a*a*b"));
    }

    #[test]
    fn cidrs() {
        assert_eq!(cidr_contains("10.20.0.0/16", "10.20.3.4"), Some(true));
        assert_eq!(cidr_contains("10.20.0.0/16", "10.21.3.4"), Some(false));
        assert_eq!(cidr_contains("0.0.0.0/0", "8.8.8.8"), Some(true));
        assert_eq!(cidr_contains("10.0.0.1", "10.0.0.1"), Some(true));
        assert_eq!(cidr_contains("2001:db8::/32", "2001:db8::1"), Some(true));
        assert_eq!(cidr_contains("10.0.0.0/8", "::ffff:10.1.2.3"), Some(true));
        assert_eq!(cidr_contains("10.0.0.0/33", "10.0.0.1"), None);
        assert_eq!(cidr_contains("nope", "10.0.0.1"), None);
        assert_eq!(cidr_contains("10.0.0.0/8", "2001:db8::1"), Some(false));
    }
}
