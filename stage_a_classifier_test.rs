// Stage A: verbatim reproduction of codex-rs/network-proxy/src/policy.rs
// classifiers at commit c0cc9fc820f62e4dbdde68214dd6d792d6c8a7ee (main).
// The functions below are copied byte-for-byte from the upstream source.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_non_public_ipv4(ip),
        IpAddr::V6(ip) => is_non_public_ipv6(ip),
    }
}

fn is_non_public_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ipv4_in_cidr(ip, [0, 0, 0, 0], /*prefix*/ 8)
        || ipv4_in_cidr(ip, [100, 64, 0, 0], /*prefix*/ 10)
        || ipv4_in_cidr(ip, [192, 0, 0, 0], /*prefix*/ 24)
        || ipv4_in_cidr(ip, [192, 0, 2, 0], /*prefix*/ 24)
        || ipv4_in_cidr(ip, [198, 18, 0, 0], /*prefix*/ 15)
        || ipv4_in_cidr(ip, [198, 51, 100, 0], /*prefix*/ 24)
        || ipv4_in_cidr(ip, [203, 0, 113, 0], /*prefix*/ 24)
        || ipv4_in_cidr(ip, [240, 0, 0, 0], /*prefix*/ 4)
}

fn ipv4_in_cidr(ip: Ipv4Addr, base: [u8; 4], prefix: u8) -> bool {
    let ip = u32::from(ip);
    let base = u32::from(Ipv4Addr::from(base));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (ip & mask) == (base & mask)
}

fn is_non_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4() {
        return is_non_public_ipv4(v4) || ip.is_loopback();
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
}

// ---- Fixed variant: decodes RFC 6052 NAT64 Well-Known Prefix 64:ff9b::/96 ----
fn is_non_public_ipv6_fixed(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4() {
        return is_non_public_ipv4(v4) || ip.is_loopback();
    }
    let o = ip.octets();
    if o[0..12] == [0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0] {
        return is_non_public_ipv4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
}

fn is_non_public_ip_fixed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_non_public_ipv4(ip),
        IpAddr::V6(ip) => is_non_public_ipv6_fixed(ip),
    }
}

fn check(label: &str, ip: &str, vulnerable: bool, fixed: bool) {
    let v = is_non_public_ip(ip.parse::<IpAddr>().unwrap());
    let f = is_non_public_ip_fixed(ip.parse::<IpAddr>().unwrap());
    println!(
        "{:<40} vulnerable={:<5} fixed={:<5}",
        format!("{label} [{ip}]"),
        v, f
    );
    assert_eq!(v, vulnerable, "vulnerable classifier mismatch for {ip}");
    assert_eq!(f, fixed, "fixed classifier mismatch for {ip}");
}

fn main() {
    println!("== Stage A: is_non_public_ip classifier (verbatim functions from policy.rs)");
    println!("== upstream commit c0cc9fc820f62e4dbdde68214dd6d792d6c8a7ee (main)");
    println!();
    // The SSRF primitive: RFC 6052 WKP embedding the private IPv4 10.20.0.10.
    check("NAT64 WKP + private v4", "64:ff9b::a14:a", false, true);
    check("plain private v4", "10.20.0.10", true, true);
    // Legitimate NAT64 to a public address must stay allowed in both variants.
    check("NAT64 WKP + public v4", "64:ff9b::808:808", false, false);
    check("public v4", "8.8.8.8", false, false);
    // Regression guards: everything the original function already caught.
    check("IPv4-mapped private", "::ffff:10.0.0.1", true, true);
    check("IPv4-mapped public", "::ffff:8.8.8.8", false, false);
    check("loopback v6", "::1", true, true);
    check("unique-local", "fc00::1", true, true);
    check("link-local", "fe80::1", true, true);
    println!();
    println!(
        "VERDICT: {}",
        if is_non_public_ip("64:ff9b::a14:a".parse().unwrap()) {
            "NOT VULNERABLE"
        } else {
            "CONFIRMED - 64:ff9b::a14:a (embeds private 10.20.0.10) is classified as PUBLIC"
        }
    );
}
