//! Minimal DNS message parsing: the first question, and the addresses a
//! response resolves it to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest legal presentation-format name.
const MAX_NAME_LEN: usize = 253;

/// Extract the first question name from a DNS message (the UDP/TCP payload,
/// starting at the 12-byte DNS header). Returns `None` for anything that is
/// not a well-formed question.
pub fn question_name(msg: &[u8]) -> Option<String> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut name = String::new();
    let mut pos = 12;
    loop {
        let len = usize::from(*msg.get(pos)?);
        pos += 1;
        if len == 0 {
            break;
        }
        // Compression pointers (top bits set) do not occur in the first
        // question, and labels are at most 63 bytes.
        if len > 63 {
            return None;
        }
        let label = msg.get(pos..pos + len)?;
        pos += len;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            // Hostnames on the wire are attacker-controlled: keep only
            // printable ASCII so they are safe to draw in a terminal.
            if !b.is_ascii_graphic() {
                return None;
            }
            name.push(char::from(b.to_ascii_lowercase()));
        }
        if name.len() > MAX_NAME_LEN {
            return None;
        }
    }
    // QTYPE + QCLASS must follow the name.
    msg.get(pos..pos + 4)?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Skip over a (possibly compressed) name, returning the offset after it.
///
/// A name ends at a zero byte or at a compression pointer; the pointer's
/// target is never followed, so a pointer loop cannot hang the parser.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    // A name has at most 127 labels; the bound also guards against garbage.
    for _ in 0..128 {
        let len = usize::from(*msg.get(pos)?);
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            msg.get(pos + 1)?;
            return Some(pos + 2);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
    None
}

/// For a DNS response: the question name and every A/AAAA address in the
/// answer section. The addresses are attributed to the name that was asked
/// for, which is what a person recognises, rather than to the CNAME target.
pub fn answers(msg: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    // Most records worth reading from one message.
    const MAX_RECORDS: usize = 32;

    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return None; // too short, or a query
    }
    let name = question_name(msg)?;
    let qdcount = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    let ancount = usize::from(u16::from_be_bytes([msg[6], msg[7]]));

    let mut pos = 12;
    for _ in 0..qdcount.min(4) {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut addrs = Vec::new();
    for _ in 0..ancount.min(MAX_RECORDS) {
        let Some(after_name) = skip_name(msg, pos) else { break };
        let Some(fixed) = msg.get(after_name..after_name + 10) else { break };
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let Some(rdata) = msg.get(after_name + 10..after_name + 10 + rdlen) else { break };
        match (rtype, rdlen) {
            (1, 4) => addrs.push(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {} // CNAME and friends
        }
        pos = after_name + 10 + rdlen;
    }
    Some((name, addrs))
}

#[cfg(test)]
pub(crate) use crate::synth::dns_query as query;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_real_names() {
        assert_eq!(question_name(&query("example.com")).as_deref(), Some("example.com"));
        assert_eq!(question_name(&query("WWW.Rust-Lang.ORG")).as_deref(), Some("www.rust-lang.org"));
    }

    #[test]
    fn rejects_malformed_messages() {
        assert_eq!(question_name(&[0; 50]), None); // no question
        assert_eq!(question_name(&[0; 5]), None); // truncated header
        let mut m = query("example.com");
        m.truncate(m.len() - 6); // name cut off
        assert_eq!(question_name(&m), None);
        let mut ptr = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        ptr.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // pointer to itself
        assert_eq!(question_name(&ptr), None);
        let mut esc = query("abc");
        esc[13] = 0x1b; // terminal escape inside a label
        assert_eq!(question_name(&esc), None);
    }

    #[test]
    fn answers_with_compression_cname_and_both_families() {
        use crate::synth::dns_response;
        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        let v6: IpAddr = "2606:2800:220:1::1".parse().unwrap();
        let (name, addrs) = answers(&dns_response("example.com", &[v4, v6])).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(addrs, vec![v4, v6]);

        // A CNAME record in front of the address is skipped, not fatal.
        let mut msg = dns_response("www.example.com", &[v4]);
        let a_record = msg.split_off(msg.len() - 16);
        msg[7] = 2; // two answers
        msg.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x10]);
        msg.extend_from_slice(&a_record);
        assert_eq!(answers(&msg).unwrap().1, vec![v4]);

        assert_eq!(answers(&query("example.com")), None, "queries have no answers");
        // Answer count lies about how much data follows: stop cleanly.
        let mut lying = dns_response("example.com", &[v4]);
        lying[7] = 200;
        assert_eq!(answers(&lying).unwrap().1, vec![v4]);
    }

    #[test]
    fn pointer_loops_cannot_hang_the_parser() {
        // Answer whose name is a pointer to itself, and one made of nothing
        // but length bytes.
        let mut msg = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        msg.extend_from_slice(b"\x01a\x00\x00\x01\x00\x01");
        let selfptr = msg.len() as u8;
        msg.extend_from_slice(&[0xc0, selfptr, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(answers(&msg).unwrap().1, vec![IpAddr::from([1, 2, 3, 4])]);
        assert_eq!(skip_name(&[1; 400], 0), None);
    }

    proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = answers(&data);
            if let Some(name) = question_name(&data) {
                prop_assert!(name.len() <= MAX_NAME_LEN);
                prop_assert!(name.bytes().all(|b| b.is_ascii_graphic()));
            }
        }
    }
}
