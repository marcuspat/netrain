//! Minimal DNS message parsing: the name in the first question.

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

    proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Some(name) = question_name(&data) {
                prop_assert!(name.len() <= MAX_NAME_LEN);
                prop_assert!(name.bytes().all(|b| b.is_ascii_graphic()));
            }
        }
    }
}
