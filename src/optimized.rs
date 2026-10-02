use once_cell::sync::Lazy;
use std::collections::HashMap;

// Character sets copied from matrix_rain module
const ASCII_CHARS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()[]{}|\\/<>?+=~`";
const KATAKANA_CHARS: &str = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ";
const SYMBOLS_CHARS: &str = "☆★○●◎◇◆□■△▲▽▼※〒→←↑↓〓∈∋⊆⊇⊂⊃∪∩∧∨¬⇒⇔∀∃∠⊥⌒∂∇≡≒≪≫√∽∝∵∫∬";
const BINARY_CHARS: &str = "01";
const HEX_CHARS: &str = "0123456789ABCDEF";

// Lookup tables for character sets to avoid repeated string parsing
static ASCII_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| ASCII_CHARS.chars().collect());

static KATAKANA_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| KATAKANA_CHARS.chars().collect());

static SYMBOLS_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| SYMBOLS_CHARS.chars().collect());

static BINARY_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| BINARY_CHARS.chars().collect());

static HEX_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| HEX_CHARS.chars().collect());

static MIXED_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| {
    let all_chars = format!(
        "{}{}{}{}",
        ASCII_CHARS, KATAKANA_CHARS, SYMBOLS_CHARS, BINARY_CHARS
    );
    all_chars.chars().collect()
});

// Optimized random character generation using lookup tables
#[inline]
pub fn random_matrix_char_optimized(
    rng: &mut impl rand::Rng,
    char_set: super::matrix_rain::CharacterSet,
) -> char {
    use super::matrix_rain::CharacterSet;

    let chars = match char_set {
        CharacterSet::ASCII => &*ASCII_CHARS_VEC,
        CharacterSet::Katakana => &*KATAKANA_CHARS_VEC,
        CharacterSet::Symbols => &*SYMBOLS_CHARS_VEC,
        CharacterSet::Binary => &*BINARY_CHARS_VEC,
        CharacterSet::Hex => &*HEX_CHARS_VEC,
        CharacterSet::Mixed => &*MIXED_CHARS_VEC,
    };

    // Bounds-checked: the check is negligible next to the RNG call, and this
    // crate has no need for `unsafe`.
    match chars.len() {
        0 => '?',
        len => chars[rng.gen_range(0..len)],
    }
}

// Static default IP for zero allocation
static DEFAULT_IP: &str = "0.0.0.0";

// Zero-allocation packet structure that references the original data
pub struct PacketRef<'a> {
    pub data: &'a [u8],
    pub length: usize,
    pub timestamp: u64,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

impl<'a> PacketRef<'a> {
    pub fn to_owned(&self) -> super::Packet {
        super::Packet {
            data: self.data.to_vec(),
            length: self.length,
            timestamp: self.timestamp,
            src_ip: format!(
                "{}.{}.{}.{}",
                self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]
            ),
            dst_ip: format!(
                "{}.{}.{}.{}",
                self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]
            ),
        }
    }
}

// Ultra-fast zero-allocation packet parsing
#[inline(always)]
pub fn parse_packet_zero_alloc(data: &[u8]) -> Result<PacketRef<'_>, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("Empty packet data".into());
    }

    let (src_ip, dst_ip) = if data.len() >= 20 && (data[0] >> 4) == 4 {
        // IPv4 packet - IPs are at bytes 12-15 (source) and 16-19 (destination)
        (
            [data[12], data[13], data[14], data[15]],
            [data[16], data[17], data[18], data[19]],
        )
    } else {
        ([0, 0, 0, 0], [0, 0, 0, 0])
    };

    Ok(PacketRef {
        data,
        length: 60,
        timestamp: 0,
        src_ip,
        dst_ip,
    })
}

/// Kept for API compatibility; identical to [`crate::packet::parse_packet`].
#[inline]
pub fn parse_packet_optimized(data: &[u8]) -> Result<super::Packet, Box<dyn std::error::Error>> {
    crate::packet::parse_packet(data)
}

// Most optimized version - reuse Vec allocation
#[inline(always)]
pub fn parse_packet_ultra_optimized(
    data: &[u8],
    reuse_vec: &mut Vec<u8>,
) -> Result<super::Packet, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("Empty packet data".into());
    }

    // Reuse the provided Vec instead of allocating new one
    reuse_vec.clear();
    reuse_vec.extend_from_slice(data);

    // Use small string optimization for IP addresses
    let (src_ip, dst_ip) = if data.len() >= 20 && (data[0] >> 4) == 4 {
        // Pre-allocate with exact capacity
        let mut src = String::with_capacity(15);
        let mut dst = String::with_capacity(15);
        use std::fmt::Write;
        let _ = write!(
            &mut src,
            "{}.{}.{}.{}",
            data[12], data[13], data[14], data[15]
        );
        let _ = write!(
            &mut dst,
            "{}.{}.{}.{}",
            data[16], data[17], data[18], data[19]
        );
        (src, dst)
    } else {
        (DEFAULT_IP.to_string(), DEFAULT_IP.to_string())
    };

    Ok(super::Packet {
        data: std::mem::take(reuse_vec),
        length: 60,
        timestamp: 0,
        src_ip,
        dst_ip,
    })
}

/// Kept for API compatibility; identical to [`crate::packet::classify_protocol`].
/// Never panics.
#[inline]
pub fn classify_protocol_optimized(packet: &super::Packet) -> super::Protocol {
    crate::classify::classify_bytes(&packet.data)
}

// Object pool for MatrixChar to reduce allocations
pub struct MatrixCharPool {
    pool: Vec<super::matrix_rain::MatrixChar>,
}

impl MatrixCharPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            pool: Vec::with_capacity(capacity),
        }
    }

    #[inline]
    pub fn acquire(&mut self, value: char, y: f32) -> super::matrix_rain::MatrixChar {
        if let Some(mut char) = self.pool.pop() {
            char.value = value;
            char.y = y;
            char.intensity = 1.0;
            char.glitch_timer = 0.0;
            char.color_override = None;
            // Reset trail intensities
            if char.trail_intensity.len() >= 5 {
                char.trail_intensity[0] = 0.9;
                char.trail_intensity[1] = 0.7;
                char.trail_intensity[2] = 0.5;
                char.trail_intensity[3] = 0.3;
                char.trail_intensity[4] = 0.15;
            } else {
                char.trail_intensity = vec![0.9, 0.7, 0.5, 0.3, 0.15];
            }
            char
        } else {
            super::matrix_rain::MatrixChar {
                value,
                intensity: 1.0,
                y,
                trail_intensity: vec![0.9, 0.7, 0.5, 0.3, 0.15],
                color_override: None,
                glitch_timer: 0.0,
            }
        }
    }

    #[inline]
    pub fn release(&mut self, char: super::matrix_rain::MatrixChar) {
        if self.pool.len() < self.pool.capacity() {
            self.pool.push(char);
        }
    }
}

// Protocol classification cache for repeated packets
pub struct ProtocolCache {
    cache: HashMap<u64, super::Protocol>,
    capacity: usize,
}

impl ProtocolCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    #[inline]
    pub fn get_or_classify<F>(&mut self, packet: &super::Packet, classify_fn: F) -> super::Protocol
    where
        F: FnOnce(&super::Packet) -> super::Protocol,
    {
        // Simple hash of first 8 bytes for cache key
        let key = if packet.data.len() >= 8 {
            u64::from_ne_bytes([
                packet.data[0],
                packet.data[1],
                packet.data[2],
                packet.data[3],
                packet.data[4],
                packet.data[5],
                packet.data[6],
                packet.data[7],
            ])
        } else {
            let mut bytes = [0u8; 8];
            for (i, &b) in packet.data.iter().enumerate().take(8) {
                bytes[i] = b;
            }
            u64::from_ne_bytes(bytes)
        };

        if let Some(&protocol) = self.cache.get(&key) {
            return protocol;
        }

        let protocol = classify_fn(packet);

        // Evict random entry if at capacity
        if self.cache.len() >= self.capacity {
            if let Some(&k) = self.cache.keys().next() {
                self.cache.remove(&k);
            }
        }

        self.cache.insert(key, protocol);
        protocol
    }
}
