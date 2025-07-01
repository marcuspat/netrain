use once_cell::sync::Lazy;
use std::collections::HashMap;

// Character sets copied from matrix_rain module
const ASCII_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()[]{}|\\/<>?+=~`";
const KATAKANA_CHARS: &str = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ";
const SYMBOLS_CHARS: &str = "☆★○●◎◇◆□■△▲▽▼※〒→←↑↓〓∈∋⊆⊇⊂⊃∪∩∧∨¬⇒⇔∀∃∠⊥⌒∂∇≡≒≪≫√∽∝∵∫∬";
const BINARY_CHARS: &str = "01";
const HEX_CHARS: &str = "0123456789ABCDEF";

// Lookup tables for character sets to avoid repeated string parsing
static ASCII_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| {
    ASCII_CHARS.chars().collect()
});

static KATAKANA_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| {
    KATAKANA_CHARS.chars().collect()
});

static SYMBOLS_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| {
    SYMBOLS_CHARS.chars().collect()
});

static BINARY_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| {
    BINARY_CHARS.chars().collect()
});

static HEX_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| {
    HEX_CHARS.chars().collect()
});

static MIXED_CHARS_VEC: Lazy<Vec<char>> = Lazy::new(|| {
    let all_chars = format!("{}{}{}{}", ASCII_CHARS, KATAKANA_CHARS, SYMBOLS_CHARS, BINARY_CHARS);
    all_chars.chars().collect()
});

// Optimized random character generation using lookup tables
#[inline]
pub fn random_matrix_char_optimized(rng: &mut impl rand::Rng, char_set: super::matrix_rain::CharacterSet) -> char {
    use super::matrix_rain::CharacterSet;
    
    let chars = match char_set {
        CharacterSet::ASCII => &*ASCII_CHARS_VEC,
        CharacterSet::Katakana => &*KATAKANA_CHARS_VEC,
        CharacterSet::Symbols => &*SYMBOLS_CHARS_VEC,
        CharacterSet::Binary => &*BINARY_CHARS_VEC,
        CharacterSet::Hex => &*HEX_CHARS_VEC,
        CharacterSet::Mixed => &*MIXED_CHARS_VEC,
    };
    
    if chars.is_empty() {
        '?'
    } else {
        unsafe {
            // Safe because we check is_empty above
            *chars.get_unchecked(rng.gen_range(0..chars.len()))
        }
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
            src_ip: format!("{}.{}.{}.{}", self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]),
            dst_ip: format!("{}.{}.{}.{}", self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]),
        }
    }
}

// Ultra-fast zero-allocation packet parsing
#[inline(always)]
pub fn parse_packet_zero_alloc(data: &[u8]) -> Result<PacketRef, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("Empty packet data".into());
    }
    
    let (src_ip, dst_ip) = if data.len() >= 20 && (data[0] >> 4) == 4 {
        // IPv4 packet - IPs are at bytes 12-15 (source) and 16-19 (destination)
        ([data[12], data[13], data[14], data[15]], [data[16], data[17], data[18], data[19]])
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

// Optimized packet parsing with zero allocations for IP addresses
#[inline]
pub fn parse_packet_optimized(data: &[u8]) -> Result<super::Packet, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("Empty packet data".into());
    }
    
    // Parse IP addresses - handle both raw IP and Ethernet frames
    let (src_ip, dst_ip) = if data.len() >= 20 && (data[0] >> 4) == 4 {
        // Raw IPv4 packet - IPs are at bytes 12-15 (source) and 16-19 (destination)
        let src = format_ipv4_inline(&data[12..16]);
        let dst = format_ipv4_inline(&data[16..20]);
        (src, dst)
    } else if data.len() >= 34 && data.len() > 14 {
        // Ethernet frame - check if it contains IPv4 (EtherType 0x0800)
        if data[12] == 0x08 && data[13] == 0x00 {
            // IPv4 in Ethernet frame - skip 14-byte Ethernet header
            if data[14] >> 4 == 4 {
                let src = format_ipv4_inline(&data[26..30]);
                let dst = format_ipv4_inline(&data[30..34]);
                (src, dst)
            } else {
                ("0.0.0.0".to_string(), "0.0.0.0".to_string())
            }
        } else {
            ("0.0.0.0".to_string(), "0.0.0.0".to_string())
        }
    } else {
        ("0.0.0.0".to_string(), "0.0.0.0".to_string())
    };
    
    Ok(super::Packet {
        data: data.to_vec(),
        length: data.len(),  // Use actual packet length
        timestamp: 0,
        src_ip,
        dst_ip,
    })
}

// Most optimized version - reuse Vec allocation
#[inline(always)]
pub fn parse_packet_ultra_optimized(data: &[u8], reuse_vec: &mut Vec<u8>) -> Result<super::Packet, Box<dyn std::error::Error>> {
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
        let _ = write!(&mut src, "{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
        let _ = write!(&mut dst, "{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
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

// Inline IP formatting to reduce overhead
#[inline(always)]
fn format_ipv4_inline(bytes: &[u8]) -> String {
    if bytes.len() >= 4 {
        // Pre-allocate capacity for "255.255.255.255" (15 chars)
        let mut result = String::with_capacity(15);
        use std::fmt::Write;
        let _ = write!(&mut result, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
        result
    } else {
        "0.0.0.0".to_string()
    }
}

// Protocol classification with early returns and inline hints
#[inline]
pub fn classify_protocol_optimized(packet: &super::Packet) -> super::Protocol {
    use super::Protocol;
    
    if packet.data.is_empty() {
        panic!("Invalid protocol bytes");
    }
    
    let data = &packet.data;
    let len = data.len();
    
    // Fast path for common protocols
    match data.get(0) {
        Some(&b'S') if len >= 4 && &data[0..4] == b"SSH-" => return Protocol::SSH,
        Some(&b'G') if len >= 4 && &data[0..4] == b"GET " => return Protocol::HTTP,
        Some(&b'P') if len >= 5 => {
            if &data[0..5] == b"POST " { return Protocol::HTTP; }
            if &data[0..4] == b"PUT " { return Protocol::HTTP; }
        }
        Some(&b'D') if len >= 7 && &data[0..7] == b"DELETE " => return Protocol::HTTP,
        Some(&b'H') if len >= 5 && &data[0..5] == b"HTTP/" => return Protocol::HTTP,
        Some(&0x16) => return Protocol::HTTPS, // TLS handshake
        _ => {}
    }
    
    // Handle Ethernet frames
    let offset = if len > 14 && data[12] == 0x08 && data[13] == 0x00 {
        14  // Ethernet frame with IPv4
    } else if len > 0 && (data[0] >> 4) == 4 {
        0   // Raw IP packet
    } else {
        return Protocol::Unknown;
    };
    
    // Check if we have enough data after offset
    if len <= offset + 9 {
        return Protocol::Unknown;
    }
    
    // Check IP protocol field (9 bytes into IP header)
    match data.get(offset + 9) {
        Some(&0x06) => {
            // TCP - check ports first for common protocols
            if len > offset + 23 {  // Ensure we have TCP ports
                let src_port = ((data[offset + 20] as u16) << 8) | data[offset + 21] as u16;
                let dst_port = ((data[offset + 22] as u16) << 8) | data[offset + 23] as u16;
                
                // Check for SSH on port 22
                if src_port == 22 || dst_port == 22 {
                    return Protocol::SSH;
                }
                
                // Check for HTTPS on port 443
                if src_port == 443 || dst_port == 443 {
                    return Protocol::HTTPS;
                }
                
                // Check for HTTP on port 80
                if src_port == 80 || dst_port == 80 {
                    return Protocol::HTTP;
                }
                
                // For other ports, check application data
                if len > offset + 40 {  // At least TCP header
                    let tcp_data_start = offset + 20 + ((data[offset + 32] >> 4) * 4) as usize;
                    if tcp_data_start < len {
                        let app_data = &data[tcp_data_start..];
                        // Check for HTTP methods
                        if app_data.starts_with(b"GET ") || app_data.starts_with(b"POST ") ||
                           app_data.starts_with(b"PUT ") || app_data.starts_with(b"DELETE ") ||
                           app_data.starts_with(b"HTTP/") {
                            return Protocol::HTTP;
                        }
                        // Check for SSH banner (initial handshake only)
                        if app_data.starts_with(b"SSH-") {
                            return Protocol::SSH;
                        }
                        // Check for HTTPS (TLS handshake)
                        if app_data.len() > 0 && app_data[0] == 0x16 {
                            return Protocol::HTTPS;
                        }
                    }
                }
            }
            Protocol::TCP
        }
        Some(&0x11) => {
            // UDP - check for DNS on port 53
            if len > offset + 28 {
                let src_port = ((data[offset + 20] as u16) << 8) | data[offset + 21] as u16;
                let dst_port = ((data[offset + 22] as u16) << 8) | data[offset + 23] as u16;
                if src_port == 53 || dst_port == 53 {
                    return Protocol::DNS;
                }
            }
            Protocol::UDP
        }
        _ => Protocol::Unknown,
    }
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
                packet.data[0], packet.data[1], packet.data[2], packet.data[3],
                packet.data[4], packet.data[5], packet.data[6], packet.data[7],
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