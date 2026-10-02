//! Classic pcap file format, read and written in pure Rust.
//!
//! This lets capture files be analysed and test fixtures generated without
//! libpcap. Only the classic format is handled (not pcapng).

use std::fmt;

const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const MAGIC_NANOS: u32 = 0xa1b2_3c4d;

/// Refuse absurd per-packet lengths rather than trusting the file.
const MAX_PACKET: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapError {
    /// Shorter than the 24-byte global header.
    TooShort,
    /// Not a classic pcap file.
    BadMagic(u32),
    /// A record header or body runs past the end of the file.
    TruncatedRecord { index: usize },
    /// A record claims an implausible captured length.
    OversizedRecord { index: usize, len: usize },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "file is too short to be a pcap capture"),
            Self::BadMagic(m) => write!(f, "not a pcap file (magic {m:#010x})"),
            Self::TruncatedRecord { index } => write!(f, "packet {index} is truncated"),
            Self::OversizedRecord { index, len } => write!(f, "packet {index} claims {len} bytes"),
        }
    }
}

impl std::error::Error for PcapError {}

/// One packet record. Borrows from the file buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Capture time in microseconds since the Unix epoch.
    pub ts_micros: i64,
    /// Length of the packet on the wire.
    pub wire_len: usize,
    /// Captured bytes (at most the snap length).
    pub data: &'a [u8],
}

/// Reader over an in-memory pcap file.
#[derive(Debug, Clone)]
pub struct PcapReader<'a> {
    rest: &'a [u8],
    big_endian: bool,
    nanos: bool,
    /// The file's link-layer type (a `DLT_*` / `LINKTYPE_*` value).
    pub link_type: i32,
    index: usize,
    failed: bool,
}

impl<'a> PcapReader<'a> {
    pub fn new(file: &'a [u8]) -> Result<Self, PcapError> {
        if file.len() < 24 {
            return Err(PcapError::TooShort);
        }
        let raw = [file[0], file[1], file[2], file[3]];
        let (le, be) = (u32::from_le_bytes(raw), u32::from_be_bytes(raw));
        let (big_endian, nanos) = match (le, be) {
            (MAGIC_MICROS, _) => (false, false),
            (MAGIC_NANOS, _) => (false, true),
            (_, MAGIC_MICROS) => (true, false),
            (_, MAGIC_NANOS) => (true, true),
            _ => return Err(PcapError::BadMagic(be)),
        };
        let mut reader = Self {
            rest: &file[24..],
            big_endian,
            nanos,
            link_type: 0,
            index: 0,
            failed: false,
        };
        // The upper bits of the link-type word carry FCS flags, not the type.
        reader.link_type = (reader.u32_at(file, 20) & 0x0fff_ffff) as i32;
        Ok(reader)
    }

    fn u32_at(&self, buf: &[u8], at: usize) -> u32 {
        let b = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
        if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }
}

impl<'a> Iterator for PcapReader<'a> {
    type Item = Result<Record<'a>, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        let index = self.index;
        if self.rest.len() < 16 {
            self.failed = true;
            return Some(Err(PcapError::TruncatedRecord { index }));
        }
        let secs = i64::from(self.u32_at(self.rest, 0));
        let frac = i64::from(self.u32_at(self.rest, 4));
        let caplen = self.u32_at(self.rest, 8) as usize;
        let wire_len = self.u32_at(self.rest, 12) as usize;
        if caplen > MAX_PACKET {
            self.failed = true;
            return Some(Err(PcapError::OversizedRecord { index, len: caplen }));
        }
        let Some(data) = self.rest.get(16..16 + caplen) else {
            self.failed = true;
            return Some(Err(PcapError::TruncatedRecord { index }));
        };
        self.rest = &self.rest[16 + caplen..];
        self.index += 1;
        let micros = if self.nanos { frac / 1000 } else { frac };
        Some(Ok(Record {
            ts_micros: secs * 1_000_000 + micros,
            wire_len: wire_len.max(caplen),
            data,
        }))
    }
}

/// Writer producing a little-endian, microsecond-resolution pcap file.
#[derive(Debug, Clone)]
pub struct PcapWriter {
    buf: Vec<u8>,
}

impl PcapWriter {
    /// `link_type` is a `LINKTYPE_*` value; 1 is Ethernet.
    pub fn new(link_type: u32) -> Self {
        let mut buf = Vec::with_capacity(1024);
        buf.extend_from_slice(&MAGIC_MICROS.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&[0; 8]);
        buf.extend_from_slice(&65_535u32.to_le_bytes());
        buf.extend_from_slice(&link_type.to_le_bytes());
        Self { buf }
    }

    /// Append one packet captured at `ts_micros`.
    pub fn packet(&mut self, ts_micros: i64, data: &[u8]) -> &mut Self {
        self.buf
            .extend_from_slice(&((ts_micros / 1_000_000) as u32).to_le_bytes());
        self.buf
            .extend_from_slice(&((ts_micros % 1_000_000) as u32).to_le_bytes());
        self.buf
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.buf
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(data);
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trip() {
        let mut w = PcapWriter::new(1);
        w.packet(1_700_000_000_250_000, b"first")
            .packet(1_700_000_001_000_001, &[0xab; 70]);
        let file = w.finish();
        let reader = PcapReader::new(&file).unwrap();
        assert_eq!(reader.link_type, 1);
        let records: Vec<_> = reader.map(Result::unwrap).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0],
            Record {
                ts_micros: 1_700_000_000_250_000,
                wire_len: 5,
                data: b"first"
            }
        );
        assert_eq!(records[1].ts_micros, 1_700_000_001_000_001);
        assert_eq!(records[1].data.len(), 70);
    }

    #[test]
    fn big_endian_and_nanosecond_files() {
        let mut f = Vec::new();
        f.extend_from_slice(&MAGIC_NANOS.to_be_bytes());
        f.extend_from_slice(&[0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
        f.extend_from_slice(&65_535u32.to_be_bytes());
        f.extend_from_slice(&101u32.to_be_bytes());
        f.extend_from_slice(&10u32.to_be_bytes());
        f.extend_from_slice(&5_000_000u32.to_be_bytes()); // 5 ms in ns
        f.extend_from_slice(&3u32.to_be_bytes()); // captured
        f.extend_from_slice(&1500u32.to_be_bytes()); // on the wire
        f.extend_from_slice(b"abc");
        let mut r = PcapReader::new(&f).unwrap();
        assert_eq!(r.link_type, 101);
        let rec = r.next().unwrap().unwrap();
        assert_eq!(
            rec,
            Record {
                ts_micros: 10_005_000,
                wire_len: 1500,
                data: b"abc"
            }
        );
        assert!(r.next().is_none());
    }

    #[test]
    fn rejects_non_pcap_and_reports_truncation() {
        assert_eq!(PcapReader::new(b"short").unwrap_err(), PcapError::TooShort);
        // The repository's old fixtures began with the ASCII text "PCAP".
        let fake = b"PCAP\x02\x00\x04\x00________________extra";
        assert_eq!(
            PcapReader::new(fake).unwrap_err(),
            PcapError::BadMagic(0x5043_4150)
        );

        let mut w = PcapWriter::new(1);
        w.packet(0, b"complete").packet(1, b"cut-off-here");
        let mut file = w.finish();
        file.truncate(file.len() - 4);
        let results: Vec<_> = PcapReader::new(&file).unwrap().collect();
        assert!(results[0].is_ok());
        assert_eq!(results[1], Err(PcapError::TruncatedRecord { index: 1 }));
        assert_eq!(results.len(), 2, "iteration stops after an error");
    }

    #[test]
    fn oversized_record_is_refused() {
        let mut file = PcapWriter::new(1).finish();
        file.extend_from_slice(&[0; 8]);
        file.extend_from_slice(&u32::MAX.to_le_bytes());
        file.extend_from_slice(&u32::MAX.to_le_bytes());
        let first = PcapReader::new(&file).unwrap().next().unwrap();
        assert!(matches!(
            first,
            Err(PcapError::OversizedRecord { index: 0, .. })
        ));
    }

    proptest! {
        #[test]
        fn never_panics_on_arbitrary_files(data in proptest::collection::vec(any::<u8>(), 0..400)) {
            if let Ok(reader) = PcapReader::new(&data) {
                for r in reader.take(1000).flatten() {
                    prop_assert!(r.data.len() <= data.len());
                }
            }
        }

        #[test]
        fn written_files_always_read_back(
            packets in proptest::collection::vec((0i64..4_000_000_000_000_000, proptest::collection::vec(any::<u8>(), 0..100)), 0..20)
        ) {
            let mut w = PcapWriter::new(1);
            for (ts, data) in &packets {
                w.packet(*ts, data);
            }
            let file = w.finish();
            let back: Vec<_> = PcapReader::new(&file).unwrap().map(Result::unwrap).collect();
            prop_assert_eq!(back.len(), packets.len());
            for (rec, (ts, data)) in back.iter().zip(&packets) {
                prop_assert_eq!(rec.ts_micros, *ts);
                prop_assert_eq!(rec.data, &data[..]);
            }
        }
    }
}
