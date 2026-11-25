//! A script's text: its encoding, its code units, the signature block's
//! location, and the digests over the text the block leaves out.
//!
//! Nothing here allocates in proportion to the file except the base64
//! payload of a signature block, which is capped. The text is read in
//! place, as code units of its encoding (bytes for UTF-8 and BOM-less
//! text, 16-bit units for UTF-16), and converted to UTF-16LE in small
//! chunks as it is hashed. Every structural element the block parser looks
//! for is ASCII, and in UTF-8 an ASCII byte is never part of a multi-byte
//! sequence, so comparing code units with ASCII is exact in every encoding.

#![forbid(unsafe_code)]

use super::{BlockError, Style, TextEncoding, TextIssue};
use crate::hash::{AlgorithmSet, Digest, FlatHashes, HashAlgorithm, MultiHasher};

const CR: u16 = 0x0d;
const LF: u16 = 0x0a;

/// The largest signature, in bytes, a block may decode to: the same 16 MiB
/// limit as a PE certificate table.
pub const MAX_SIGNATURE_SIZE: usize = 16 * 1024 * 1024;
/// The most base64 characters a block may hold: enough for
/// [`MAX_SIGNATURE_SIZE`] bytes.
const MAX_PAYLOAD: usize = MAX_SIGNATURE_SIZE / 3 * 4 + 4;
/// Bytes buffered before they are fed to a hash.
const CHUNK: usize = 16 * 1024;

/// A script's text, read in place.
pub(super) struct Text<'a> {
    /// The bytes after the byte order mark.
    body: &'a [u8],
    /// The byte order mark's length.
    bom_len: usize,
    pub encoding: TextEncoding,
}

impl<'a> Text<'a> {
    /// Reads `data`'s byte order mark and checks that the rest decodes
    /// without ambiguity. Returns the text, and what is wrong with it if
    /// it does not.
    pub fn new(data: &'a [u8]) -> (Self, Option<TextIssue>) {
        let (encoding, bom_len) = match data {
            [0xff, 0xfe, ..] => (TextEncoding::Utf16Le, 2),
            [0xfe, 0xff, ..] => (TextEncoding::Utf16Be, 2),
            [0xef, 0xbb, 0xbf, ..] => (TextEncoding::Utf8Bom, 3),
            _ => (TextEncoding::NoBom, 0),
        };
        let text = Self {
            body: data.get(bom_len..).unwrap_or_default(),
            bom_len,
            encoding,
        };
        let issue = text.issue(data);
        (text, issue)
    }

    fn issue(&self, data: &[u8]) -> Option<TextIssue> {
        match self.encoding {
            // Without a byte order mark the OS guesses the encoding from
            // the first bytes and otherwise uses the machine's code page,
            // so only text that every candidate decodes the same way (ASCII
            // without NUL, which a guess could take for UTF-16) is read.
            TextEncoding::NoBom => {
                if self.body.contains(&0) {
                    Some(TextIssue::NulWithoutBom)
                } else if !self.body.is_ascii() {
                    Some(TextIssue::NonAsciiWithoutBom)
                } else {
                    None
                }
            }
            TextEncoding::Utf8Bom => std::str::from_utf8(self.body)
                .is_err()
                .then_some(TextIssue::InvalidUtf8),
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => {
                if data.starts_with(&[0xff, 0xfe, 0, 0]) {
                    // A UTF-32LE byte order mark starts with the UTF-16LE one.
                    Some(TextIssue::Utf32Bom)
                } else if self.body.len() % 2 != 0 {
                    Some(TextIssue::OddUtf16Length)
                } else if char::decode_utf16(self.units_in(0, self.len())).any(|c| c.is_err()) {
                    Some(TextIssue::UnpairedSurrogate)
                } else {
                    None
                }
            }
        }
    }

    const fn unit_size(&self) -> usize {
        match self.encoding {
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => 2,
            TextEncoding::NoBom | TextEncoding::Utf8Bom => 1,
        }
    }

    /// The number of code units after the byte order mark. A trailing odd
    /// byte of UTF-16 text is not a unit.
    pub fn len(&self) -> usize {
        self.body.len() / self.unit_size()
    }

    /// The code unit at `i`, if there is one.
    fn unit(&self, i: usize) -> Option<u16> {
        match self.encoding {
            TextEncoding::NoBom | TextEncoding::Utf8Bom => self.body.get(i).map(|b| u16::from(*b)),
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => {
                let at = i.checked_mul(2)?;
                let pair = [*self.body.get(at)?, *self.body.get(at.checked_add(1)?)?];
                Some(if self.encoding == TextEncoding::Utf16Le {
                    u16::from_le_bytes(pair)
                } else {
                    u16::from_be_bytes(pair)
                })
            }
        }
    }

    /// The UTF-16 units of `start..end`; for UTF-8 text, its bytes.
    fn units_in(&self, start: usize, end: usize) -> impl Iterator<Item = u16> + '_ {
        (start..end).map_while(|i| self.unit(i))
    }

    /// The file offset of unit `i`.
    pub fn byte_offset(&self, i: usize) -> u64 {
        let at = i
            .saturating_mul(self.unit_size())
            .saturating_add(self.bom_len);
        u64::try_from(at).unwrap_or(u64::MAX)
    }

    /// Whether units `start..end` are exactly the ASCII text `s`.
    fn is(&self, start: usize, end: usize, s: &str) -> bool {
        end.checked_sub(start) == Some(s.len())
            && end <= self.len()
            && self
                .units_in(start, end)
                .zip(s.bytes())
                .all(|(u, b)| u == u16::from(b))
    }

    /// How many times the ASCII text `s` occurs, counting at most to 2.
    pub fn count(&self, s: &str) -> usize {
        (0..self.len())
            .filter(|i| self.starts_with_at(*i, s))
            .take(2)
            .count()
    }

    /// Whether the units from `at` start with the ASCII text `s`.
    pub fn starts_with_at(&self, at: usize, s: &str) -> bool {
        self.is(at, at.saturating_add(s.len()), s)
    }

    /// The index of the first LF at or after `from`.
    fn next_lf(&self, from: usize) -> Option<usize> {
        (from..self.len()).find(|i| self.unit(*i) == Some(LF))
    }

    /// The first unit at which the ASCII text `s` occurs.
    pub fn find(&self, s: &str) -> Option<usize> {
        (0..self.len()).find(|i| self.starts_with_at(*i, s))
    }

    /// Whether the ASCII text `s` occurs at or after unit `from`.
    pub fn contains_from(&self, from: usize, s: &str) -> bool {
        (from..self.len()).any(|i| self.starts_with_at(i, s))
    }

    /// Whether every code unit is ASCII.
    pub fn is_ascii(&self) -> bool {
        self.units_in(0, self.len()).all(|u| u < 0x80)
    }

    /// Reads the signature block whose `begin` line starts at unit
    /// `begin`, exactly as signers write it: a CRLF before the begin line,
    /// the begin line, one `prefix base64 suffix` line per chunk of the
    /// signature, the end line, every line ending in CRLF; and then, for
    /// every format but WSF, the end of the file.
    pub fn parse_block(&self, begin: usize, style: &Style) -> Result<Block, BlockError> {
        let crlf_at = |i: usize| self.unit(i) == Some(CR) && self.unit(i + 1) == Some(LF);
        let start = begin
            .checked_sub(2)
            .filter(|s| crlf_at(*s))
            .ok_or(BlockError::NoLineBreakBefore)?;
        let mut pos = begin + style.begin.len();
        if !crlf_at(pos) {
            return Err(BlockError::BadLineEnding { line: 0 });
        }
        pos += 2;
        let mut payload = Vec::new();
        let mut line = 1_usize;
        let end = loop {
            let Some(lf) = self.next_lf(pos) else {
                return Err(if self.is(pos, self.len(), style.end) {
                    BlockError::Unterminated
                } else {
                    BlockError::MissingEnd
                });
            };
            if lf == pos || self.unit(lf - 1) != Some(CR) {
                return Err(BlockError::BadLineEnding { line });
            }
            let content_end = lf - 1;
            if self.is(pos, content_end, style.end) {
                break lf + 1;
            }
            let data_start = pos + style.prefix.len();
            let data_end = content_end
                .checked_sub(style.suffix.len())
                .filter(|e| *e > data_start)
                .ok_or(BlockError::BadLine { line })?;
            let well_formed = self.is(pos, data_start, style.prefix)
                && self.is(data_end, content_end, style.suffix)
                && self.units_in(data_start, data_end).all(is_base64);
            if !well_formed {
                return Err(BlockError::BadLine { line });
            }
            if payload.len().saturating_add(data_end - data_start) > MAX_PAYLOAD {
                return Err(BlockError::TooLarge);
            }
            // Every unit is a base64 character, so it fits in a byte.
            payload.extend(
                self.units_in(data_start, data_end)
                    .filter_map(|u| u8::try_from(u).ok()),
            );
            pos = lf + 1;
            line += 1;
        };
        if !style.allows_text_after && end != self.len() {
            return Err(BlockError::NotAtEnd);
        }
        if payload.is_empty() {
            return Err(BlockError::Empty);
        }
        Ok(Block {
            start,
            end,
            payload,
        })
    }

    /// Hashes units `start..end` into `sink`. Returns the number of UTF-16
    /// units the range decodes to, or `None` if it does not decode (which
    /// [`Self::new`] has already ruled out for text it accepts).
    fn feed(&self, start: usize, end: usize, sink: &mut Sink) -> Option<u64> {
        let mut units = 0_u64;
        match self.encoding {
            TextEncoding::NoBom | TextEncoding::Utf8Bom => {
                let text = std::str::from_utf8(self.body.get(start..end)?).ok()?;
                for c in text.chars() {
                    let mut buf = [0_u16; 2];
                    for unit in c.encode_utf16(&mut buf) {
                        sink.unit(*unit);
                        units += 1;
                    }
                    sink.char(c);
                }
            }
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => {
                for c in char::decode_utf16(self.units_in(start, end)) {
                    let c = c.ok()?;
                    let mut buf = [0_u16; 2];
                    for unit in c.encode_utf16(&mut buf) {
                        sink.unit(*unit);
                        units += 1;
                    }
                    sink.char(c);
                }
            }
        }
        Some(units)
    }

    /// The digests over the text outside `block` (the whole text when
    /// there is none): the subject interface package's digest under every
    /// algorithm in `sip`, and the normalised script hash.
    pub fn digests(&self, block: Option<&Block>, style: &Style, sip: AlgorithmSet) -> Digests {
        let mut sink = Sink::new(sip);
        let (before, after) = match block {
            Some(b) => ((0, b.start), (b.end, self.len())),
            None => ((0, self.len()), (self.len(), self.len())),
        };
        if style.hashes_bom && self.bom_len > 0 {
            // The byte order mark is hashed as U+FEFF, not as part of the
            // normalised text.
            sink.unit(0xfeff);
        }
        let position = self.feed(before.0, before.1, &mut sink);
        let rest = self.feed(after.0, after.1, &mut sink);
        let decoded = position.is_some() && rest.is_some();
        let empty = position.unwrap_or(0) == 0 && rest.unwrap_or(0) == 0;
        if style.hashes_position {
            // The block's position in the text, in UTF-16 units, as a
            // 32-bit little-endian integer.
            match position.and_then(|p| u32::try_from(p).ok()) {
                Some(p) => sink.raw(&p.to_le_bytes()),
                None => sink.sip = None,
            }
        }
        if !decoded {
            sink.sip = None;
            sink.normalised = None;
        }
        let mut digests = sink.finish();
        digests.empty = empty;
        digests
    }
}

fn is_base64(u: u16) -> bool {
    u8::try_from(u).is_ok_and(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// A well-formed signature block.
#[derive(Debug)]
pub(super) struct Block {
    /// The unit of the CR before the begin line.
    pub start: usize,
    /// The unit after the end line's LF.
    pub end: usize,
    /// The base64 text, every line's data joined.
    pub payload: Vec<u8>,
}

/// What [`Text::digests`] computes. Either is `None` when the text does
/// not decode.
pub(super) struct Digests {
    /// The subject interface package digests.
    pub sip: Option<FlatHashes>,
    /// The normalised script hash, SHA-256.
    pub normalised: Option<Digest>,
    /// Whether the text outside the block is empty, so every digest is a
    /// well-known constant.
    pub empty: bool,
}

/// Feeds the UTF-16LE stream to the subject interface package digest and
/// the decoded characters, line endings normalised, to the normalised hash.
struct Sink {
    sip: Option<MultiHasher>,
    sip_buf: Vec<u8>,
    normalised: Option<MultiHasher>,
    norm_buf: Vec<u8>,
    prev_cr: bool,
}

impl Sink {
    fn new(sip: AlgorithmSet) -> Self {
        Self {
            sip: Some(MultiHasher::new(sip)),
            sip_buf: Vec::with_capacity(CHUNK),
            normalised: Some(MultiHasher::new(AlgorithmSet::SHA256)),
            norm_buf: Vec::with_capacity(CHUNK),
            prev_cr: false,
        }
    }

    fn unit(&mut self, unit: u16) {
        self.raw(&unit.to_le_bytes());
    }

    fn raw(&mut self, bytes: &[u8]) {
        if let Some(h) = &mut self.sip {
            self.sip_buf.extend_from_slice(bytes);
            if self.sip_buf.len() >= CHUNK {
                h.update(&self.sip_buf);
                self.sip_buf.clear();
            }
        }
    }

    /// CRLF and a lone CR both become LF.
    fn char(&mut self, c: char) {
        let Some(h) = &mut self.normalised else {
            return;
        };
        let out = match c {
            '\r' => Some('\n'),
            '\n' if self.prev_cr => None,
            other => Some(other),
        };
        self.prev_cr = c == '\r';
        if let Some(out) = out {
            let mut buf = [0_u8; 4];
            self.norm_buf
                .extend_from_slice(out.encode_utf8(&mut buf).as_bytes());
            if self.norm_buf.len() >= CHUNK {
                h.update(&self.norm_buf);
                self.norm_buf.clear();
            }
        }
    }

    fn finish(mut self) -> Digests {
        let sip = self.sip.take().map(|mut h| {
            h.update(&self.sip_buf);
            h.finalize()
        });
        let normalised = self.normalised.take().and_then(|mut h| {
            h.update(&self.norm_buf);
            h.finalize().get(HashAlgorithm::Sha256).cloned()
        });
        Digests {
            sip,
            normalised,
            empty: false,
        }
    }
}

/// Decodes strict base64: the standard alphabet, a length that is a
/// multiple of four, padding only at the end, and zero bits after the last
/// encoded byte. Anything else is `None`.
pub(super) fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 4 != 0 {
        return None;
    }
    let value = |b: u8| -> Option<u32> {
        Some(u32::from(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let quads = text.chunks_exact(4);
    let last = quads.len().saturating_sub(1);
    for (i, quad) in quads.enumerate() {
        let [a, b, c, d] = <[u8; 4]>::try_from(quad).ok()?;
        let pad = match (c, d) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            _ => 0,
        };
        if pad > 0 && i != last {
            return None;
        }
        let (c, d) = (
            if pad == 2 { b'A' } else { c },
            if pad >= 1 { b'A' } else { d },
        );
        let n = (value(a)? << 18) | (value(b)? << 12) | (value(c)? << 6) | value(d)?;
        let [_, x, y, z] = n.to_be_bytes();
        // Bits past the last encoded byte must be zero.
        if (pad == 2 && n & 0xffff != 0) || (pad == 1 && n & 0xff != 0) {
            return None;
        }
        out.push(x);
        if pad < 2 {
            out.push(y);
        }
        if pad < 1 {
            out.push(z);
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_strict() {
        assert_eq!(decode_base64(b"TWFu").unwrap(), b"Man");
        assert_eq!(decode_base64(b"TWE=").unwrap(), b"Ma");
        assert_eq!(decode_base64(b"TQ==").unwrap(), b"M");
        assert_eq!(decode_base64(b"").as_deref(), None);
        assert_eq!(decode_base64(b"TWF").as_deref(), None);
        assert_eq!(decode_base64(b"TQ==TWFu").as_deref(), None, "inner padding");
        assert_eq!(
            decode_base64(b"TR==").as_deref(),
            None,
            "non-zero spare bits"
        );
        assert_eq!(
            decode_base64(b"TWF=").as_deref(),
            None,
            "non-zero spare bits"
        );
        assert_eq!(decode_base64(b"T===").as_deref(), None);
        assert_eq!(decode_base64(b"TW-u").as_deref(), None);
        assert_eq!(decode_base64(b"=WFu").as_deref(), None);
    }

    #[test]
    fn base64_round_trips_every_byte() {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for len in 0..40_usize {
            let data: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) % 256) as u8).collect();
            let mut text = Vec::new();
            for chunk in data.chunks(3) {
                let n = chunk
                    .iter()
                    .enumerate()
                    .fold(0_u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
                for i in 0..4 {
                    if i <= chunk.len() {
                        text.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]);
                    } else {
                        text.push(b'=');
                    }
                }
            }
            if len == 0 {
                assert!(decode_base64(&text).is_none());
            } else {
                assert_eq!(decode_base64(&text).unwrap(), data, "{len}");
            }
        }
    }
}
