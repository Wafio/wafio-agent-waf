//! The raw ClientHello of a TLS connection, read before the handshake: its SNI name and the JA4
//! fingerprint. rustls's parsed ClientHello lacks the extension list JA4 needs, so the listener
//! reads the first record itself, rewinds it onto the stream and then starts the handshake.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

/// A TLS record header and the largest record payload.
pub const MAX_RECORD_LEN: usize = 5 + (1 << 14);

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_RECORD: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// The fingerprint prints a count as two digits and stops at this.
const MAX_COUNT: usize = 99;
/// The longest DNS name, so a hostile SNI cannot grow the string we keep.
const MAX_SERVER_NAME_LEN: usize = 255;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// What the ClientHello tells about the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHelloSummary {
    /// The `server_name` host name, lower case; `None` when the extension is absent or holds no
    /// usable name (the handshake judges the name, this is for the log).
    pub server_name: Option<String>,
    /// JA4, as in `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub ja4: String,
}

/// Reads the first TLS record: the 5-byte header, then the payload it announces, at most
/// [`MAX_RECORD_LEN`] bytes in all. A header that is not a handshake record ends the read and its
/// bytes are returned as read, for the caller to rewind. The caller bounds the time.
pub async fn read_first_record<R: AsyncRead + Unpin>(io: &mut R) -> std::io::Result<Vec<u8>> {
    let mut record = vec![0u8; RECORD_HEADER_LEN];
    io.read_exact(&mut record).await?;
    let payload = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record[0] != HANDSHAKE_RECORD || RECORD_HEADER_LEN + payload > MAX_RECORD_LEN {
        return Ok(record);
    }
    // Grown as bytes arrive: a client that announces a full record and sends nothing holds none.
    io.take(payload as u64).read_to_end(&mut record).await?;
    if record.len() != RECORD_HEADER_LEN + payload {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(record)
}

/// Parses a handshake record holding a whole ClientHello. `None`: not a ClientHello, cut short (a
/// hello spanning records) or malformed. The input is the client's, so every length is checked
/// before it is used. The body of an extension the fingerprint reads is judged leniently (a name
/// or list that does not parse counts as absent): the handshake refuses such a hello anyway.
pub fn parse(record: &[u8]) -> Option<ClientHelloSummary> {
    let mut rec = Cursor(record);
    if rec.u8()? != HANDSHAKE_RECORD || rec.u8()? != 3 {
        return None;
    }
    rec.u8()?; // minor version: old clients put 1 here, the real version is in the hello
    let payload = rec.block16()?;
    if payload.len() > MAX_RECORD_LEN - RECORD_HEADER_LEN {
        return None;
    }
    let mut payload = Cursor(payload);
    if payload.u8()? != CLIENT_HELLO {
        return None;
    }
    let hello_len = payload.u24()?;
    let mut hello = Cursor(payload.bytes(hello_len)?);

    let legacy_version = hello.u16()?;
    hello.bytes(32)?; // random
    hello.block8()?; // session id
    let cipher_block = hello.block16()?;
    if cipher_block.is_empty() {
        return None;
    }
    let mut values: Vec<u16> = pairs(cipher_block)?.filter(|v| !is_grease(*v)).collect();
    let cipher_count = values.len();
    values.sort_unstable();
    let cipher_hash = hash12(&values, &[]);
    values.clear();

    hello.block8()?; // compression methods
    // A hello without extensions ends here.
    let extensions: &[u8] = if hello.is_empty() {
        &[]
    } else {
        hello.block16()?
    };
    if !hello.is_empty() {
        return None;
    }

    let mut extension_count = 0;
    let mut has_sni = false;
    let mut server_name = None;
    let mut alpn: &[u8] = &[];
    let mut signature_algorithms: &[u8] = &[];
    let mut top_version = None;
    let mut ext = Cursor(extensions);
    while !ext.is_empty() {
        let kind = ext.u16()?;
        let data = ext.block16()?;
        if is_grease(kind) {
            continue;
        }
        extension_count += 1;
        // The name and the protocol are in the first part of the fingerprint already.
        if kind != EXT_SERVER_NAME && kind != EXT_ALPN {
            values.push(kind);
        }
        match kind {
            EXT_SERVER_NAME => {
                has_sni = true;
                server_name = host_name(data);
            }
            EXT_ALPN => alpn = first_alpn(data),
            EXT_SIGNATURE_ALGORITHMS => {
                signature_algorithms = Cursor(data).block16().unwrap_or_default();
            }
            EXT_SUPPORTED_VERSIONS => top_version = highest_version(data),
            _ => {}
        }
    }
    values.sort_unstable();

    let mut ja4 = String::with_capacity(36);
    ja4.push('t');
    ja4.push_str(version_code(top_version.unwrap_or(legacy_version)));
    ja4.push(if has_sni { 'd' } else { 'i' });
    let _ = write!(
        ja4,
        "{:02}{:02}",
        cipher_count.min(MAX_COUNT),
        extension_count.min(MAX_COUNT)
    );
    ja4.extend(alpn_chars(alpn).map(char::from));
    ja4.push('_');
    ja4.extend(cipher_hash.map(char::from));
    ja4.push('_');
    ja4.extend(hash12(&values, signature_algorithms).map(char::from));
    Some(ClientHelloSummary { server_name, ja4 })
}

/// A read position in bytes from the network: every read checks the length first.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.bytes(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.bytes(3)?;
        Some((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }

    /// A block behind a one-byte length.
    fn block8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.bytes(usize::from(n))
    }

    /// A block behind a two-byte length.
    fn block16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }
}

/// The big-endian pairs of `bytes`; `None` for an odd length.
fn pairs(bytes: &[u8]) -> Option<impl Iterator<Item = u16> + '_> {
    let chunks = bytes.chunks_exact(2);
    chunks
        .remainder()
        .is_empty()
        .then(|| chunks.map(|c| u16::from_be_bytes([c[0], c[1]])))
}

/// The reserved values of RFC 8701: both bytes `0x?a` with the same high nibble.
fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

/// The first host name of a `server_name` extension body, lower case. Only printable ASCII is kept,
/// so the name is safe to log.
fn host_name(data: &[u8]) -> Option<String> {
    let mut list = Cursor(Cursor(data).block16()?);
    while !list.is_empty() {
        let kind = list.u8()?;
        let name = list.block16()?;
        if kind == 0 {
            let usable = !name.is_empty()
                && name.len() <= MAX_SERVER_NAME_LEN
                && name.iter().all(u8::is_ascii_graphic);
            return usable
                .then(|| String::from_utf8(name.to_ascii_lowercase()).ok())
                .flatten();
        }
    }
    None
}

/// The first protocol of an ALPN extension body; empty when there is none.
fn first_alpn(data: &[u8]) -> &[u8] {
    let list = Cursor(data).block16().unwrap_or_default();
    Cursor(list).block8().unwrap_or_default()
}

/// The highest version a `supported_versions` extension body offers, GREASE left out.
fn highest_version(data: &[u8]) -> Option<u16> {
    pairs(Cursor(data).block8()?)?
        .filter(|v| !is_grease(*v))
        .max()
}

fn version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// The first and last character of the first ALPN value. Where either byte is not an ASCII letter
/// or digit, the first and last hex digit of the value instead, as the JA4 specification says.
fn alpn_chars(value: &[u8]) -> [u8; 2] {
    match (value.first(), value.last()) {
        (Some(&first), Some(&last))
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() =>
        {
            [first, last]
        }
        (Some(&first), Some(&last)) => [hex_byte(first)[0], hex_byte(last)[1]],
        _ => *b"00",
    }
}

fn hex_byte(byte: u8) -> [u8; 2] {
    [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]]
}

/// Feeds `values` to `hash` as comma separated 4-digit lower case hex.
fn feed(hash: &mut Sha256, values: impl Iterator<Item = u16>) {
    for (i, value) in values.enumerate() {
        if i > 0 {
            hash.update(b",");
        }
        let [high, low] = value.to_be_bytes();
        hash.update(hex_byte(high));
        hash.update(hex_byte(low));
    }
}

/// The first 12 hex digits of the SHA-256 of `values` (comma separated hex), followed when `tail`
/// is not empty by `_` and its big-endian pairs the same way. All zeros for no values, so an empty
/// list reads as empty and not as the hash of nothing.
fn hash12(values: &[u16], tail: &[u8]) -> [u8; 12] {
    if values.is_empty() {
        return [b'0'; 12];
    }
    let mut hash = Sha256::new();
    feed(&mut hash, values.iter().copied());
    if !tail.is_empty() {
        hash.update(b"_");
        feed(
            &mut hash,
            tail.chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]])),
        );
    }
    let digest = hash.finalize();
    let mut out = [0u8; 12];
    for (pair, byte) in out.chunks_exact_mut(2).zip(digest.iter()) {
        pair.copy_from_slice(&hex_byte(*byte));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn be16(n: usize) -> [u8; 2] {
        u16::try_from(n).unwrap().to_be_bytes()
    }

    fn u16s(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
        cat(&[&kind.to_be_bytes(), &be16(data.len()), data])
    }

    fn sni_ext(name: &str) -> Vec<u8> {
        let entry = cat(&[&[0], &be16(name.len()), name.as_bytes()]);
        ext(EXT_SERVER_NAME, &cat(&[&be16(entry.len()), &entry]))
    }

    fn alpn_ext(values: &[&[u8]]) -> Vec<u8> {
        let list: Vec<u8> = values
            .iter()
            .flat_map(|v| cat(&[&[u8::try_from(v.len()).unwrap()], v]))
            .collect();
        ext(EXT_ALPN, &cat(&[&be16(list.len()), &list]))
    }

    fn versions_ext(versions: &[u16]) -> Vec<u8> {
        let list = u16s(versions);
        ext(
            EXT_SUPPORTED_VERSIONS,
            &cat(&[&[u8::try_from(list.len()).unwrap()], &list]),
        )
    }

    fn sigalgs_ext(algorithms: &[u16]) -> Vec<u8> {
        let list = u16s(algorithms);
        ext(EXT_SIGNATURE_ALGORITHMS, &cat(&[&be16(list.len()), &list]))
    }

    /// A handshake record around one ClientHello; `extensions` `None` leaves the block out.
    fn record(legacy_version: u16, ciphers: &[u16], extensions: Option<&[Vec<u8>]>) -> Vec<u8> {
        let ciphers = u16s(ciphers);
        let mut hello = cat(&[
            &legacy_version.to_be_bytes(),
            &[7; 32],
            &[32],
            &[9; 32],
            &be16(ciphers.len()),
            &ciphers,
            &[1, 0],
        ]);
        if let Some(extensions) = extensions {
            let body = extensions.concat();
            hello.extend(cat(&[&be16(body.len()), &body]));
        }
        let len = u32::try_from(hello.len()).unwrap().to_be_bytes();
        let handshake = cat(&[&[CLIENT_HELLO, len[1], len[2], len[3]], &hello]);
        cat(&[
            &[HANDSHAKE_RECORD, 3, 1],
            &be16(handshake.len()),
            &handshake,
        ])
    }

    // The hello behind the JA4 specification's worked example: its ciphers, extensions and
    // signature algorithms in the original order of its raw listing. Bodies the fingerprint does
    // not read are empty.
    const SPEC_CIPHERS: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    const SPEC_SIGNATURE_ALGORITHMS: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    const SPEC_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

    fn spec_extensions(versions: &[u16], algorithms: &[u16]) -> Vec<Vec<u8>> {
        vec![
            ext(0x001b, b""),
            sni_ext("Shop.Example.com"),
            ext(0x0033, b""),
            alpn_ext(&[b"h2", b"http/1.1"]),
            ext(0x4469, b""),
            ext(0x0017, b""),
            ext(0x002d, b""),
            sigalgs_ext(algorithms),
            ext(0x0005, b""),
            ext(0x0023, b""),
            ext(0x0012, b""),
            versions_ext(versions),
            ext(0xff01, b""),
            ext(0x000b, b""),
            ext(0x000a, b""),
            ext(0x0015, b""),
        ]
    }

    fn spec_record() -> Vec<u8> {
        record(
            0x0303,
            &SPEC_CIPHERS,
            Some(&spec_extensions(
                &[0x0304, 0x0303],
                &SPEC_SIGNATURE_ALGORITHMS,
            )),
        )
    }

    fn ja4_of(record: &[u8]) -> String {
        parse(record).unwrap().ja4
    }

    #[test]
    fn matches_the_specification_example() {
        let summary = parse(&spec_record()).unwrap();
        assert_eq!(summary.ja4, SPEC_JA4);
        assert_eq!(summary.server_name.as_deref(), Some("shop.example.com"));
    }

    #[test]
    fn extension_hash_without_signature_algorithms_matches_the_specification() {
        // The specification hashes the same sorted list without the `_` part to 6d807ffa2a79.
        let rec = record(
            0x0303,
            &SPEC_CIPHERS,
            Some(&spec_extensions(&[0x0304, 0x0303], &[])),
        );
        assert_eq!(ja4_of(&rec), "t13d1516h2_8daaf6152771_6d807ffa2a79");
    }

    #[test]
    fn hello_without_extensions_computed_by_hand() {
        // Hashes taken with `printf %s '009c,c02f,c030' | shasum -a 256`, not from this code.
        let expected = "t12i030000_13bac7b83268_000000000000";
        let ciphers = [0xc030, 0xc02f, 0x009c];
        let rec = record(0x0303, &ciphers, None);
        let summary = parse(&rec).unwrap();
        assert_eq!(summary.ja4, expected);
        assert_eq!(summary.server_name, None);
        assert_eq!(ja4_of(&record(0x0303, &ciphers, Some(&[]))), expected);
    }

    #[test]
    fn grease_is_dropped_everywhere() {
        let mut ciphers = vec![0x0a0a];
        ciphers.extend(SPEC_CIPHERS);
        ciphers.push(0xfafa);
        let mut extensions = spec_extensions(&[0x2a2a, 0x0304, 0x0303], &SPEC_SIGNATURE_ALGORITHMS);
        extensions.insert(0, ext(0x1a1a, b"\0"));
        extensions.push(ext(0xdada, b""));
        assert_eq!(
            ja4_of(&record(0x0303, &ciphers, Some(&extensions))),
            SPEC_JA4
        );
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && is_grease(0x7a7a));
        assert!(!is_grease(0x0a1a) && !is_grease(0x1301) && !is_grease(0x0a0b));
    }

    #[test]
    fn version_is_the_highest_offered_else_the_legacy_one() {
        let version_of = |versions: &[u16]| {
            let rec = record(
                0x0303,
                &SPEC_CIPHERS,
                Some(&spec_extensions(versions, &SPEC_SIGNATURE_ALGORITHMS)),
            );
            ja4_of(&rec)[1..3].to_string()
        };
        assert_eq!(version_of(&[0x0302, 0x0303]), "12");
        assert_eq!(version_of(&[0x0301, 0x0304, 0x0302]), "13");
        // Only GREASE offered: the legacy version of the hello.
        assert_eq!(version_of(&[0x2a2a]), "12");
        assert_eq!(version_of(&[0x1234]), "00");
    }

    #[test]
    fn alpn_characters_follow_the_specification() {
        let cases: [(&[u8], &[u8; 2]); 12] = [
            (b"h2", b"h2"),
            (b"http/1.1", b"h1"),
            (b"a", b"aa"),
            (b"", b"00"),
            (&[0xab], b"ab"),
            (&[0x20], b"20"),
            (&[0xab, 0xcd], b"ad"),
            (&[0x20, 0x61], b"21"),
            (&[0x30, 0xab], b"3b"),
            (&[0x61, 0x20], b"60"),
            (&[0x30, 0x31, 0xab, 0xcd], b"3d"),
            (&[0x30, 0xab, 0xcd, 0x31], b"01"),
        ];
        for (value, expected) in cases {
            assert_eq!(&alpn_chars(value), expected, "{value:02x?}");
        }
    }

    #[test]
    fn alpn_extension_forms() {
        let ja4_with = |alpn: Vec<u8>| {
            let rec = record(0x0303, &SPEC_CIPHERS, Some(&[sni_ext("a.test"), alpn]));
            ja4_of(&rec)
        };
        assert_eq!(&ja4_with(alpn_ext(&[b"http/1.1"]))[8..10], "h1");
        assert_eq!(&ja4_with(alpn_ext(&[]))[8..10], "00");
        assert_eq!(&ja4_with(alpn_ext(&[b""]))[8..10], "00");
        assert_eq!(&ja4_with(ext(EXT_ALPN, b""))[8..10], "00");
        assert_eq!(&ja4_with(ext(EXT_ALPN, &[0, 9, 5, b'h']))[8..10], "00");
    }

    #[test]
    fn counts_stop_at_99() {
        let ciphers: Vec<u16> = (0..150).collect();
        let extensions: Vec<Vec<u8>> = (0x0100..0x0100 + 120).map(|k| ext(k, b"")).collect();
        let ja4 = ja4_of(&record(0x0303, &ciphers, Some(&extensions)));
        assert!(ja4.starts_with("t12i999900_"), "{ja4}");
    }

    #[test]
    fn server_name_is_lower_case_printable_ascii_or_none() {
        let name_of = |name: &str| {
            let rec = record(0x0303, &SPEC_CIPHERS, Some(&[sni_ext(name)]));
            let summary = parse(&rec).unwrap();
            assert_eq!(summary.ja4.as_bytes()[3], b'd', "the extension is there");
            summary.server_name
        };
        assert_eq!(
            name_of("WWW.Example.COM").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(name_of(""), None);
        assert_eq!(name_of("bad name"), None);
        assert_eq!(name_of("caf\u{e9}.example"), None);
        assert_eq!(name_of("line\nbreak"), None);
        assert_eq!(name_of(&"a".repeat(256)), None);
        assert!(name_of(&"a".repeat(255)).is_some());
        // An entry of another name type is skipped, a broken list gives no name.
        let other_kind = cat(&[&[1], &be16(3), b"abc"]);
        let body = ext(
            EXT_SERVER_NAME,
            &cat(&[&be16(other_kind.len()), &other_kind]),
        );
        let rec = record(0x0303, &SPEC_CIPHERS, Some(&[body]));
        assert_eq!(parse(&rec).unwrap().server_name, None);
        let rec = record(
            0x0303,
            &SPEC_CIPHERS,
            Some(&[ext(EXT_SERVER_NAME, &[0, 40, 0])]),
        );
        assert_eq!(parse(&rec).unwrap().server_name, None);
    }

    #[test]
    fn not_a_client_hello_is_none() {
        let good = spec_record();
        assert!(parse(&good).is_some());
        let with = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut rec = good.clone();
            edit(&mut rec);
            parse(&rec)
        };
        assert_eq!(with(&|r| r[0] = 0x17), None, "application data record");
        assert_eq!(with(&|r| r[1] = 2), None, "record version");
        assert_eq!(with(&|r| r[5] = 2), None, "server hello");
        assert_eq!(with(&|r| r[6] = 1), None, "hello length past the record");
        assert_eq!(
            with(&|r| r.extend(b"x")),
            parse(&good),
            "bytes after the record are not read"
        );
        assert_eq!(parse(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), None);
        assert_eq!(parse(b"\x80\x2e\x01\x03\x01\x00\x25"), None);
        assert_eq!(parse(&record(0x0303, &[], Some(&[]))), None, "no ciphers");
        // An odd cipher list and bytes after the extension block are malformed.
        let mut rec = good.clone();
        rec[77] = 29;
        assert_eq!(parse(&rec), None);
        let mut rec = record(0x0303, &SPEC_CIPHERS, Some(&[sni_ext("a.test")]));
        rec.push(0);
        let len = be16(rec.len() - 5);
        rec[3..5].copy_from_slice(&len);
        let hello_len = u32::try_from(rec.len() - 9).unwrap().to_be_bytes();
        rec[6..9].copy_from_slice(&hello_len[1..]);
        assert_eq!(parse(&rec), None);
    }

    #[test]
    fn every_prefix_is_none() {
        let sample_records = [
            spec_record(),
            record(0x0303, &[0xc030, 0xc02f, 0x009c], None),
            record(0x0301, &[0x002f], Some(&[sni_ext("a.test")])),
        ];
        for rec in sample_records {
            assert!(parse(&rec).is_some());
            for n in 0..rec.len() {
                assert_eq!(parse(&rec[..n]), None, "prefix of {n} bytes");
            }
        }
    }

    #[test]
    fn oversized_lengths_are_none() {
        let good = spec_record();
        // Layout: 5 record header, 4 handshake header, 2 version, 32 random, 1 + 32 session id,
        // 2 + 30 ciphers, 1 + 1 compression, then the extension block length at 110.
        let ext_len_at = 110;
        assert_eq!(
            usize::from(u16::from_be_bytes([good[ext_len_at], good[ext_len_at + 1]])),
            good.len() - ext_len_at - 2
        );
        let first_ext_len_at = ext_len_at + 2 + 2;
        for (at, width) in [
            (3, 2),
            (6, 3),
            (43, 1),
            (76, 2),
            (ext_len_at, 2),
            (first_ext_len_at, 2),
        ] {
            let mut rec = good.clone();
            rec[at..at + width].fill(0xff);
            assert_eq!(parse(&rec), None, "length at {at}");
        }
        // A record longer than the largest allowed, whatever it holds.
        let mut rec = good.clone();
        rec.resize(5 + (1 << 14) + 1, 0);
        rec[3..5].copy_from_slice(&be16((1 << 14) + 1));
        assert_eq!(parse(&rec), None);
    }

    #[test]
    fn no_byte_change_makes_parse_panic() {
        for original in [spec_record(), record(0x0303, &[0xc030], None)] {
            for at in 0..original.len() {
                for value in [0x00, 0x01, 0x02, 0x7f, 0x80, 0xff] {
                    let mut rec = original.clone();
                    rec[at] = value;
                    let _ = parse(&rec);
                }
                if at + 2 <= original.len() {
                    let mut rec = original.clone();
                    rec[at..at + 2].fill(0xff);
                    let _ = parse(&rec);
                }
            }
        }
    }

    #[tokio::test]
    async fn reads_one_record_and_leaves_the_rest() {
        let rec = spec_record();
        let input = cat(&[&rec, b"tail"]);
        let mut io = &input[..];
        assert_eq!(read_first_record(&mut io).await.unwrap(), rec);
        assert_eq!(io, b"tail");
    }

    #[tokio::test]
    async fn stops_at_a_header_that_is_not_a_handshake_or_is_too_large() {
        let mut io = &b"GET / HTTP/1.1\r\n"[..];
        assert_eq!(read_first_record(&mut io).await.unwrap(), b"GET /");
        assert_eq!(io, b" HTTP/1.1\r\n");
        let mut io = &[0x16, 3, 1, 0x40, 0x01, 9, 9][..];
        assert_eq!(
            read_first_record(&mut io).await.unwrap(),
            [0x16, 3, 1, 0x40, 0x01]
        );
        let largest = cat(&[&[0x16, 3, 1], &be16(1 << 14), &[0; 1 << 14]]);
        let mut io = &largest[..];
        assert_eq!(read_first_record(&mut io).await.unwrap(), largest);
    }

    #[tokio::test]
    async fn a_record_cut_short_is_an_error() {
        for input in [&[0x16, 3][..], &[0x16, 3, 1, 0, 9, 1, 2][..], &b""[..]] {
            let mut io = input;
            let err = read_first_record(&mut io).await.unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "{input:02x?}"
            );
        }
    }
}
