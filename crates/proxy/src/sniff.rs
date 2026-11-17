//! Content type sniffing from the leading bytes of a body, used on bodies the agent decrypts for
//! the client (`response_decrypt_aes`).

const SNIFF_WINDOW: usize = 512;

enum Sig {
    Html(&'static [u8]),
    Masked {
        mask: &'static [u8],
        pat: &'static [u8],
        skip_ws: bool,
        ct: &'static str,
    },
    Exact(&'static [u8], &'static str),
    Mp4,
    Text,
}

const fn m(mask: &'static [u8], pat: &'static [u8], ct: &'static str) -> Sig {
    Sig::Masked {
        mask,
        pat,
        skip_ws: false,
        ct,
    }
}

const SIGS: &[Sig] = &[
    Sig::Html(b"<!DOCTYPE HTML"),
    Sig::Html(b"<HTML"),
    Sig::Html(b"<HEAD"),
    Sig::Html(b"<SCRIPT"),
    Sig::Html(b"<IFRAME"),
    Sig::Html(b"<H1"),
    Sig::Html(b"<DIV"),
    Sig::Html(b"<FONT"),
    Sig::Html(b"<TABLE"),
    Sig::Html(b"<A"),
    Sig::Html(b"<STYLE"),
    Sig::Html(b"<TITLE"),
    Sig::Html(b"<B"),
    Sig::Html(b"<BODY"),
    Sig::Html(b"<BR"),
    Sig::Html(b"<P"),
    Sig::Html(b"<!--"),
    Sig::Masked { mask: b"\xFF\xFF\xFF\xFF\xFF", pat: b"<?xml", skip_ws: true, ct: "text/xml; charset=utf-8" },
    Sig::Exact(b"%PDF-", "application/pdf"),
    Sig::Exact(b"%!PS-Adobe-", "application/postscript"),
    m(b"\xFF\xFF\x00\x00", b"\xFE\xFF\x00\x00", "text/plain; charset=utf-16be"),
    m(b"\xFF\xFF\x00\x00", b"\xFF\xFE\x00\x00", "text/plain; charset=utf-16le"),
    m(b"\xFF\xFF\xFF\x00", b"\xEF\xBB\xBF\x00", "text/plain; charset=utf-8"),
    Sig::Exact(b"\x00\x00\x01\x00", "image/x-icon"),
    Sig::Exact(b"\x00\x00\x02\x00", "image/x-icon"),
    Sig::Exact(b"BM", "image/bmp"),
    Sig::Exact(b"GIF87a", "image/gif"),
    Sig::Exact(b"GIF89a", "image/gif"),
    m(b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF", b"RIFF\x00\x00\x00\x00WEBPVP", "image/webp"),
    Sig::Exact(b"\x89PNG\x0D\x0A\x1A\x0A", "image/png"),
    Sig::Exact(b"\xFF\xD8\xFF", "image/jpeg"),
    m(b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", b"FORM\x00\x00\x00\x00AIFF", "audio/aiff"),
    m(b"\xFF\xFF\xFF", b"ID3", "audio/mpeg"),
    m(b"\xFF\xFF\xFF\xFF\xFF", b"OggS\x00", "application/ogg"),
    m(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", b"MThd\x00\x00\x00\x06", "audio/midi"),
    m(b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", b"RIFF\x00\x00\x00\x00AVI ", "video/avi"),
    m(b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", b"RIFF\x00\x00\x00\x00WAVE", "audio/wave"),
    Sig::Mp4,
    Sig::Exact(b"\x1A\x45\xDF\xA3", "video/webm"),
    m(
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
        "application/vnd.ms-fontobject",
    ),
    Sig::Exact(b"\x00\x01\x00\x00", "font/ttf"),
    Sig::Exact(b"OTTO", "font/otf"),
    Sig::Exact(b"ttcf", "font/collection"),
    Sig::Exact(b"wOFF", "font/woff"),
    Sig::Exact(b"wOF2", "font/woff2"),
    Sig::Exact(b"\x1F\x8B\x08", "application/x-gzip"),
    Sig::Exact(b"PK\x03\x04", "application/zip"),
    Sig::Exact(b"Rar!\x1A\x07\x00", "application/x-rar-compressed"),
    Sig::Exact(b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"),
    Sig::Exact(b"\x00\x61\x73\x6D", "application/wasm"),
    Sig::Text,
];

fn is_sniff_whitespace(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

fn matches(sig: &Sig, data: &[u8], first_non_ws: usize) -> Option<&'static str> {
    match *sig {
        Sig::Exact(p, ct) => data.starts_with(p).then_some(ct),
        Sig::Masked {
            mask,
            pat,
            skip_ws,
            ct,
        } => {
            let data = if skip_ws { &data[first_non_ws..] } else { data };
            (data.len() >= pat.len()
                && pat
                    .iter()
                    .zip(mask)
                    .enumerate()
                    .all(|(i, (&p, &mk))| data[i] & mk == p))
            .then_some(ct)
        }
        Sig::Html(h) => {
            let data = &data[first_non_ws..];
            if data.len() < h.len() + 1 {
                return None;
            }
            let ok = h.iter().enumerate().all(|(i, &b)| {
                let db = if b.is_ascii_uppercase() {
                    data[i] & 0xDF
                } else {
                    data[i]
                };
                b == db
            });
            (ok && matches!(data[h.len()], b' ' | b'>')).then_some("text/html; charset=utf-8")
        }
        Sig::Mp4 => {
            if data.len() < 12 {
                return None;
            }
            let box_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if data.len() < box_size || !box_size.is_multiple_of(4) || &data[4..8] != b"ftyp" {
                return None;
            }
            (8..box_size)
                .step_by(4)
                .filter(|&st| st != 12)
                .any(|st| &data[st..st + 3] == b"mp4")
                .then_some("video/mp4")
        }
        Sig::Text => {
            let bad = data[first_non_ws..].iter().any(|&b| {
                b <= 0x08 || b == 0x0b || (0x0e..=0x1a).contains(&b) || (0x1c..=0x1f).contains(&b)
            });
            (!bad).then_some("text/plain; charset=utf-8")
        }
    }
}

/// The sniffed content type of `data`.
pub fn sniff_content_type(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(SNIFF_WINDOW)];
    let first_non_ws = data
        .iter()
        .position(|&b| !is_sniff_whitespace(b))
        .unwrap_or(data.len());
    SIGS.iter()
        .find_map(|s| matches(s, data, first_non_ws))
        .unwrap_or("application/octet-stream")
}

#[cfg(test)]
mod tests {
    use super::sniff_content_type as d;

    #[test]
    fn sniffs_known_content_types() {
        assert_eq!(d(b""), "text/plain; charset=utf-8");
        assert_eq!(d(b"\x01\x02\x03"), "application/octet-stream");
        assert_eq!(
            d(b"<HtMl><bOdY>blah blah blah</body></html>"),
            "text/html; charset=utf-8"
        );
        assert_eq!(d(b"\n<html>blah"), "text/html; charset=utf-8");
        assert_eq!(d(b"<!-- a"), "text/html; charset=utf-8");
        assert_eq!(d(b"\n<?xml!"), "text/xml; charset=utf-8");
        assert_eq!(d(b"\xFE\xFF\x00\x00"), "text/plain; charset=utf-16be");
        assert_eq!(d(b"GIF87a"), "image/gif");
        assert_eq!(d(b"\x89PNG\x0D\x0A\x1A\x0A"), "image/png");
        assert_eq!(
            d(b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom<\x06t\xbfmdat"),
            "video/mp4"
        );
        assert_eq!(d(b"%PDF-1.4"), "application/pdf");
        assert_eq!(d(b"{\"a\":1}"), "text/plain; charset=utf-8");
    }
}
