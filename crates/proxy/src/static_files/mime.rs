//! The content type of a file, by the extension of its name.

/// Extensions in lower case and what they are served as. Text types name their charset, since a
/// file has no header of its own to say so.
const TYPES: &[(&str, &str)] = &[
    ("avif", "image/avif"),
    ("bmp", "image/bmp"),
    ("css", "text/css; charset=utf-8"),
    ("csv", "text/csv; charset=utf-8"),
    ("eot", "application/vnd.ms-fontobject"),
    ("gif", "image/gif"),
    ("gz", "application/gzip"),
    ("htm", "text/html; charset=utf-8"),
    ("html", "text/html; charset=utf-8"),
    ("ico", "image/vnd.microsoft.icon"),
    ("jpeg", "image/jpeg"),
    ("jpg", "image/jpeg"),
    ("js", "text/javascript; charset=utf-8"),
    ("json", "application/json"),
    ("map", "application/json"),
    ("md", "text/markdown; charset=utf-8"),
    ("mjs", "text/javascript; charset=utf-8"),
    ("mp3", "audio/mpeg"),
    ("mp4", "video/mp4"),
    ("oga", "audio/ogg"),
    ("ogg", "audio/ogg"),
    ("ogv", "video/ogg"),
    ("otf", "font/otf"),
    ("pdf", "application/pdf"),
    ("png", "image/png"),
    ("svg", "image/svg+xml"),
    ("tar", "application/x-tar"),
    ("ttf", "font/ttf"),
    ("txt", "text/plain; charset=utf-8"),
    ("wasm", "application/wasm"),
    ("wav", "audio/wav"),
    ("webm", "video/webm"),
    ("webmanifest", "application/manifest+json"),
    ("webp", "image/webp"),
    ("woff", "font/woff"),
    ("woff2", "font/woff2"),
    ("xml", "application/xml"),
    ("zip", "application/zip"),
];

/// What a file named `name` is served as: by the text after its last dot, in any case, and
/// `application/octet-stream` for a name with no dot or one this table does not know.
pub(super) fn content_type(name: &[u8]) -> &'static str {
    let Some(dot) = name.iter().rposition(|&c| c == b'.') else {
        return "application/octet-stream";
    };
    let ext = &name[dot + 1..];
    TYPES
        .iter()
        .find(|(known, _)| known.as_bytes().eq_ignore_ascii_case(ext))
        .map_or("application/octet-stream", |&(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_extension_picks_the_type_in_any_case_and_the_rest_is_a_download() {
        for (name, want) in [
            ("index.html", "text/html; charset=utf-8"),
            ("A.HTM", "text/html; charset=utf-8"),
            ("app.min.js", "text/javascript; charset=utf-8"),
            ("site.css", "text/css; charset=utf-8"),
            ("logo.SVG", "image/svg+xml"),
            ("font.woff2", "font/woff2"),
            ("a.b.png", "image/png"),
            ("data.json", "application/json"),
            ("noext", "application/octet-stream"),
            ("trailing.", "application/octet-stream"),
            (".hidden", "application/octet-stream"),
            ("archive.tar.xz", "application/octet-stream"),
            ("x.exe", "application/octet-stream"),
        ] {
            assert_eq!(content_type(name.as_bytes()), want, "{name}");
        }
    }

    #[test]
    fn the_table_is_sorted_and_lower_case_so_a_name_has_one_type() {
        for pair in TYPES.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} before {}", pair[0].0, pair[1].0);
        }
        assert!(TYPES.iter().all(|(e, _)| {
            e.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        }));
    }
}
