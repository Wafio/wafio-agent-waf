//! Unix path cleaning.

/// Cleans a Unix path: collapses repeated separators and resolves `.` and `..` elements.
pub fn normalize_path(path: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return b".".to_vec();
    }
    let rooted = path[0] == b'/';
    let n = path.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if path[r] == b'/' || (path[r] == b'.' && (r + 1 == n || path[r + 1] == b'/')) {
            r += 1; // empty or "." element
        } else if path[r] == b'.' && path[r + 1] == b'.' && (r + 2 == n || path[r + 2] == b'/') {
            r += 2;
            if out.len() > dotdot {
                // Drop the last element: back up to the separator that opens it.
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && path[r] != b'/' {
                out.push(path[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return b".".to_vec();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_matches_reference() {
        for (i, o) in [
            ("a/../../b", "../b"),
            ("/../a", "/a"),
            ("", "."),
            ("a//b/./c/", "a/b/c"),
            ("..", ".."),
            ("/", "/"),
            ("//a", "/a"),
            ("a/b/..", "a"),
            ("../..", "../.."),
            ("/a/b/../../..", "/"),
            ("./a", "a"),
            ("x/a/../b", "x/b"),
            ("mailto:..///b/..", "mailto:.."),
            ("a/b/c/../../d", "a/d"),
            ("//1.2.3.4.5/a/../b", "/1.2.3.4.5/b"),
        ] {
            assert_eq!(normalize_path(i.as_bytes()), o.as_bytes(), "{i}");
        }
    }
}
