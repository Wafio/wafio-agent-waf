//! RE2 syntax (Perl flavour) as far as the WAF agent needs it: `parse` (which patterns are
//! accepted, with fixed error text), `simplify` and the instruction count of the compiled
//! program (`program_size`, the rule regex budget). `CompiledRegex::compile` parses every
//! pattern here first and hands the regex crate an explicit pattern written from the syntax
//! tree ([`to_rust_pattern`]), so accept/reject and match semantics do not depend on the
//! regex crate's reading of the pattern text.
//!
//! Nodes are owned and moved (`std::mem::take`), never shared: no node sits in two places of
//! the final tree.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::CodePoint;
use crate::unicode::next_case_fold_equivalent;

const MAX_CODE_POINT: CodePoint = 0x10FFFF;

// Flags.
const CASE_INSENSITIVE: u16 = 1;
const CLASS_MATCHES_NEWLINE: u16 = 1 << 2;
const DOT_MATCHES_NEWLINE: u16 = 1 << 3;
const ANCHORS_AT_TEXT_ONLY: u16 = 1 << 4;
const LAZY: u16 = 1 << 5;
const PERL_EXTENSIONS: u16 = 1 << 6;
const UNICODE_CLASS_ESCAPES: u16 = 1 << 7;
const ENDED_WITH_DOLLAR: u16 = 1 << 8;
const PERL_SYNTAX: u16 =
    CLASS_MATCHES_NEWLINE | ANCHORS_AT_TEXT_ONLY | PERL_EXTENSIONS | UNICODE_CLASS_ESCAPES;

const MAX_NESTING_DEPTH: usize = 1000;
const MIN_FOLDABLE_CODE_POINT: CodePoint = 0x0041;
const MAX_FOLDABLE_CODE_POINT: CodePoint = 0x1e943;

// Error codes.
const REASON_INVALID_CHAR_RANGE: &str = "invalid character class range";
const REASON_INVALID_ESCAPE: &str = "invalid escape sequence";
const REASON_INVALID_NAMED_CAPTURE: &str = "invalid named capture";
const REASON_INVALID_PERL_OP: &str = "invalid or unsupported Perl syntax";
const REASON_INVALID_REPEAT_OP: &str = "invalid nested repetition operator";
const REASON_INVALID_REPEAT_SIZE: &str = "invalid repeat count";
const REASON_MISSING_BRACKET: &str = "missing closing ]";
const REASON_MISSING_PAREN: &str = "missing closing )";
const REASON_MISSING_REPEAT_ARGUMENT: &str = "missing argument to repetition operator";
const REASON_TRAILING_BACKSLASH: &str = "trailing backslash at end of expression";
const REASON_UNEXPECTED_PAREN: &str = "unexpected )";
const REASON_NESTING_DEPTH: &str = "expression nests too deeply";

fn error_message(code: &str, expr: &str) -> String {
    format!("error parsing regexp: {code}: `{expr}`")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NodeKind {
    NoMatch = 1,
    EmptyMatch,
    Literal,
    CharClass,
    AnyCharNotNewline,
    AnyChar,
    BeginLine,
    EndLine,
    BeginText,
    EndText,
    WordBoundary,
    NoWordBoundary,
    Capture,
    Star,
    Plus,
    Optional,
    Repeat,
    Concat,
    Alternate,
    LeftParen = 128,
    VerticalBar,
}

#[derive(Clone, Debug)]
struct SyntaxNode {
    kind: NodeKind,
    flags: u16,
    children: Vec<SyntaxNode>,
    code_points: Vec<CodePoint>,
    min: i32,
    max: i32,
    capture_index: i32,
    name: String,
}

impl Default for SyntaxNode {
    fn default() -> SyntaxNode {
        SyntaxNode::new(NodeKind::EmptyMatch)
    }
}

impl SyntaxNode {
    fn new(op: NodeKind) -> SyntaxNode {
        SyntaxNode {
            kind: op,
            flags: 0,
            children: Vec::new(),
            code_points: Vec::new(),
            min: 0,
            max: 0,
            capture_index: 0,
            name: String::new(),
        }
    }

    fn equal(&self, y: &SyntaxNode) -> bool {
        if self.kind != y.kind {
            return false;
        }
        match self.kind {
            NodeKind::EndText => self.flags & ENDED_WITH_DOLLAR == y.flags & ENDED_WITH_DOLLAR,
            NodeKind::Literal | NodeKind::CharClass => {
                self.flags & CASE_INSENSITIVE == y.flags & CASE_INSENSITIVE
                    && self.code_points == y.code_points
            }
            NodeKind::Alternate | NodeKind::Concat => {
                self.children.len() == y.children.len()
                    && self
                        .children
                        .iter()
                        .zip(&y.children)
                        .all(|(a, b)| a.equal(b))
            }
            NodeKind::Star | NodeKind::Plus | NodeKind::Optional => {
                self.flags & LAZY == y.flags & LAZY && self.children[0].equal(&y.children[0])
            }
            NodeKind::Repeat => {
                self.flags & LAZY == y.flags & LAZY
                    && self.min == y.min
                    && self.max == y.max
                    && self.children[0].equal(&y.children[0])
            }
            NodeKind::Capture => {
                self.capture_index == y.capture_index
                    && self.name == y.name
                    && self.children[0].equal(&y.children[0])
            }
            _ => true,
        }
    }
}

struct Parser<'a> {
    flags: u16,
    stack: Vec<SyntaxNode>,
    capture_count: i32,
    whole: &'a str,
    node_count: usize,
}

fn next_code_point(t: &str) -> (CodePoint, &str) {
    // An empty string gives (U+FFFD, 0), which is not an error.
    match t.chars().next() {
        Some(c) => (c as CodePoint, &t[c.len_utf8()..]),
        None => (0xFFFD, t),
    }
}

fn is_ascii_alphanumeric(c: CodePoint) -> bool {
    (b'0' as CodePoint..=b'9' as CodePoint).contains(&c)
        || (b'A' as CodePoint..=b'Z' as CodePoint).contains(&c)
        || (b'a' as CodePoint..=b'z' as CodePoint).contains(&c)
}

fn hex_digit_value(c: CodePoint) -> CodePoint {
    match u8::try_from(c) {
        Ok(b @ b'0'..=b'9') => (b - b'0') as CodePoint,
        Ok(b @ b'a'..=b'f') => (b - b'a' + 10) as CodePoint,
        Ok(b @ b'A'..=b'F') => (b - b'A' + 10) as CodePoint,
        _ => -1,
    }
}

fn is_char_class(re: &SyntaxNode) -> bool {
    re.kind == NodeKind::Literal && re.code_points.len() == 1
        || matches!(
            re.kind,
            NodeKind::CharClass | NodeKind::AnyCharNotNewline | NodeKind::AnyChar
        )
}

fn matches_code_point(re: &SyntaxNode, r: CodePoint) -> bool {
    match re.kind {
        NodeKind::Literal => re.code_points.len() == 1 && re.code_points[0] == r,
        NodeKind::CharClass => re.code_points.chunks(2).any(|p| p[0] <= r && r <= p[1]),
        NodeKind::AnyCharNotNewline => r != '\n' as CodePoint,
        NodeKind::AnyChar => true,
        _ => false,
    }
}

fn min_fold_code_point(r: CodePoint) -> CodePoint {
    if !(MIN_FOLDABLE_CODE_POINT..=MAX_FOLDABLE_CODE_POINT).contains(&r) {
        return r;
    }
    let (mut m, r0) = (r, r);
    let mut r = next_case_fold_equivalent(r);
    while r != r0 {
        m = m.min(r);
        r = next_case_fold_equivalent(r);
    }
    m
}

fn repeat_is_valid(re: &SyntaxNode, mut n: i32) -> bool {
    if re.kind == NodeKind::Repeat {
        let mut m = re.max;
        if m == 0 {
            return true;
        }
        if m < 0 {
            m = re.min;
        }
        if m > n {
            return false;
        }
        if m > 0 {
            n /= m;
        }
    }
    re.children.iter().all(|s| repeat_is_valid(s, n))
}

fn nesting_depth(re: &SyntaxNode) -> usize {
    1 + re.children.iter().map(nesting_depth).max().unwrap_or(0)
}

fn normalize_alternation(re: &mut SyntaxNode) {
    if re.kind == NodeKind::CharClass {
        normalize_class_ranges(&mut re.code_points);
        if re.code_points == [0, MAX_CODE_POINT] {
            re.code_points.clear();
            re.kind = NodeKind::AnyChar;
        } else if re.code_points
            == [
                0,
                '\n' as CodePoint - 1,
                '\n' as CodePoint + 1,
                MAX_CODE_POINT,
            ]
        {
            re.code_points.clear();
            re.kind = NodeKind::AnyCharNotNewline;
        }
    }
}

fn merge_char_class(dst: &mut SyntaxNode, src: &SyntaxNode) {
    match dst.kind {
        NodeKind::AnyChar => {}
        NodeKind::AnyCharNotNewline if matches_code_point(src, '\n' as CodePoint) => {
            dst.kind = NodeKind::AnyChar;
        }
        NodeKind::CharClass => {
            if src.kind == NodeKind::Literal {
                append_literal(&mut dst.code_points, src.code_points[0], src.flags);
            } else {
                append_class(&mut dst.code_points, &src.code_points);
            }
        }
        NodeKind::Literal => {
            if src.code_points[0] == dst.code_points[0] && src.flags == dst.flags {
                return;
            }
            dst.kind = NodeKind::CharClass;
            let first = dst.code_points[0];
            dst.code_points.clear();
            append_literal(&mut dst.code_points, first, dst.flags);
            append_literal(&mut dst.code_points, src.code_points[0], src.flags);
        }
        _ => {}
    }
}

fn leading_string(re: &SyntaxNode) -> (Vec<CodePoint>, u16) {
    let re = if re.kind == NodeKind::Concat && !re.children.is_empty() {
        &re.children[0]
    } else {
        re
    };
    if re.kind != NodeKind::Literal {
        return (Vec::new(), 0);
    }
    (re.code_points.clone(), re.flags & CASE_INSENSITIVE)
}

fn remove_leading_string(mut re: SyntaxNode, n: usize) -> SyntaxNode {
    if re.kind == NodeKind::Concat && !re.children.is_empty() {
        let sub = remove_leading_string(std::mem::take(&mut re.children[0]), n);
        let empty = sub.kind == NodeKind::EmptyMatch;
        re.children[0] = sub;
        if empty {
            match re.children.len() {
                0 | 1 => {
                    re.kind = NodeKind::EmptyMatch;
                    re.children.clear();
                }
                2 => return re.children.remove(1),
                _ => {
                    re.children.remove(0);
                }
            }
        }
        return re;
    }
    if re.kind == NodeKind::Literal {
        re.code_points.drain(..n.min(re.code_points.len()));
        if re.code_points.is_empty() {
            re.kind = NodeKind::EmptyMatch;
        }
    }
    re
}

fn leading_node(re: &SyntaxNode) -> Option<&SyntaxNode> {
    if re.kind == NodeKind::EmptyMatch {
        return None;
    }
    if re.kind == NodeKind::Concat && !re.children.is_empty() {
        let sub = &re.children[0];
        if sub.kind == NodeKind::EmptyMatch {
            return None;
        }
        return Some(sub);
    }
    Some(re)
}

fn remove_leading_node(mut re: SyntaxNode) -> SyntaxNode {
    if re.kind == NodeKind::Concat && !re.children.is_empty() {
        re.children.remove(0);
        match re.children.len() {
            0 => {
                re.kind = NodeKind::EmptyMatch;
                re.children.clear();
            }
            1 => return re.children.pop().unwrap(),
            _ => {}
        }
        return re;
    }
    SyntaxNode::new(NodeKind::EmptyMatch)
}

impl<'a> Parser<'a> {
    fn new_node(&mut self, op: NodeKind) -> SyntaxNode {
        self.node_count += 1;
        SyntaxNode::new(op)
    }

    /// Rejects expressions nested deeper than the limit. The "expression too large" size check
    /// is not modelled (shortcut: it needs a program over 3.3M instructions, far past the 256
    /// rule budget and the 500-byte path exception cap; such a pattern is rejected here only
    /// later or with another text).
    fn check_nesting_depth(&self, re: &SyntaxNode) -> Result<(), String> {
        if self.node_count >= MAX_NESTING_DEPTH && nesting_depth(re) > MAX_NESTING_DEPTH {
            return Err(error_message(REASON_NESTING_DEPTH, self.whole));
        }
        Ok(())
    }

    fn push(&mut self, mut re: SyntaxNode) -> Result<(), String> {
        let sf = next_case_fold_equivalent;
        let r = &re.code_points;
        if re.kind == NodeKind::CharClass && r.len() == 2 && r[0] == r[1] {
            if self.merge_literal_run(r[0], self.flags & !CASE_INSENSITIVE) {
                return Ok(());
            }
            re.kind = NodeKind::Literal;
            re.code_points.truncate(1);
            re.flags = self.flags & !CASE_INSENSITIVE;
        } else if re.kind == NodeKind::CharClass
            && (r.len() == 4
                && r[0] == r[1]
                && r[2] == r[3]
                && sf(r[0]) == r[2]
                && sf(r[2]) == r[0]
                || r.len() == 2 && r[0] + 1 == r[1] && sf(r[0]) == r[1] && sf(r[1]) == r[0])
        {
            if self.merge_literal_run(r[0], self.flags | CASE_INSENSITIVE) {
                return Ok(());
            }
            re.kind = NodeKind::Literal;
            re.code_points.truncate(1);
            re.flags = self.flags | CASE_INSENSITIVE;
        } else {
            self.merge_literal_run(-1, 0);
        }
        self.check_nesting_depth(&re)?;
        self.stack.push(re);
        Ok(())
    }

    fn merge_literal_run(&mut self, r: CodePoint, flags: u16) -> bool {
        let n = self.stack.len();
        if n < 2 {
            return false;
        }
        let (re1, re2) = (&self.stack[n - 1], &self.stack[n - 2]);
        if re1.kind != NodeKind::Literal
            || re2.kind != NodeKind::Literal
            || re1.flags & CASE_INSENSITIVE != re2.flags & CASE_INSENSITIVE
        {
            return false;
        }
        let appended = re1.code_points.clone();
        self.stack[n - 2].code_points.extend(appended);
        if r >= 0 {
            let re1 = &mut self.stack[n - 1];
            re1.code_points = vec![r];
            re1.flags = flags;
            return true;
        }
        self.stack.pop();
        false
    }

    fn literal(&mut self, mut r: CodePoint) -> Result<(), String> {
        let mut re = self.new_node(NodeKind::Literal);
        re.flags = self.flags;
        if self.flags & CASE_INSENSITIVE != 0 {
            r = min_fold_code_point(r);
        }
        re.code_points = vec![r];
        self.push(re)
    }

    fn op(&mut self, op: NodeKind) -> Result<&mut SyntaxNode, String> {
        let mut re = self.new_node(op);
        re.flags = self.flags;
        self.push(re)?;
        Ok(self.stack.last_mut().unwrap())
    }

    fn repeat<'s>(
        &mut self,
        op: NodeKind,
        min: i32,
        max: i32,
        before: &'s str,
        mut after: &'s str,
        last_repeat: &str,
    ) -> Result<&'s str, String> {
        let mut flags = self.flags;
        if after.starts_with('?') {
            after = &after[1..];
            flags ^= LAZY;
        }
        if !last_repeat.is_empty() {
            return Err(error_message(
                REASON_INVALID_REPEAT_OP,
                &last_repeat[..last_repeat.len() - after.len()],
            ));
        }
        let missing = || {
            error_message(
                REASON_MISSING_REPEAT_ARGUMENT,
                &before[..before.len() - after.len()],
            )
        };
        let Some(top) = self.stack.last() else {
            return Err(missing());
        };
        if top.kind >= NodeKind::LeftParen {
            return Err(missing());
        }
        let sub = self.stack.pop().unwrap();
        let mut re = self.new_node(op);
        re.min = min;
        re.max = max;
        re.flags = flags;
        re.children = vec![sub];
        self.check_nesting_depth(&re)?;
        let invalid =
            op == NodeKind::Repeat && (min >= 2 || max >= 2) && !repeat_is_valid(&re, 1000);
        self.stack.push(re);
        if invalid {
            return Err(error_message(
                REASON_INVALID_REPEAT_SIZE,
                &before[..before.len() - after.len()],
            ));
        }
        Ok(after)
    }

    fn pseudo_start(&self) -> usize {
        let mut i = self.stack.len();
        while i > 0 && self.stack[i - 1].kind < NodeKind::LeftParen {
            i -= 1;
        }
        i
    }

    fn concat(&mut self) -> Result<(), String> {
        self.merge_literal_run(-1, 0);
        let subs = self.stack.split_off(self.pseudo_start());
        if subs.is_empty() {
            let re = self.new_node(NodeKind::EmptyMatch);
            return self.push(re);
        }
        let re = self.collapse(subs, NodeKind::Concat)?;
        self.push(re)
    }

    fn alternate(&mut self) -> Result<(), String> {
        let mut subs = self.stack.split_off(self.pseudo_start());
        if let Some(last) = subs.last_mut() {
            normalize_alternation(last);
        }
        if subs.is_empty() {
            let re = self.new_node(NodeKind::NoMatch);
            return self.push(re);
        }
        let re = self.collapse(subs, NodeKind::Alternate)?;
        self.push(re)
    }

    fn collapse(&mut self, mut subs: Vec<SyntaxNode>, op: NodeKind) -> Result<SyntaxNode, String> {
        if subs.len() == 1 {
            return Ok(subs.pop().unwrap());
        }
        let mut re = self.new_node(op);
        for sub in subs {
            if sub.kind == op {
                re.children.extend(sub.children);
            } else {
                re.children.push(sub);
            }
        }
        if op == NodeKind::Alternate {
            re.children = self.factor(std::mem::take(&mut re.children))?;
            if re.children.len() == 1 {
                return Ok(re.children.pop().unwrap());
            }
        }
        Ok(re)
    }

    fn factor(&mut self, mut sub: Vec<SyntaxNode>) -> Result<Vec<SyntaxNode>, String> {
        if sub.len() < 2 {
            return Ok(sub);
        }
        // Round 1: common literal prefixes.
        let mut out = Vec::new();
        let (mut str_, mut strflags): (Vec<CodePoint>, u16) = (Vec::new(), 0);
        let mut start = 0;
        for i in 0..=sub.len() {
            let (mut istr, mut iflags) = (Vec::new(), 0);
            if i < sub.len() {
                (istr, iflags) = leading_string(&sub[i]);
                if iflags == strflags {
                    let same = str_.iter().zip(&istr).take_while(|(a, b)| a == b).count();
                    if same > 0 {
                        str_.truncate(same);
                        continue;
                    }
                }
            }
            if i == start {
            } else if i == start + 1 {
                out.push(std::mem::take(&mut sub[start]));
            } else {
                let mut prefix = self.new_node(NodeKind::Literal);
                prefix.flags = strflags;
                prefix.code_points = str_.clone();
                let mut run = Vec::with_capacity(i - start);
                for s in &mut sub[start..i] {
                    let r = remove_leading_string(std::mem::take(s), str_.len());
                    self.check_nesting_depth(&r)?;
                    run.push(r);
                }
                let suffix = self.collapse(run, NodeKind::Alternate)?;
                let mut re = self.new_node(NodeKind::Concat);
                re.children = vec![prefix, suffix];
                out.push(re);
            }
            start = i;
            str_ = istr;
            strflags = iflags;
        }
        let mut sub = out;

        // Round 2: common simple leading regexp (a char class or a fixed repeat of one).
        let mut out = Vec::new();
        let mut start = 0;
        let mut first: Option<SyntaxNode> = None;
        for i in 0..=sub.len() {
            let mut ifirst = None;
            if i < sub.len() {
                ifirst = leading_node(&sub[i]).cloned();
                if let (Some(f), Some(fi)) = (&first, &ifirst)
                    && f.equal(fi)
                    && (is_char_class(f)
                        || f.kind == NodeKind::Repeat
                            && f.min == f.max
                            && is_char_class(&f.children[0]))
                {
                    continue;
                }
            }
            if i == start {
            } else if i == start + 1 {
                out.push(std::mem::take(&mut sub[start]));
            } else {
                let prefix = first.clone().unwrap();
                let mut run = Vec::with_capacity(i - start);
                for s in &mut sub[start..i] {
                    let r = remove_leading_node(std::mem::take(s));
                    self.check_nesting_depth(&r)?;
                    run.push(r);
                }
                let suffix = self.collapse(run, NodeKind::Alternate)?;
                let mut re = self.new_node(NodeKind::Concat);
                re.children = vec![prefix, suffix];
                out.push(re);
            }
            start = i;
            first = ifirst;
        }
        let mut sub = out;

        // Round 3: runs of literal runes and classes become one class.
        let mut out = Vec::new();
        let mut start = 0;
        for i in 0..=sub.len() {
            if i < sub.len() && is_char_class(&sub[i]) {
                continue;
            }
            if i == start {
            } else if i == start + 1 {
                out.push(std::mem::take(&mut sub[start]));
            } else {
                let mut max = start;
                for j in start + 1..i {
                    if sub[max].kind < sub[j].kind
                        || sub[max].kind == sub[j].kind
                            && sub[max].code_points.len() < sub[j].code_points.len()
                    {
                        max = j;
                    }
                }
                sub.swap(start, max);
                let mut dst = std::mem::take(&mut sub[start]);
                for s in &sub[start + 1..i] {
                    merge_char_class(&mut dst, s);
                }
                normalize_alternation(&mut dst);
                out.push(dst);
            }
            if i < sub.len() {
                out.push(std::mem::take(&mut sub[i]));
            }
            start = i + 1;
        }
        let sub = out;

        // Round 4: collapse runs of empty matches into one.
        let n = sub.len();
        let mut out = Vec::with_capacity(n);
        let mut it = sub.into_iter().peekable();
        while let Some(x) = it.next() {
            if x.kind == NodeKind::EmptyMatch
                && it.peek().is_some_and(|y| y.kind == NodeKind::EmptyMatch)
            {
                continue;
            }
            out.push(x);
        }
        Ok(out)
    }

    fn parse_vertical_bar(&mut self) -> Result<(), String> {
        self.concat()?;
        if !self.swap_vertical_bar() {
            self.op(NodeKind::VerticalBar)?;
        }
        Ok(())
    }

    fn swap_vertical_bar(&mut self) -> bool {
        let n = self.stack.len();
        if n >= 3
            && self.stack[n - 2].kind == NodeKind::VerticalBar
            && is_char_class(&self.stack[n - 1])
            && is_char_class(&self.stack[n - 3])
        {
            let mut re1 = self.stack.pop().unwrap();
            if re1.kind > self.stack[n - 3].kind {
                std::mem::swap(&mut re1, &mut self.stack[n - 3]);
            }
            merge_char_class(&mut self.stack[n - 3], &re1);
            return true;
        }
        if n >= 2 && self.stack[n - 2].kind == NodeKind::VerticalBar {
            if n >= 3 {
                normalize_alternation(&mut self.stack[n - 3]);
            }
            self.stack.swap(n - 2, n - 1);
            return true;
        }
        false
    }

    fn parse_right_paren(&mut self) -> Result<(), String> {
        self.concat()?;
        if self.swap_vertical_bar() {
            self.stack.pop();
        }
        self.alternate()?;
        if self.stack.len() < 2 {
            return Err(error_message(REASON_UNEXPECTED_PAREN, self.whole));
        }
        let re1 = self.stack.pop().unwrap();
        let mut re2 = self.stack.pop().unwrap();
        if re2.kind != NodeKind::LeftParen {
            return Err(error_message(REASON_UNEXPECTED_PAREN, self.whole));
        }
        self.flags = re2.flags;
        if re2.capture_index == 0 {
            self.push(re1)
        } else {
            re2.kind = NodeKind::Capture;
            re2.children = vec![re1];
            self.push(re2)
        }
    }

    fn parse_perl_flags<'s>(&mut self, s: &'s str) -> Result<&'s str, String> {
        let b = s.as_bytes();
        let starts_with_p = b.len() > 4 && b[2] == b'P' && b[3] == b'<';
        let starts_with_name = b.len() > 3 && b[2] == b'<';
        if starts_with_p || starts_with_name {
            let expr_start = if starts_with_name { 3 } else { 4 };
            let Some(end) = s.find('>') else {
                return Err(error_message(REASON_INVALID_NAMED_CAPTURE, s));
            };
            let (capture, name) = (&s[..end + 1], &s[expr_start..end]);
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c == '_' || is_ascii_alphanumeric(c as CodePoint))
            {
                return Err(error_message(REASON_INVALID_NAMED_CAPTURE, capture));
            }
            self.capture_count += 1;
            let cap = self.capture_count;
            let re = self.op(NodeKind::LeftParen)?;
            re.capture_index = cap;
            re.name = name.to_string();
            return Ok(&s[end + 1..]);
        }
        let mut t = &s[2..];
        let mut flags = self.flags;
        let mut sign = 1;
        let mut saw_flag = false;
        while !t.is_empty() {
            let (c, rest) = next_code_point(t);
            t = rest;
            match char::from_u32(c as u32).unwrap_or('\u{FFFD}') {
                'i' => {
                    flags |= CASE_INSENSITIVE;
                    saw_flag = true;
                }
                'm' => {
                    flags &= !ANCHORS_AT_TEXT_ONLY;
                    saw_flag = true;
                }
                's' => {
                    flags |= DOT_MATCHES_NEWLINE;
                    saw_flag = true;
                }
                'U' => {
                    flags |= LAZY;
                    saw_flag = true;
                }
                '-' => {
                    if sign < 0 {
                        break;
                    }
                    sign = -1;
                    flags = !flags;
                    saw_flag = false;
                }
                c @ (':' | ')') => {
                    if sign < 0 {
                        if !saw_flag {
                            break;
                        }
                        flags = !flags;
                    }
                    if c == ':' {
                        self.op(NodeKind::LeftParen)?;
                    }
                    self.flags = flags;
                    return Ok(t);
                }
                _ => break,
            }
        }
        Err(error_message(
            REASON_INVALID_PERL_OP,
            &s[..s.len() - t.len()],
        ))
    }

    fn parse_escape<'s>(&self, s: &'s str) -> Result<(CodePoint, &'s str), String> {
        let mut t = &s[1..];
        if t.is_empty() {
            return Err(error_message(REASON_TRAILING_BACKSLASH, ""));
        }
        let (c, rest) = next_code_point(t);
        t = rest;
        let octal = |t: &str| {
            t.as_bytes()
                .first()
                .is_some_and(|b| (b'0'..=b'7').contains(b))
        };
        'sw: {
            match u8::try_from(c) {
                Ok(b'1'..=b'7') | Ok(b'0') => {
                    if c != '0' as CodePoint && !octal(t) {
                        break 'sw;
                    }
                    let mut r = c - '0' as CodePoint;
                    for _ in 1..3 {
                        if !octal(t) {
                            break;
                        }
                        r = r * 8 + (t.as_bytes()[0] - b'0') as CodePoint;
                        t = &t[1..];
                    }
                    return Ok((r, t));
                }
                Ok(b'x') => {
                    if t.is_empty() {
                        break 'sw;
                    }
                    let (c, rest) = next_code_point(t);
                    t = rest;
                    if c == '{' as CodePoint {
                        let mut nhex = 0;
                        let mut r: CodePoint = 0;
                        loop {
                            if t.is_empty() {
                                break 'sw;
                            }
                            let (c, rest) = next_code_point(t);
                            t = rest;
                            if c == '}' as CodePoint {
                                break;
                            }
                            let v = hex_digit_value(c);
                            if v < 0 {
                                break 'sw;
                            }
                            r = r * 16 + v;
                            if r > MAX_CODE_POINT {
                                break 'sw;
                            }
                            nhex += 1;
                        }
                        if nhex == 0 {
                            break 'sw;
                        }
                        return Ok((r, t));
                    }
                    let x = hex_digit_value(c);
                    let (c, rest) = next_code_point(t);
                    t = rest;
                    let y = hex_digit_value(c);
                    if x < 0 || y < 0 {
                        break 'sw;
                    }
                    return Ok((x * 16 + y, t));
                }
                Ok(b'a') => return Ok((7, t)),
                Ok(b'f') => return Ok((12, t)),
                Ok(b'n') => return Ok((10, t)),
                Ok(b'r') => return Ok((13, t)),
                Ok(b't') => return Ok((9, t)),
                Ok(b'v') => return Ok((11, t)),
                _ => {
                    if c < 0x80 && !is_ascii_alphanumeric(c) {
                        return Ok((c, t));
                    }
                }
            }
        }
        Err(error_message(
            REASON_INVALID_ESCAPE,
            &s[..s.len() - t.len()],
        ))
    }

    fn parse_class_char<'s>(
        &self,
        s: &'s str,
        whole_class: &str,
    ) -> Result<(CodePoint, &'s str), String> {
        if s.is_empty() {
            return Err(error_message(REASON_MISSING_BRACKET, whole_class));
        }
        if s.starts_with('\\') {
            return self.parse_escape(s);
        }
        Ok(next_code_point(s))
    }

    fn parse_perl_class_escape<'s>(&self, s: &'s str, r: &mut Vec<CodePoint>) -> Option<&'s str> {
        let b = s.as_bytes();
        if b.len() < 2 || b[0] != b'\\' {
            return None;
        }
        let (sign, class): (i32, &[CodePoint]) = match b[1] {
            b'd' => (1, &[0x30, 0x39]),
            b'D' => (-1, &[0x30, 0x39]),
            b's' => (1, &[0x9, 0xa, 0xc, 0xd, 0x20, 0x20]),
            b'S' => (-1, &[0x9, 0xa, 0xc, 0xd, 0x20, 0x20]),
            b'w' => (1, &[0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a]),
            b'W' => (-1, &[0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a]),
            _ => return None,
        };
        self.append_group(r, sign, class);
        Some(&s[2..])
    }

    fn parse_named_class<'s>(
        &self,
        s: &'s str,
        r: &mut Vec<CodePoint>,
    ) -> Result<Option<&'s str>, String> {
        if !s.starts_with("[:") {
            return Ok(None);
        }
        let Some(i) = s[2..].find(":]") else {
            return Ok(None);
        };
        let i = i + 2;
        let (name, rest) = (&s[..i + 2], &s[i + 2..]);
        let (neg, base) = match name.strip_prefix("[:^") {
            Some(b) => (true, b),
            None => (false, &name[2..]),
        };
        let class: &[CodePoint] = match base {
            "alnum:]" => &[0x30, 0x39, 0x41, 0x5a, 0x61, 0x7a],
            "alpha:]" => &[0x41, 0x5a, 0x61, 0x7a],
            "ascii:]" => &[0x0, 0x7f],
            "blank:]" => &[0x9, 0x9, 0x20, 0x20],
            "cntrl:]" => &[0x0, 0x1f, 0x7f, 0x7f],
            "digit:]" => &[0x30, 0x39],
            "graph:]" => &[0x21, 0x7e],
            "lower:]" => &[0x61, 0x7a],
            "print:]" => &[0x20, 0x7e],
            "punct:]" => &[0x21, 0x2f, 0x3a, 0x40, 0x5b, 0x60, 0x7b, 0x7e],
            "space:]" => &[0x9, 0xd, 0x20, 0x20],
            "upper:]" => &[0x41, 0x5a],
            "word:]" => &[0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a],
            "xdigit:]" => &[0x30, 0x39, 0x41, 0x46, 0x61, 0x66],
            _ => return Err(error_message(REASON_INVALID_CHAR_RANGE, name)),
        };
        self.append_group(r, if neg { -1 } else { 1 }, class);
        Ok(Some(rest))
    }

    fn append_group(&self, r: &mut Vec<CodePoint>, sign: i32, class: &[CodePoint]) {
        if self.flags & CASE_INSENSITIVE == 0 {
            if sign < 0 {
                append_negated_class(r, class);
            } else {
                append_class(r, class);
            }
        } else {
            let mut tmp = Vec::new();
            for p in class.chunks(2) {
                append_folded_range(&mut tmp, p[0], p[1]);
            }
            normalize_class_ranges(&mut tmp);
            if sign < 0 {
                append_negated_class(r, &tmp);
            } else {
                append_class(r, &tmp);
            }
        }
    }

    fn parse_unicode_class<'s>(
        &mut self,
        s: &'s str,
        r: &mut Vec<CodePoint>,
    ) -> Result<Option<&'s str>, String> {
        let b = s.as_bytes();
        if self.flags & UNICODE_CLASS_ESCAPES == 0
            || b.len() < 2
            || b[0] != b'\\'
            || b[1] != b'p' && b[1] != b'P'
        {
            return Ok(None);
        }
        let mut sign = if b[1] == b'P' { -1 } else { 1 };
        let (c, mut t) = next_code_point(&s[2..]);
        let (seq, mut name);
        if c != '{' as CodePoint {
            seq = &s[..s.len() - t.len()];
            name = &seq[2..];
        } else {
            let Some(end) = s.find('}') else {
                return Err(error_message(REASON_INVALID_CHAR_RANGE, s));
            };
            seq = &s[..end + 1];
            t = &s[end + 1..];
            name = &s[3..end];
        }
        let caret = name.starts_with('^');
        if caret {
            sign = -sign;
            name = &name[1..];
        }
        let Some((tab, fold, tsign)) = unicode_table(name) else {
            return Err(error_message(REASON_INVALID_CHAR_RANGE, seq));
        };
        if tsign < 0 {
            sign = -sign;
        }
        match fold {
            Some(folded) if self.flags & CASE_INSENSITIVE != 0 => {
                if sign > 0 {
                    append_class(r, &folded);
                } else {
                    append_negated_class(r, &folded);
                }
            }
            _ => {
                if sign > 0 {
                    append_class(r, &tab);
                } else {
                    append_negated_class(r, &tab);
                }
            }
        }
        Ok(Some(t))
    }

    fn parse_class<'s>(&mut self, s: &'s str) -> Result<&'s str, String> {
        let mut t = &s[1..];
        let mut re = self.new_node(NodeKind::CharClass);
        re.flags = self.flags;
        let mut class: Vec<CodePoint> = Vec::new();
        let mut sign = 1;
        if t.starts_with('^') {
            sign = -1;
            t = &t[1..];
            if self.flags & CLASS_MATCHES_NEWLINE == 0 {
                class.extend(['\n' as CodePoint, '\n' as CodePoint]);
            }
        }
        let mut first = true;
        while t.is_empty() || !t.starts_with(']') || first {
            first = false;
            if t.len() > 2
                && t.starts_with("[:")
                && let Some(nt) = self.parse_named_class(t, &mut class)?
            {
                t = nt;
                continue;
            }
            if let Some(nt) = self.parse_unicode_class(t, &mut class)? {
                t = nt;
                continue;
            }
            if let Some(nt) = self.parse_perl_class_escape(t, &mut class) {
                t = nt;
                continue;
            }
            let rng = t;
            let (lo, nt) = self.parse_class_char(t, s)?;
            t = nt;
            let mut hi = lo;
            let tb = t.as_bytes();
            if tb.len() >= 2 && tb[0] == b'-' && tb[1] != b']' {
                t = &t[1..];
                let (h, nt) = self.parse_class_char(t, s)?;
                hi = h;
                t = nt;
                if hi < lo {
                    return Err(error_message(
                        REASON_INVALID_CHAR_RANGE,
                        &rng[..rng.len() - t.len()],
                    ));
                }
            }
            if self.flags & CASE_INSENSITIVE == 0 {
                append_range(&mut class, lo, hi);
            } else {
                append_folded_range(&mut class, lo, hi);
            }
        }
        t = &t[1..];
        normalize_class_ranges(&mut class);
        if sign < 0 {
            negate_class(&mut class);
        }
        re.code_points = class;
        self.push(re)?;
        Ok(t)
    }

    fn parse_backslash<'s>(&mut self, t: &'s str) -> Result<&'s str, String> {
        let b = t.as_bytes();
        if b.len() >= 2 {
            match b[1] {
                b'A' => return self.op(NodeKind::BeginText).map(|_| &t[2..]),
                b'b' => return self.op(NodeKind::WordBoundary).map(|_| &t[2..]),
                b'B' => return self.op(NodeKind::NoWordBoundary).map(|_| &t[2..]),
                b'C' => return Err(error_message(REASON_INVALID_ESCAPE, &t[..2])),
                b'Q' => {
                    let rest = &t[2..];
                    let (lit, after) = match rest.find("\\E") {
                        Some(i) => (&rest[..i], &rest[i + 2..]),
                        None => (rest, ""),
                    };
                    for c in lit.chars() {
                        self.literal(c as CodePoint)?;
                    }
                    return Ok(after);
                }
                b'z' => return self.op(NodeKind::EndText).map(|_| &t[2..]),
                _ => {}
            }
        }
        let mut class = Vec::new();
        if b.len() >= 2
            && (b[1] == b'p' || b[1] == b'P')
            && let Some(rest) = self.parse_unicode_class(t, &mut class)?
        {
            let mut re = self.new_node(NodeKind::CharClass);
            re.flags = self.flags;
            re.code_points = class;
            self.push(re)?;
            return Ok(rest);
        }
        if let Some(rest) = self.parse_perl_class_escape(t, &mut class) {
            let mut re = self.new_node(NodeKind::CharClass);
            re.flags = self.flags;
            re.code_points = class;
            self.push(re)?;
            return Ok(rest);
        }
        let (c, rest) = self.parse_escape(t)?;
        self.literal(c)?;
        Ok(rest)
    }

    fn parse_repeat<'s>(&self, s: &'s str) -> Option<(i32, i32, &'s str)> {
        let s = s.strip_prefix('{')?;
        let (mut min, mut s) = parse_int(s)?;
        let max;
        if s.is_empty() {
            return None;
        }
        if !s.starts_with(',') {
            max = min;
        } else {
            s = &s[1..];
            if s.is_empty() {
                return None;
            }
            if s.starts_with('}') {
                max = -1;
            } else {
                let (m, rest) = parse_int(s)?;
                s = rest;
                max = m;
                if max < 0 {
                    min = -1;
                }
            }
        }
        let rest = s.strip_prefix('}')?;
        Some((min, max, rest))
    }
}

fn parse_int(s: &str) -> Option<(i32, &str)> {
    let b = s.as_bytes();
    if b.is_empty() || !b[0].is_ascii_digit() {
        return None;
    }
    if b.len() >= 2 && b[0] == b'0' && b[1].is_ascii_digit() {
        return None;
    }
    let k = b.iter().take_while(|c| c.is_ascii_digit()).count();
    let mut n: i32 = 0;
    for &d in &b[..k] {
        if n >= 100_000_000 {
            n = -1;
            break;
        }
        n = n * 10 + (d - b'0') as i32;
    }
    Some((n, &s[k..]))
}

fn parse(s: &str) -> Result<SyntaxNode, String> {
    let mut p = Parser {
        flags: PERL_SYNTAX,
        stack: Vec::new(),
        capture_count: 0,
        whole: s,
        node_count: 0,
    };
    let mut t = s;
    let mut last_repeat: &str = "";
    while !t.is_empty() {
        let mut repeat = "";
        match t.as_bytes()[0] {
            b'(' => {
                if t.len() >= 2 && t.as_bytes()[1] == b'?' {
                    t = p.parse_perl_flags(t)?;
                } else {
                    p.capture_count += 1;
                    let cap = p.capture_count;
                    p.op(NodeKind::LeftParen)?.capture_index = cap;
                    t = &t[1..];
                }
            }
            b'|' => {
                p.parse_vertical_bar()?;
                t = &t[1..];
            }
            b')' => {
                p.parse_right_paren()?;
                t = &t[1..];
            }
            b'^' => {
                p.op(if p.flags & ANCHORS_AT_TEXT_ONLY != 0 {
                    NodeKind::BeginText
                } else {
                    NodeKind::BeginLine
                })?;
                t = &t[1..];
            }
            b'$' => {
                if p.flags & ANCHORS_AT_TEXT_ONLY != 0 {
                    p.op(NodeKind::EndText)?.flags |= ENDED_WITH_DOLLAR;
                } else {
                    p.op(NodeKind::EndLine)?;
                }
                t = &t[1..];
            }
            b'.' => {
                p.op(if p.flags & DOT_MATCHES_NEWLINE != 0 {
                    NodeKind::AnyChar
                } else {
                    NodeKind::AnyCharNotNewline
                })?;
                t = &t[1..];
            }
            b'[' => t = p.parse_class(t)?,
            c @ (b'*' | b'+' | b'?') => {
                let before = t;
                let op = match c {
                    b'*' => NodeKind::Star,
                    b'+' => NodeKind::Plus,
                    _ => NodeKind::Optional,
                };
                let after = p.repeat(op, 0, 0, before, &t[1..], last_repeat)?;
                repeat = before;
                t = after;
            }
            b'{' => {
                let before = t;
                match p.parse_repeat(t) {
                    None => {
                        p.literal('{' as CodePoint)?;
                        t = &t[1..];
                    }
                    Some((min, max, after)) => {
                        if !(0..=1000).contains(&min) || max > 1000 || max >= 0 && min > max {
                            return Err(error_message(
                                REASON_INVALID_REPEAT_SIZE,
                                &before[..before.len() - after.len()],
                            ));
                        }
                        let after =
                            p.repeat(NodeKind::Repeat, min, max, before, after, last_repeat)?;
                        repeat = before;
                        t = after;
                    }
                }
            }
            b'\\' => t = p.parse_backslash(t)?,
            _ => {
                let (c, rest) = next_code_point(t);
                p.literal(c)?;
                t = rest;
            }
        }
        last_repeat = repeat;
    }
    p.concat()?;
    if p.swap_vertical_bar() {
        p.stack.pop();
    }
    p.alternate()?;
    if p.stack.len() != 1 {
        return Err(error_message(REASON_MISSING_PAREN, s));
    }
    Ok(p.stack.pop().unwrap())
}

// ---- character classes ------------------------------------------------------------------

fn normalize_class_ranges(r: &mut Vec<CodePoint>) {
    let mut pairs: Vec<(CodePoint, CodePoint)> = r.chunks(2).map(|p| (p[0], p[1])).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    r.clear();
    for (lo, hi) in pairs {
        if let Some(last) = r.last_mut()
            && lo <= *last + 1
        {
            if hi > *last {
                *last = hi;
            }
            continue;
        }
        r.extend([lo, hi]);
    }
}

fn append_literal(r: &mut Vec<CodePoint>, x: CodePoint, flags: u16) {
    if flags & CASE_INSENSITIVE != 0 {
        append_folded_range(r, x, x);
    } else {
        append_range(r, x, x);
    }
}

fn append_range(r: &mut Vec<CodePoint>, lo: CodePoint, hi: CodePoint) {
    let n = r.len();
    for i in [2, 4] {
        if n >= i {
            let (rlo, rhi) = (r[n - i], r[n - i + 1]);
            if lo <= rhi + 1 && rlo <= hi + 1 {
                if lo < rlo {
                    r[n - i] = lo;
                }
                if hi > rhi {
                    r[n - i + 1] = hi;
                }
                return;
            }
        }
    }
    r.extend([lo, hi]);
}

fn append_folded_range(r: &mut Vec<CodePoint>, mut lo: CodePoint, mut hi: CodePoint) {
    if lo <= MIN_FOLDABLE_CODE_POINT && hi >= MAX_FOLDABLE_CODE_POINT
        || hi < MIN_FOLDABLE_CODE_POINT
        || lo > MAX_FOLDABLE_CODE_POINT
    {
        append_range(r, lo, hi);
        return;
    }
    if lo < MIN_FOLDABLE_CODE_POINT {
        append_range(r, lo, MIN_FOLDABLE_CODE_POINT - 1);
        lo = MIN_FOLDABLE_CODE_POINT;
    }
    if hi > MAX_FOLDABLE_CODE_POINT {
        append_range(r, MAX_FOLDABLE_CODE_POINT + 1, hi);
        hi = MAX_FOLDABLE_CODE_POINT;
    }
    for c in lo..=hi {
        append_range(r, c, c);
        let mut f = next_case_fold_equivalent(c);
        while f != c {
            append_range(r, f, f);
            f = next_case_fold_equivalent(f);
        }
    }
}

fn append_class(r: &mut Vec<CodePoint>, x: &[CodePoint]) {
    for p in x.chunks(2) {
        append_range(r, p[0], p[1]);
    }
}

fn append_negated_class(r: &mut Vec<CodePoint>, x: &[CodePoint]) {
    let mut next_lo: CodePoint = 0;
    for p in x.chunks(2) {
        if next_lo < p[0] {
            append_range(r, next_lo, p[0] - 1);
        }
        next_lo = p[1] + 1;
    }
    if next_lo <= MAX_CODE_POINT {
        append_range(r, next_lo, MAX_CODE_POINT);
    }
}

fn negate_class(r: &mut Vec<CodePoint>) {
    let src = std::mem::take(r);
    let mut next_lo: CodePoint = 0;
    for p in src.chunks(2) {
        if next_lo < p[0] {
            r.extend([next_lo, p[0] - 1]);
        }
        next_lo = p[1] + 1;
    }
    if next_lo <= MAX_CODE_POINT {
        r.extend([next_lo, MAX_CODE_POINT]);
    }
}

// ---- Unicode tables ---------------------------------------------------------------------

const CATEGORIES: &[&str] = &[
    "C", "Cc", "Cf", "Cn", "Co", "Cs", "L", "LC", "Ll", "Lm", "Lo", "Lt", "Lu", "M", "Mc", "Me",
    "Mn", "N", "Nd", "Nl", "No", "P", "Pc", "Pd", "Pe", "Pf", "Pi", "Po", "Ps", "S", "Sc", "Sk",
    "Sm", "So", "Z", "Zl", "Zp", "Zs",
];
const FOLD_CATEGORIES: &[&str] = &["L", "Ll", "Lt", "Lu", "M", "Mn"];
const FOLD_SCRIPTS: &[&str] = &["Common", "Greek", "Inherited"];
/// Script names (Unicode 15.0.0). Only names that are already canonical can match: the
/// canonical name (`Old_Italic` → `Olditalic`) is looked up in this list as is.
const SCRIPTS: &[&str] = &[
    "Adlam",
    "Ahom",
    "Anatolian_Hieroglyphs",
    "Arabic",
    "Armenian",
    "Avestan",
    "Balinese",
    "Bamum",
    "Bassa_Vah",
    "Batak",
    "Bengali",
    "Bhaiksuki",
    "Bopomofo",
    "Brahmi",
    "Braille",
    "Buginese",
    "Buhid",
    "Canadian_Aboriginal",
    "Carian",
    "Caucasian_Albanian",
    "Chakma",
    "Cham",
    "Cherokee",
    "Chorasmian",
    "Common",
    "Coptic",
    "Cuneiform",
    "Cypriot",
    "Cypro_Minoan",
    "Cyrillic",
    "Deseret",
    "Devanagari",
    "Dives_Akuru",
    "Dogra",
    "Duployan",
    "Egyptian_Hieroglyphs",
    "Elbasan",
    "Elymaic",
    "Ethiopic",
    "Georgian",
    "Glagolitic",
    "Gothic",
    "Grantha",
    "Greek",
    "Gujarati",
    "Gunjala_Gondi",
    "Gurmukhi",
    "Han",
    "Hangul",
    "Hanifi_Rohingya",
    "Hanunoo",
    "Hatran",
    "Hebrew",
    "Hiragana",
    "Imperial_Aramaic",
    "Inherited",
    "Inscriptional_Pahlavi",
    "Inscriptional_Parthian",
    "Javanese",
    "Kaithi",
    "Kannada",
    "Katakana",
    "Kawi",
    "Kayah_Li",
    "Kharoshthi",
    "Khitan_Small_Script",
    "Khmer",
    "Khojki",
    "Khudawadi",
    "Lao",
    "Latin",
    "Lepcha",
    "Limbu",
    "Linear_A",
    "Linear_B",
    "Lisu",
    "Lycian",
    "Lydian",
    "Mahajani",
    "Makasar",
    "Malayalam",
    "Mandaic",
    "Manichaean",
    "Marchen",
    "Masaram_Gondi",
    "Medefaidrin",
    "Meetei_Mayek",
    "Mende_Kikakui",
    "Meroitic_Cursive",
    "Meroitic_Hieroglyphs",
    "Miao",
    "Modi",
    "Mongolian",
    "Mro",
    "Multani",
    "Myanmar",
    "Nabataean",
    "Nag_Mundari",
    "Nandinagari",
    "New_Tai_Lue",
    "Newa",
    "Nko",
    "Nushu",
    "Nyiakeng_Puachue_Hmong",
    "Ogham",
    "Ol_Chiki",
    "Old_Hungarian",
    "Old_Italic",
    "Old_North_Arabian",
    "Old_Permic",
    "Old_Persian",
    "Old_Sogdian",
    "Old_South_Arabian",
    "Old_Turkic",
    "Old_Uyghur",
    "Oriya",
    "Osage",
    "Osmanya",
    "Pahawh_Hmong",
    "Palmyrene",
    "Pau_Cin_Hau",
    "Phags_Pa",
    "Phoenician",
    "Psalter_Pahlavi",
    "Rejang",
    "Runic",
    "Samaritan",
    "Saurashtra",
    "Sharada",
    "Shavian",
    "Siddham",
    "SignWriting",
    "Sinhala",
    "Sogdian",
    "Sora_Sompeng",
    "Soyombo",
    "Sundanese",
    "Syloti_Nagri",
    "Syriac",
    "Tagalog",
    "Tagbanwa",
    "Tai_Le",
    "Tai_Tham",
    "Tai_Viet",
    "Takri",
    "Tamil",
    "Tangsa",
    "Tangut",
    "Telugu",
    "Thaana",
    "Thai",
    "Tibetan",
    "Tifinagh",
    "Tirhuta",
    "Toto",
    "Ugaritic",
    "Vai",
    "Vithkuqi",
    "Wancho",
    "Warang_Citi",
    "Yezidi",
    "Yi",
    "Zanabazar_Square",
];
const CATEGORY_ALIASES: &[(&str, &str)] = &[
    ("Cased_Letter", "LC"),
    ("Close_Punctuation", "Pe"),
    ("Combining_Mark", "M"),
    ("Connector_Punctuation", "Pc"),
    ("Control", "Cc"),
    ("Currency_Symbol", "Sc"),
    ("Dash_Punctuation", "Pd"),
    ("Decimal_Number", "Nd"),
    ("Enclosing_Mark", "Me"),
    ("Final_Punctuation", "Pf"),
    ("Format", "Cf"),
    ("Initial_Punctuation", "Pi"),
    ("Letter", "L"),
    ("Letter_Number", "Nl"),
    ("Line_Separator", "Zl"),
    ("Lowercase_Letter", "Ll"),
    ("Mark", "M"),
    ("Math_Symbol", "Sm"),
    ("Modifier_Letter", "Lm"),
    ("Modifier_Symbol", "Sk"),
    ("Nonspacing_Mark", "Mn"),
    ("Number", "N"),
    ("Open_Punctuation", "Ps"),
    ("Other", "C"),
    ("Other_Letter", "Lo"),
    ("Other_Number", "No"),
    ("Other_Punctuation", "Po"),
    ("Other_Symbol", "So"),
    ("Paragraph_Separator", "Zp"),
    ("Private_Use", "Co"),
    ("Punctuation", "P"),
    ("Separator", "Z"),
    ("Space_Separator", "Zs"),
    ("Spacing_Mark", "Mc"),
    ("Surrogate", "Cs"),
    ("Symbol", "S"),
    ("Titlecase_Letter", "Lt"),
    ("Unassigned", "Cn"),
    ("Uppercase_Letter", "Lu"),
    ("cntrl", "Cc"),
    ("digit", "Nd"),
    ("punct", "P"),
];

fn canonical_name(name: &str) -> String {
    let mut out = Vec::with_capacity(name.len());
    let mut first = true;
    for &c in name.as_bytes() {
        if matches!(c, b'_' | b'-' | b' ') {
            continue;
        }
        if first {
            out.push(c.to_ascii_uppercase());
            first = false;
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

type UcdCache = Mutex<HashMap<(String, bool), Vec<CodePoint>>>;
static UCD: LazyLock<UcdCache> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Ranges of a Unicode property, optionally closed under simple case folding.
/// shortcut: ranges come from regex-syntax's Unicode tables (16.0), not Unicode 15.0.0; the
/// difference only matters for class equality in factoring, never for which names exist.
fn ucd(prop: &str, fold: bool) -> Vec<CodePoint> {
    let key = (prop.to_string(), fold);
    let mut cache = UCD.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = cache.get(&key) {
        return v.clone();
    }
    let mut v: Vec<CodePoint> = Vec::new();
    let hir = regex_syntax::ParserBuilder::new()
        .case_insensitive(fold)
        .build()
        .parse(&format!("\\p{{{prop}}}"));
    if let Ok(h) = hir
        && let regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(c)) = h.kind()
    {
        for r in c.ranges() {
            v.extend([r.start() as CodePoint, r.end() as CodePoint]);
        }
    }
    if prop == "gc=Cs" || prop == "gc=C" {
        // Rust chars exclude surrogates; the property tables list them.
        v.extend([0xD800, 0xDFFF]);
        normalize_class_ranges(&mut v);
    }
    cache.insert(key, v.clone());
    v
}

/// (table, table ∪ fold table when there is one, sign).
fn unicode_table(name: &str) -> Option<(Vec<CodePoint>, Option<Vec<CodePoint>>, i32)> {
    let name = canonical_name(name);
    let category = |c: &str| {
        let q = format!("gc={c}");
        Some((
            ucd(&q, false),
            FOLD_CATEGORIES.contains(&c).then(|| ucd(&q, true)),
            1,
        ))
    };
    match name.as_str() {
        "Any" => return Some((vec![0, MAX_CODE_POINT], Some(vec![0, MAX_CODE_POINT]), 1)),
        "Assigned" => {
            let cn = ucd("gc=Cn", false);
            return Some((cn.clone(), Some(cn), -1));
        }
        "Ascii" => {
            return Some((
                vec![0, 0x7f],
                Some(vec![0, 0x7f, 0x17f, 0x17f, 0x212a, 0x212a]),
                1,
            ));
        }
        "Lc" => return category("LC"),
        _ => {}
    }
    if CATEGORIES.contains(&name.as_str()) {
        return category(&name);
    }
    if SCRIPTS.contains(&name.as_str()) {
        let q = format!("sc={name}");
        return Some((
            ucd(&q, false),
            FOLD_SCRIPTS.contains(&name.as_str()).then(|| ucd(&q, true)),
            1,
        ));
    }
    let actual = CATEGORY_ALIASES
        .iter()
        .find(|(a, _)| canonical_name(a) == name)?
        .1;
    category(actual)
}

// ---- Simplify and the instruction count --------------------------------------------------

fn simplify_unary(op: NodeKind, flags: u16, sub: SyntaxNode) -> SyntaxNode {
    if sub.kind == NodeKind::EmptyMatch || op == sub.kind && flags & LAZY == sub.flags & LAZY {
        return sub;
    }
    let mut re = SyntaxNode::new(op);
    re.flags = flags;
    re.children = vec![sub];
    re
}

fn simplify(mut re: SyntaxNode) -> SyntaxNode {
    match re.kind {
        NodeKind::Capture | NodeKind::Concat | NodeKind::Alternate => {
            re.children = std::mem::take(&mut re.children)
                .into_iter()
                .map(simplify)
                .collect();
            re
        }
        NodeKind::Star | NodeKind::Plus | NodeKind::Optional => {
            let sub = simplify(re.children.pop().unwrap());
            simplify_unary(re.kind, re.flags, sub)
        }
        NodeKind::Repeat => {
            if re.min == 0 && re.max == 0 {
                return SyntaxNode::new(NodeKind::EmptyMatch);
            }
            let sub = simplify(re.children.pop().unwrap());
            let concat = |subs: Vec<SyntaxNode>| {
                let mut c = SyntaxNode::new(NodeKind::Concat);
                c.children = subs;
                c
            };
            if re.max == -1 {
                if re.min == 0 {
                    return simplify_unary(NodeKind::Star, re.flags, sub);
                }
                if re.min == 1 {
                    return simplify_unary(NodeKind::Plus, re.flags, sub);
                }
                let mut v: Vec<SyntaxNode> = (0..re.min - 1).map(|_| sub.clone()).collect();
                v.push(simplify_unary(NodeKind::Plus, re.flags, sub));
                return concat(v);
            }
            if re.min == 1 && re.max == 1 {
                return sub;
            }
            let mut prefix =
                (re.min > 0).then(|| concat((0..re.min).map(|_| sub.clone()).collect()));
            if re.max > re.min {
                let mut suffix = simplify_unary(NodeKind::Optional, re.flags, sub.clone());
                for _ in re.min + 1..re.max {
                    suffix = simplify_unary(
                        NodeKind::Optional,
                        re.flags,
                        concat(vec![sub.clone(), suffix]),
                    );
                }
                match prefix.as_mut() {
                    None => return suffix,
                    Some(p) => p.children.push(suffix),
                }
            }
            prefix.unwrap_or_else(|| SyntaxNode::new(NodeKind::NoMatch))
        }
        _ => re,
    }
}

#[derive(Clone, Copy)]
struct Frag {
    fail: bool,
    nullable: bool,
}

const FAIL: Frag = Frag {
    fail: true,
    nullable: false,
};

fn inst(n: &mut usize, nullable: bool) -> Frag {
    *n += 1;
    Frag {
        fail: false,
        nullable,
    }
}

fn cat(f1: Frag, f2: Frag) -> Frag {
    if f1.fail || f2.fail {
        return FAIL;
    }
    Frag {
        fail: false,
        nullable: f1.nullable && f2.nullable,
    }
}

fn alt(f1: Frag, f2: Frag, n: &mut usize) -> Frag {
    if f1.fail {
        return f2;
    }
    if f2.fail {
        return f1;
    }
    inst(n, f1.nullable || f2.nullable)
}

fn plus(f1: Frag, n: &mut usize) -> Frag {
    *n += 1; // the loop's Alt
    f1
}

/// Compiles `re`, counting the instructions it appends.
fn compile_count(re: &SyntaxNode, n: &mut usize) -> Frag {
    match re.kind {
        NodeKind::NoMatch => FAIL,
        NodeKind::EmptyMatch => inst(n, true),
        NodeKind::Literal => {
            if re.code_points.is_empty() {
                return inst(n, true);
            }
            let mut f = inst(n, false);
            for _ in 1..re.code_points.len() {
                let f1 = inst(n, false);
                f = cat(f, f1);
            }
            f
        }
        NodeKind::CharClass | NodeKind::AnyCharNotNewline | NodeKind::AnyChar => inst(n, false),
        NodeKind::BeginLine
        | NodeKind::EndLine
        | NodeKind::BeginText
        | NodeKind::EndText
        | NodeKind::WordBoundary
        | NodeKind::NoWordBoundary => inst(n, true),
        NodeKind::Capture => {
            let bra = inst(n, true);
            let sub = compile_count(&re.children[0], n);
            let ket = inst(n, true);
            cat(cat(bra, sub), ket)
        }
        NodeKind::Star => {
            let f1 = compile_count(&re.children[0], n);
            if f1.nullable {
                plus(f1, n);
            }
            inst(n, true) // quest(plus) or loop: one more Alt, nullable
        }
        NodeKind::Plus => {
            let f1 = compile_count(&re.children[0], n);
            plus(f1, n)
        }
        NodeKind::Optional => {
            compile_count(&re.children[0], n);
            inst(n, true)
        }
        NodeKind::Concat => {
            let mut it = re.children.iter();
            let Some(first) = it.next() else {
                return inst(n, true);
            };
            let mut f = compile_count(first, n);
            for s in it {
                let f1 = compile_count(s, n);
                f = cat(f, f1);
            }
            f
        }
        NodeKind::Alternate => {
            let mut f = FAIL;
            for s in &re.children {
                let f1 = compile_count(s, n);
                f = alt(f, f1, n);
            }
            f
        }
        // Repeat is gone after Simplify; pseudo ops never leave the parser.
        _ => FAIL,
    }
}

/// Instruction count of the compiled, simplified program for `pattern`, or its parse error.
pub fn program_size(pattern: &str) -> Result<usize, String> {
    let re = parse(pattern)?;
    let mut n = 0;
    compile_count(&simplify(re), &mut n);
    Ok(n + 2) // InstFail + InstMatch
}

/// A regex-crate pattern with the same semantics as `pattern` (or its parse error) and the
/// capture group names (index 0 = whole match; "" for an unnamed group).
pub(crate) fn to_rust_pattern(pattern: &str) -> Result<(String, Vec<String>), String> {
    let re = parse(pattern)?;
    let mut names = vec![String::new()];
    collect_names(&re, &mut names);
    let mut out = String::with_capacity(pattern.len() * 2);
    emit(&re, &mut out);
    Ok((out, names))
}

/// A boolean formula over literal atoms every match of a pattern must contain. A necessary
/// condition by construction: a literal node requires its text, a concatenation all its parts,
/// an alternation one of its branches, a repetition with a minimum of one its body; everything
/// else requires nothing. An input for which it is false cannot match, so a caller may skip the
/// regexp (verdicts cannot change).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prefilter {
    /// `text` (ASCII; lower case when `fold`) occurs in the input; `fold`: ASCII case-insensitively.
    Atom {
        text: Vec<u8>,
        fold: bool,
        /// `fold` and `text` holds `k` or `s`: those fold with U+212A / U+017F, so an input
        /// holding either rune must be treated as containing the atom.
        has_ks: bool,
    },
    And(Vec<Prefilter>),
    Or(Vec<Prefilter>),
}

/// The literal requirement of `pattern` (parsed without simplifying), or `None` when it has
/// none or does not parse.
pub fn prefilter_for(pattern: &str) -> Option<Prefilter> {
    prefilter_from_node(&parse(pattern).ok()?)
}

/// The number of ASCII bytes every match of `pattern` must start with, at least (0: it can start
/// with anything: a class, `.`, a repetition that may be empty). Zero-width assertions in front
/// (`^`, `\b`) and capture groups are looked through; an alternation counts its shortest branch.
/// The regex crate extracts such a prefix as a literal set and searches it with SIMD, which is why
/// a pattern with a long one gains nothing from [`prefilter_for`].
pub fn leading_literal_len(pattern: &str) -> usize {
    parse(pattern).map_or(0, |re| leading_literal(&re))
}

fn leading_literal(re: &SyntaxNode) -> usize {
    match re.kind {
        NodeKind::Literal => re
            .code_points
            .iter()
            .take_while(|&&r| (0..0x80).contains(&r))
            .count(),
        NodeKind::Capture | NodeKind::Plus => leading_literal(&re.children[0]),
        NodeKind::Repeat if re.min >= 1 => leading_literal(&re.children[0]),
        NodeKind::Alternate => re.children.iter().map(leading_literal).min().unwrap_or(0),
        NodeKind::Concat => {
            for sub in &re.children {
                match sub.kind {
                    NodeKind::BeginLine
                    | NodeKind::EndLine
                    | NodeKind::BeginText
                    | NodeKind::EndText
                    | NodeKind::WordBoundary
                    | NodeKind::NoWordBoundary
                    | NodeKind::EmptyMatch => continue,
                    _ => return leading_literal(sub),
                }
            }
            0
        }
        _ => 0,
    }
}

fn prefilter_from_node(re: &SyntaxNode) -> Option<Prefilter> {
    match re.kind {
        NodeKind::Literal => {
            prefilter_from_literal(&re.code_points, re.flags & CASE_INSENSITIVE != 0)
        }
        NodeKind::Concat => prefilter_and_of(re.children.iter().map(prefilter_from_node).collect()),
        NodeKind::Alternate => {
            let mut subs = Vec::with_capacity(re.children.len());
            for s in &re.children {
                // one branch that needs nothing makes the alternation need nothing
                subs.push(prefilter_from_node(s)?);
            }
            Some(prefilter_or_of(subs))
        }
        NodeKind::Capture | NodeKind::Plus => prefilter_from_node(&re.children[0]),
        NodeKind::Repeat if re.min >= 1 => prefilter_from_node(&re.children[0]),
        _ => None,
    }
}

/// Every maximal run of ASCII runes is one required atom; a non-ASCII rune ends a
/// run and is not required itself.
fn prefilter_from_literal(code_points: &[CodePoint], fold: bool) -> Option<Prefilter> {
    let mut atoms = Vec::new();
    let mut b: Vec<u8> = Vec::new();
    let flush = |b: &mut Vec<u8>, atoms: &mut Vec<Option<Prefilter>>| {
        if !b.is_empty() {
            let text = std::mem::take(b);
            let has_ks = fold && text.iter().any(|&c| c == b'k' || c == b's');
            atoms.push(Some(Prefilter::Atom { text, fold, has_ks }));
        }
    };
    for &r in code_points {
        if !(0..0x80).contains(&r) {
            flush(&mut b, &mut atoms);
            continue;
        }
        let mut c = r as u8;
        if fold && c.is_ascii_uppercase() {
            c += 32;
        }
        b.push(c);
    }
    flush(&mut b, &mut atoms);
    prefilter_and_of(atoms)
}

/// The conjunction of `subs`; `None` entries (true) are dropped. Atoms are tested
/// before sub-formulas and longer atoms first.
fn prefilter_and_of(subs: Vec<Option<Prefilter>>) -> Option<Prefilter> {
    let mut out: Vec<Prefilter> = Vec::new();
    for s in subs.into_iter().flatten() {
        match s {
            Prefilter::And(v) => out.extend(v),
            s => out.push(s),
        }
    }
    match out.len() {
        0 => return None,
        1 => return out.pop(),
        _ => {}
    }
    let rank = |n: &Prefilter| match n {
        Prefilter::Atom { text, .. } => 1000 + text.len(),
        _ => 0,
    };
    out.sort_by_key(|n| std::cmp::Reverse(rank(n)));
    Some(Prefilter::And(out))
}

/// The disjunction of `subs` (none of which is absent).
fn prefilter_or_of(subs: Vec<Prefilter>) -> Prefilter {
    let mut out = Vec::new();
    for s in subs {
        match s {
            Prefilter::Or(v) => out.extend(v),
            s => out.push(s),
        }
    }
    if out.len() == 1 {
        return out.pop().unwrap();
    }
    Prefilter::Or(out)
}

fn collect_names(re: &SyntaxNode, names: &mut Vec<String>) {
    if re.kind == NodeKind::Capture {
        let cap = re.capture_index as usize;
        if names.len() <= cap {
            names.resize(cap + 1, String::new());
        }
        names[cap] = re.name.clone();
    }
    for s in &re.children {
        collect_names(s, names);
    }
}

/// Matches nothing (an empty character class).
const NEVER: &str = r"[^\x{0}-\x{10FFFF}]";

fn push_code_point(out: &mut String, r: CodePoint) {
    use std::fmt::Write;
    let _ = write!(out, "\\x{{{r:X}}}");
}

/// A class of `ranges` (lo, hi pairs), surrogates removed: input is decoded to runes, never
/// to surrogates, so they can never match, and the regex crate has no way to name them.
fn push_class(out: &mut String, ranges: &[CodePoint]) {
    let start = out.len();
    out.push('[');
    for p in ranges.chunks(2) {
        let (mut lo, hi) = (p[0], p[1]);
        for (a, b) in [(lo, hi.min(0xD7FF)), (lo.max(0xE000), hi)] {
            if a > b {
                continue;
            }
            lo = a;
            push_code_point(out, lo);
            if b != a {
                out.push('-');
                push_code_point(out, b);
            }
        }
    }
    if out.len() == start + 1 {
        out.truncate(start);
        out.push_str(NEVER);
    } else {
        out.push(']');
    }
}

fn emit_group(re: &SyntaxNode, out: &mut String) {
    out.push_str("(?:");
    emit(re, out);
    out.push(')');
}

fn emit(re: &SyntaxNode, out: &mut String) {
    match re.kind {
        NodeKind::NoMatch => out.push_str(NEVER),
        NodeKind::EmptyMatch => out.push_str("(?:)"),
        NodeKind::Literal => {
            let fold = re.flags & CASE_INSENSITIVE != 0;
            for &r in &re.code_points {
                if !fold {
                    push_class(out, &[r, r]);
                    continue;
                }
                // The orbit of simple folding (the runes a case-insensitive literal matches).
                let mut orbit = vec![r, r];
                let mut f = next_case_fold_equivalent(r);
                while f != r {
                    orbit.extend([f, f]);
                    f = next_case_fold_equivalent(f);
                }
                push_class(out, &orbit);
            }
        }
        NodeKind::CharClass => push_class(out, &re.code_points),
        NodeKind::AnyCharNotNewline => out.push_str(r"[^\x{A}]"),
        NodeKind::AnyChar => out.push_str("(?s:.)"),
        NodeKind::BeginLine => out.push_str("(?m:^)"),
        NodeKind::EndLine => out.push_str("(?m:$)"),
        NodeKind::BeginText => out.push_str(r"\A"),
        NodeKind::EndText => out.push_str(r"\z"),
        NodeKind::WordBoundary => out.push_str(r"(?-u:\b)"),
        NodeKind::NoWordBoundary => out.push_str(r"(?-u:\B)"),
        NodeKind::Capture => {
            out.push('(');
            emit(&re.children[0], out);
            out.push(')');
        }
        NodeKind::Star | NodeKind::Plus | NodeKind::Optional | NodeKind::Repeat => {
            emit_group(&re.children[0], out);
            match re.kind {
                NodeKind::Star => out.push('*'),
                NodeKind::Plus => out.push('+'),
                NodeKind::Optional => out.push('?'),
                _ if re.max < 0 => out.push_str(&format!("{{{},}}", re.min)),
                _ if re.max == re.min => out.push_str(&format!("{{{}}}", re.min)),
                _ => out.push_str(&format!("{{{},{}}}", re.min, re.max)),
            }
            if re.flags & LAZY != 0 {
                out.push('?');
            }
        }
        NodeKind::Concat => re.children.iter().for_each(|s| emit(s, out)),
        NodeKind::Alternate => {
            out.push_str("(?:");
            for (i, s) in re.children.iter().enumerate() {
                if i > 0 {
                    out.push('|');
                }
                emit(s, out);
            }
            out.push(')');
        }
        NodeKind::LeftParen | NodeKind::VerticalBar => unreachable!("pseudo op in a parsed tree"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::CompiledRegex;

    #[test]
    fn program_size_matches_reference() {
        let a300 = format!("[[a]{}]", "x".repeat(300));
        let fold = format!("(?i)(?:a{}|A{})", "b".repeat(130), "b".repeat(130));
        for (p, want) in [
            ("", 3),
            ("a", 3),
            ("abc", 5),
            ("a|b", 3),
            ("abc|abd", 5),
            ("a*", 4),
            ("(a)", 5),
            ("a{2,4}", 8),
            ("(?:a*)*", 4),
            ("[a-z]+", 4),
            ("^x$", 5),
            (a300.as_str(), 304),
            (fold.as_str(), 134),
            (
                "[x for x in ().__class__.__bases__[0].__subclasses__() if hasattr(x,'load_module')]",
                50,
            ),
            ("[a[b]c]", 5),
            ("(?i)ab|AC", 4),
            (" | ", 3),
            ("\\b{start}x", 11),
        ] {
            assert_eq!(program_size(p), Ok(want), "{p}");
        }
    }

    #[test]
    fn accept_reject_matches_reference() {
        for (p, want) in [
            (
                "a**",
                "error parsing regexp: invalid nested repetition operator: `**`",
            ),
            (
                "a*+",
                "error parsing regexp: invalid nested repetition operator: `*+`",
            ),
            (
                "a+?*",
                "error parsing regexp: invalid nested repetition operator: `+?*`",
            ),
            (
                "a{2}*",
                "error parsing regexp: invalid nested repetition operator: `{2}*`",
            ),
            (
                "a*{2}",
                "error parsing regexp: invalid nested repetition operator: `*{2}`",
            ),
            (
                "a*??",
                "error parsing regexp: invalid nested repetition operator: `*??`",
            ),
            (
                "a{2}{3}",
                "error parsing regexp: invalid nested repetition operator: `{2}{3}`",
            ),
            (
                "/admin+*",
                "error parsing regexp: invalid nested repetition operator: `+*`",
            ),
            (
                "(?x)a b",
                "error parsing regexp: invalid or unsupported Perl syntax: `(?x`",
            ),
            (
                "x{1001}",
                "error parsing regexp: invalid repeat count: `{1001}`",
            ),
            ("(", "error parsing regexp: missing closing ): `(`"),
            (
                "\\C",
                "error parsing regexp: invalid escape sequence: `\\C`",
            ),
            (
                "\\p{Old_Italic}",
                "error parsing regexp: invalid character class range: `\\p{Old_Italic}`",
            ),
        ] {
            assert_eq!(
                CompiledRegex::compile(p).err().as_deref(),
                Some(want),
                "{p}"
            );
        }
        for p in [
            "\\p{^Greek}",
            "\\P{^Greek}",
            "[\\p{^Greek}x]",
            "(?P<1a>x)(?P<1a>y)",
            "\\p{greek}",
            "\\pL",
            "\\p{Letter}",
            "x{2}?",
        ] {
            assert!(
                CompiledRegex::compile(p).is_ok(),
                "{p}: {:?}",
                CompiledRegex::compile(p).err()
            );
        }
        let re = CompiledRegex::compile("^/\\p{^Greek}+$").unwrap();
        assert!(re.is_match(b"/abc"));
        assert!(!re.is_match("/αβ".as_bytes()));
    }
}
