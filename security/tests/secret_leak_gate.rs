//! §10 / §16.3 secret-leak gate — mechanical enforcement of the "no plaintext
//! credentials" discipline.
//!
//! This is the repository-level half of the security review's §4.3 follow-up
//! ("独立 Secret 泄漏扫描（仓库级 + 运行时日志/响应复核）"): an independent,
//! token-wise scan that fails on hardcoded secrets, embedded private-key
//! material, and plaintext credential disclosure in output macros. The
//! runtime half (log/response review) stays with the release review.
//!
//! Scope: every `*/src/**/*.rs` and `*/tests/**/*.rs` file of the workspace.
//! Crate directories are discovered relative to `CARGO_MANIFEST_DIR`, so a
//! newly added crate is covered automatically; `.claude` worktrees, `target`,
//! and hidden directories are never crates. Files are lexed with the same
//! tokenizer as the migration bare-SQL gate (`migration/tests/bare_sql_gate.rs`):
//! comments and doc comments are stripped, and plain, byte, and raw string
//! literals are recognized as tokens, so none of the checks can be fooled by
//! quoting.
//!
//! Rules:
//!
//! [R1] Hardcoded secrets — an identifier that names a secret is directly
//! bound to a non-empty string literal: `let password = "..."`, a struct
//! field `password: "..."`, the typed-let shape `let password: SecretString =
//! "..."`, each optionally through a leading `&`. The identifier set is
//! `password`/`passwd`/`pwd`/`passphrase`/`secret`/`token`/`api_key`/
//! `apikey`/`master_key`/`bootstrap_code` and their `*_<name>` compound forms
//! (`session_token`, `account_password`, ...), matched case-insensitively.
//! Identifiers that merely *name* non-secrets are excluded on purpose:
//! `credential_id`/`endpoint_id` are addresses, `password_hash` is a digest.
//!
//! [R2] Embedded private-key material — a string literal containing a
//! complete PEM block: a `-----BEGIN ... PRIVATE KEY-----` header and a
//! `-----END ... PRIVATE KEY-----` footer in the same literal. Prefix checks
//! (`pem.starts_with("-----BEGIN PRIVATE KEY-----")`) and label-driven PEM
//! writers (`writeln!(pem, "-----BEGIN {label}-----")`) hold no block and are
//! not flagged; test-scope fixture `PEM`s are exempt by rule (see below).
//!
//! [R3] Plaintext disclosure — `println!`/`eprintln!`/`dbg!` and
//! `tracing::{trace,debug,info,warn,error}!` invocations whose message
//! formats a secret-named identifier (`println!("{password}")`,
//! `tracing::error!("{session_token:?}")`) or passes one as an argument
//! (`println!("{}", password)`).
//!
//! Exclusions:
//!
//! - Test scope is exempt by *context*, not by value allow-lists: integration
//!   tests (`*/tests/**`), items gated by `#[cfg(test)]` (including composite
//!   predicates that imply `test`, such as `all(test, ...)` — but not
//!   `any(target_arch = "wasm32", test)`, which ships the wasm build),
//!   `#[test]`/`#[tokio::test]` functions, and out-of-line test modules
//!   (`#[cfg(test)] mod tests;` resolves the sibling `tests.rs`/`tests/mod.rs`
//!   file). Fixture literals such as `"correct horse battery staple"` live in
//!   test scope and are exempt; a value allow-list would hide a future real
//!   secret behind a fixture-shaped value and is deliberately not used.
//! - The `test-support` crate is fixture scope by definition: it is a
//!   dev-only test-double workspace crate (mock BMC/center), and its
//!   secret-named constants are fixture protocol values — the mock's fixed
//!   `SESSION_TOKEN` and mock resource bodies exist to keep wire-sequence
//!   assertions deterministic. Nothing in a release ships from it.
//! - `strings_catalog!` macro bodies (ui/src/i18n.rs): catalog
//!   construction, not code. Inside the invocation the field names are i18n
//!   keys and the literals are bilingual copy (`error_bootstrap_code:
//!   "bootstrap failed — ..."`), so [R1] would misread a catalog entry as
//!   a secret assignment. The exemption is structural — the macro body is
//!   tracked like test scope — so a real secret assignment in the same
//!   file outside the macro is still flagged; no value is allow-listed.
//! - `ALLOWED_CONSTANT_HITS` below: the rare production constants whose
//!   *names* read like secrets but whose values hold no secret material
//!   (backup-package entry names). Each entry binds path+line+name+value, so
//!   any drift fails the gate and forces re-review before the entry moves
//!   (the deny.toml TRIGGER-note discipline).
//! - The bootstrap-code console print (`app/src/initialization_runtime.rs`):
//!   the one-time claim code is *designed* to be printed once to the local
//!   console (§16.2 first-run claim; the variable is `raw_code`, which no
//!   identifier set names).
//! - Span macros (`info_span!`, `#[instrument(...)]`) and
//!   `format!`/`write!`/`writeln!`: spans never emit a message line and the
//!   app's discipline is `skip_all`; the other three are not output surfaces
//!   (and the redaction tests' `format!("{password:?}")` asserts the
//!   `[REDACTED]` form, which must not trip the gate).
//! - Empty literals (`password = ""`): placeholder, not a secret.
//! - Non-`.rs` files (docs, fixtures, lockfiles): outside the mechanical
//!   scope; the release review's runtime half covers the surfaces.
//!
//! The gate is deterministic (same tree, same violation list — asserted by
//! `workspace_scan_is_deterministic`) and reports precise `path:line` hits;
//! it fails on any production-scope hit, which on the current tree means the
//! workspace is expected to scan green.

use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// One lexed token with the source line it started on (same lexer as the
/// migration bare-SQL gate's; punctuation carries no line because this gate
/// only reports on the tokens it inspects, all of which have one).
#[derive(Debug, Clone)]
enum Token {
    Ident { line: usize, name: String },
    Str { line: usize, content: String },
    RawStr { line: usize, content: String },
    Punct { ch: char },
}

impl Token {
    fn is_punct(&self, ch: char) -> bool {
        matches!(self, Token::Punct { ch: found, .. } if *found == ch)
    }
}

/// The lexed tokens of one source file, with the path used in messages.
struct SourceTokens {
    display_path: String,
    tokens: Vec<Token>,
}

/// Lexes a Rust source file for the gate's narrow purpose: identifiers,
/// string literals (plain, byte, and raw), and single-character punctuation.
/// Comments are stripped; only the string tokens carry content.
fn tokenize(display_path: &str, source: &str) -> SourceTokens {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' {
                    line += 1;
                }
                i += 1;
            }
            i = (i + 2).min(chars.len());
        } else if c == '"' {
            let (content, next) = parse_plain_string(&chars, i + 1);
            tokens.push(Token::Str { line, content });
            i = next;
        } else if c == 'r' && raw_string_start(&chars, i) {
            let (content, next) = parse_raw_string(&chars, i);
            tokens.push(Token::RawStr { line, content });
            i = next;
        } else if c == 'b' && (chars.get(i + 1) == Some(&'"') || raw_string_start(&chars, i + 1)) {
            if chars.get(i + 1) == Some(&'"') {
                let (content, next) = parse_plain_string(&chars, i + 2);
                tokens.push(Token::Str { line, content });
                i = next;
            } else {
                let (content, next) = parse_raw_string(&chars, i + 1);
                tokens.push(Token::RawStr { line, content });
                i = next;
            }
        } else if c == '\'' {
            i = skip_char_or_lifetime(&chars, i);
        } else if c.is_ascii_alphabetic() || c == '_' {
            let mut end = i + 1;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            tokens.push(Token::Ident {
                line,
                name: chars[i..end].iter().collect(),
            });
            i = end;
        } else if !c.is_whitespace() {
            tokens.push(Token::Punct { ch: c });
            i += 1;
        } else {
            i += 1;
        }
    }
    SourceTokens {
        display_path: display_path.to_owned(),
        tokens,
    }
}

/// Collects a plain `"..."` string, honoring `\` escapes and the
/// backslash-newline continuation.
fn parse_plain_string(chars: &[char], start: usize) -> (String, usize) {
    let mut content = String::new();
    let mut i = start;
    while i < chars.len() {
        if chars[i] == '\\' {
            content.push('\\');
            if i + 1 < chars.len() {
                content.push(chars[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
        } else if chars[i] == '"' {
            return (content, i + 1);
        } else {
            content.push(chars[i]);
            i += 1;
        }
    }
    (content, i)
}

/// Whether `chars[r_index]` starts a raw string: `r`, optional `#`s, `"`.
fn raw_string_start(chars: &[char], r_index: usize) -> bool {
    if chars.get(r_index) != Some(&'r') {
        return false;
    }
    let mut i = r_index + 1;
    while chars.get(i) == Some(&'#') {
        i += 1;
    }
    chars.get(i) == Some(&'"')
}

/// Whether the raw string with `hashes` hash marks closes at `chars[i]`.
fn raw_string_closes_at(chars: &[char], i: usize, hashes: usize) -> bool {
    chars.get(i) == Some(&'"') && (i + 1..i + 1 + hashes).all(|j| chars.get(j) == Some(&'#'))
}

/// Collects a raw string (`r"..."`, `r#"..."#`, ...) starting at
/// `chars[r_index]`, returning its content and the index after the closing
/// delimiter.
fn parse_raw_string(chars: &[char], r_index: usize) -> (String, usize) {
    let mut i = r_index + 1;
    while chars.get(i) == Some(&'#') {
        i += 1;
    }
    let hashes = i - r_index - 1;
    let content_start = i + 1;
    i = content_start;
    while i < chars.len() {
        if raw_string_closes_at(chars, i, hashes) {
            return (chars[content_start..i].iter().collect(), i + 1 + hashes);
        }
        i += 1;
    }
    (String::new(), i)
}

/// Advances past a `'...'` char literal or a lifetime/placeholder (`'a`,
/// `'_`) token.
fn skip_char_or_lifetime(chars: &[char], start: usize) -> usize {
    let next = start + 1;
    let is_lifetime = chars.get(next) == Some(&'_')
        || (chars.get(next).is_some_and(char::is_ascii_alphanumeric)
            && chars.get(next + 1) != Some(&'\''));
    if is_lifetime {
        return next;
    }
    let mut i = if chars.get(next) == Some(&'\\') {
        next + 1
    } else {
        next
    };
    while i < chars.len() && chars[i] != '\'' {
        i += 1;
    }
    (i + 1).min(chars.len())
}

/// Identifiers that name a secret, matched case-insensitively.
const SENSITIVE_IDENTIFIERS: [&str; 16] = [
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "secret_string",
    "token",
    "auth_token",
    "session_token",
    "csrf_token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "master_key",
    "bootstrap_code",
];

/// Compound identifier suffixes that make the identifier a secret
/// (`account_password`, `totp_secret`, ...). `credential_id`/`endpoint_id`
/// (`_id`), `password_hash` (`_hash`), and friends are deliberately absent:
/// addresses and digests are not secrets.
const SENSITIVE_IDENTIFIER_SUFFIXES: [&str; 8] = [
    "_password",
    "_passphrase",
    "_secret",
    "_token",
    "_apikey",
    "_api_key",
    "_master_key",
    "_bootstrap_code",
];

fn is_sensitive_identifier(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_IDENTIFIERS.contains(&lower.as_str())
        || SENSITIVE_IDENTIFIER_SUFFIXES
            .iter()
            .any(|suffix| lower.ends_with(suffix))
}

/// The [R3] identifier set: [R1]'s set plus the bare `credential` object
/// (logging a resolved credential), but still not `credential_id`/`_name`.
fn is_sensitive_log_identifier(name: &str) -> bool {
    is_sensitive_identifier(name) || name.eq_ignore_ascii_case("credential")
}

/// Documented carve-outs: production constants whose names read like secrets
/// but whose values are package-format identifiers, not secret material.
///
/// Each entry binds path + line + name + literal, so any drift (the constant
/// moving, being renamed, or its value changing) fails the gate: re-read the
/// constant, confirm it still holds no secret material, then update the
/// entry — the deny.toml TRIGGER-note discipline. Verified 2026-08-12.
const ALLOWED_CONSTANT_HITS: [(&str, usize, &str, &str); 2] = [
    ("app/src/backup.rs", 88, "ENTRY_MASTER_KEY", "master-key"),
    (
        "app/src/backup.rs",
        89,
        "ENTRY_SYSTEM_MASTER_KEY",
        "system-master-key",
    ),
];

fn is_allowed_constant(display_path: &str, line: usize, name: &str, literal: &str) -> bool {
    ALLOWED_CONSTANT_HITS
        .iter()
        .any(|(path, allowed_line, allowed_name, allowed_literal)| {
            display_path == *path
                && line == *allowed_line
                && name == *allowed_name
                && literal == *allowed_literal
        })
}

/// The `[R3]` output macros.
const OUTPUT_MACROS: [&str; 3] = ["println", "eprintln", "dbg"];

/// The `tracing` event levels whose messages [R3] inspects. Span macros
/// (`info_span!`, `#[instrument(...)]`) are deliberately not included.
const TRACING_EVENT_LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

/// Parses the attribute group starting at the `#` at `hash_index`, returning
/// the tokens inside the brackets, the index just past the closing `]`, and
/// whether the attribute is an inner (`#![...]`) attribute.
fn attribute_contents(tokens: &[Token], hash_index: usize) -> Option<(Vec<Token>, usize, bool)> {
    let is_inner = matches!(
        tokens.get(hash_index + 1),
        Some(Token::Punct { ch: '!', .. })
    );
    let open = hash_index + 1 + usize::from(is_inner);
    if !matches!(tokens.get(open), Some(Token::Punct { ch: '[', .. })) {
        return None;
    }
    let mut depth = 1usize;
    let mut j = open + 1;
    while j < tokens.len() && depth > 0 {
        match &tokens[j] {
            Token::Punct { ch: '[', .. } => depth += 1,
            Token::Punct { ch: ']', .. } => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    if depth > 0 {
        return None;
    }
    Some((tokens[open + 1..j - 1].to_vec(), j, is_inner))
}

/// Whether the attribute's inner tokens gate an item to test builds:
/// `#[test]`/`#[tokio::test]` (any path whose segment is `test`), `#[cfg(
/// <predicate>)]` with a predicate that implies `test`, and
/// `#[cfg_attr(<predicate>, ...)]` likewise.
fn attribute_is_test(inner: &[Token]) -> bool {
    let Some(Token::Ident { name, .. }) = inner.first() else {
        return false;
    };
    if name == "cfg" {
        return inner
            .iter()
            .position(|token| token.is_punct('('))
            .is_some_and(|open| predicate_implies_test(inner, open));
    }
    if name == "cfg_attr" {
        let Some(open) = inner.iter().position(|t| t.is_punct('(')) else {
            return false;
        };
        let mut depth = 0usize;
        for (offset, token) in inner.iter().enumerate().skip(open + 1) {
            match token {
                Token::Punct { ch: '(', .. } => depth += 1,
                Token::Punct { ch: ')', .. } => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                Token::Punct { ch: ',', .. } if depth == 0 => {
                    return atom_implies_test(&inner[open + 1..offset], 0).0;
                }
                _ => {}
            }
        }
        return false;
    }
    // A plain attribute is a test attribute iff one of its path segments is
    // literally `test` (`#[test]`, `#[tokio::test]`); `#[testify]` is not.
    inner
        .iter()
        .any(|token| matches!(token, Token::Ident { name, .. } if name == "test"))
}

/// Whether a `cfg`/`cfg_attr` predicate token list implies the `test` config,
/// i.e. the item exists only in test builds. `open` is the index of the
/// predicate's `(`; multiple predicate arguments combine as `all`.
fn predicate_implies_test(tokens: &[Token], open: usize) -> bool {
    predicate_arg_values(tokens, open).0
}

/// Evaluates the comma-separated predicate arguments inside the `(` at
/// `open`, returning `(some_implies, all_imply)`.
fn predicate_arg_values(tokens: &[Token], open: usize) -> (bool, bool) {
    let mut i = open + 1;
    let mut some_implies = false;
    let mut all_imply = true;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Punct { ch: ')', .. } => break,
            Token::Punct { ch: ',', .. } => i += 1,
            _ => {
                let (implies, next) = atom_implies_test(tokens, i);
                some_implies |= implies;
                all_imply &= implies;
                i = next;
            }
        }
    }
    (some_implies, all_imply)
}

/// Parses one predicate atom starting at `i`, returning whether it implies
/// `test` and the index just past it. `all(...)` implies `test` if any
/// conjunct does; `any(...)` only if every disjunct does (so
/// `any(target_arch = "wasm32", test)` does *not* imply `test` — the wasm
/// build ships that item); `not(...)` never implies `test`; any other atom
/// (features, target triples, ...) does not.
fn atom_implies_test(tokens: &[Token], i: usize) -> (bool, usize) {
    match tokens.get(i) {
        Some(Token::Ident { name, .. }) if name == "test" => (true, i + 1),
        Some(Token::Ident { name, .. })
            if (name == "all" || name == "any")
                && matches!(tokens.get(i + 1), Some(Token::Punct { ch: '(', .. })) =>
        {
            let (some_implies, all_imply) = predicate_arg_values(tokens, i + 1);
            let implies = if name == "all" {
                some_implies
            } else {
                all_imply
            };
            let next = skip_paren_group(tokens, i + 1);
            (implies, next)
        }
        Some(Token::Ident { name, .. })
            if name == "not" && matches!(tokens.get(i + 1), Some(Token::Punct { ch: '(', .. })) =>
        {
            (false, skip_paren_group(tokens, i + 1))
        }
        _ => (false, skip_atom(tokens, i)),
    }
}

/// Skips past the paren group opening at `open` (index of `(`).
fn skip_paren_group(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0usize;
    let mut j = open;
    while j < tokens.len() {
        match &tokens[j] {
            Token::Punct { ch: '(', .. } => depth += 1,
            Token::Punct { ch: ')', .. } => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    j
}

/// Skips one unknown atom (feature flag, target triple, ...) up to the next
/// top-level `,` or `)` (not consumed).
fn skip_atom(tokens: &[Token], i: usize) -> usize {
    let mut depth = 0usize;
    let mut j = i;
    while j < tokens.len() {
        match &tokens[j] {
            Token::Punct { ch: '(', .. } => depth += 1,
            Token::Punct { ch: ')', .. } => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            Token::Punct { ch: ',', .. } if depth == 0 => break,
            _ => {}
        }
        j += 1;
    }
    j
}

/// The one macro whose invocation body is a string-catalog construction:
/// `strings_catalog!` (ui/src/i18n.rs) declares every copy key as a struct
/// field. Inside its body, `field: "copy", zh: "copy"` bindings are catalog
/// entries — the identifier is an i18n key and the literals are message
/// copy, never a secret assignment — so [R1] is exempt there by *structure*,
/// the same way test scope is. The exemption cannot be value-based: catalog
/// keys like `error_bootstrap_code` legitimately read like secrets, and a
/// value allow-list would hide a future real secret behind catalog-shaped
/// copy.
const CATALOG_MACRO: &str = "strings_catalog";

/// Tracks whether each open brace's block is test scope, plus a pending
/// "next item is test-gated" flag set by the preceding attribute, and —
/// separately — whether each block is a `strings_catalog!` macro body
/// (catalog-construction scope, [R1]-exempt).
struct ScopeTracker {
    stack: Vec<bool>,
    pending_test: bool,
    catalog_stack: Vec<bool>,
    pending_catalog: bool,
}

impl ScopeTracker {
    fn new(initial_test: bool) -> Self {
        Self {
            stack: vec![initial_test],
            pending_test: false,
            catalog_stack: vec![false],
            pending_catalog: false,
        }
    }

    fn current(&self) -> bool {
        *self.stack.last().unwrap_or(&false)
    }

    /// Whether the current block is a `strings_catalog!` macro body.
    fn in_catalog(&self) -> bool {
        *self.catalog_stack.last().unwrap_or(&false)
    }

    fn open_brace(&mut self) {
        let next = if self.pending_test {
            true
        } else {
            self.current()
        };
        self.stack.push(next);
        self.pending_test = false;
        // A nested brace inside the catalog body stays in catalog scope.
        let in_catalog = self.pending_catalog || self.in_catalog();
        self.catalog_stack.push(in_catalog);
        self.pending_catalog = false;
    }

    fn close_brace(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
        }
        if self.catalog_stack.len() > 1 {
            self.catalog_stack.pop();
        }
    }

    fn on_attribute(&mut self, is_test: bool) {
        if is_test {
            self.pending_test = true;
        }
    }

    fn semicolon(&mut self) {
        self.pending_test = false;
    }

    /// Marks the next `{` as opening a `strings_catalog!` macro body.
    fn on_catalog_macro(&mut self) {
        self.pending_catalog = true;
    }
}

/// The `(line, literal)` of a string literal directly bound to the
/// identifier at `i` by `=` or `:` (struct field), optionally through a
/// leading `&`, or the typed-let shape `name: Type = "..."` via a bounded
/// lookahead over the type tokens.
fn assigned_literal(tokens: &[Token], i: usize) -> Option<String> {
    let next = tokens.get(i + 1)?;
    let binding = if next.is_punct('=') || next.is_punct(':') {
        literal_after(tokens, i + 1)
    } else {
        None
    };
    if binding.is_some() {
        return binding;
    }
    if !next.is_punct(':') {
        return None;
    }
    // Typed-let lookahead: `let password: SecretString = "..."`. The type is
    // a bounded run of identifiers, paths, and brackets; the `;`/`{`/`}`
    // terminals stop the scan, and a balanced `(...)` group is skipped whole.
    let mut depth = 0usize;
    let mut steps = 0usize;
    let mut j = i + 2;
    while steps < 12 && j < tokens.len() {
        match &tokens[j] {
            Token::Punct { ch: '=', .. } => return literal_after(tokens, j),
            Token::Punct {
                ch: ';' | '{' | '}',
                ..
            } => return None,
            Token::Punct { ch: '(', .. } => depth += 1,
            Token::Punct { ch: ')', .. } => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            _ => {}
        }
        j += 1;
        steps += 1;
    }
    None
}

/// The content of the non-empty string literal after the binding token at
/// `index` (`=` or `:`), skipping one optional `&`.
fn literal_after(tokens: &[Token], index: usize) -> Option<String> {
    let mut j = index + 1;
    if matches!(tokens.get(j), Some(Token::Punct { ch: '&', .. })) {
        j += 1;
    }
    match tokens.get(j) {
        Some(Token::Str { content, .. } | Token::RawStr { content, .. }) if !content.is_empty() => {
            Some(content.clone())
        }
        _ => None,
    }
}

/// [R2]: whether a literal embeds a complete PEM private-key block (a
/// `-----BEGIN ... PRIVATE KEY-----` header and its `-----END ...-----`
/// footer in the same literal). Prefix checks and label-driven writers carry
/// only one side of the block and are not flagged.
fn embedded_private_key(content: &str) -> bool {
    content.contains("-----BEGIN")
        && content.contains("-----END")
        && content.contains("PRIVATE KEY")
}

/// If `tokens[i]` starts an output-macro invocation, the argument slice
/// bounds: `(first_argument, index_past_closing_paren)`.
fn output_macro_span(tokens: &[Token], i: usize) -> Option<(usize, usize)> {
    let Token::Ident { name, .. } = &tokens[i] else {
        return None;
    };
    let bang = if OUTPUT_MACROS.contains(&name.as_str()) {
        i + 1
    } else if name == "tracing"
        && matches!(tokens.get(i + 1), Some(Token::Punct { ch: ':', .. }))
        && matches!(tokens.get(i + 2), Some(Token::Punct { ch: ':', .. }))
        && matches!(
            tokens.get(i + 3),
            Some(Token::Ident { name, .. }) if TRACING_EVENT_LEVELS.contains(&name.as_str())
        )
    {
        i + 4
    } else {
        return None;
    };
    if !matches!(tokens.get(bang), Some(Token::Punct { ch: '!', .. })) {
        return None;
    }
    let open = bang + 1;
    if !matches!(tokens.get(open), Some(Token::Punct { ch: '(', .. })) {
        return None;
    }
    let mut depth = 1usize;
    let mut j = open + 1;
    while j < tokens.len() && depth > 0 {
        match &tokens[j] {
            Token::Punct { ch: '(', .. } => depth += 1,
            Token::Punct { ch: ')', .. } => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    if depth > 0 {
        return None;
    }
    Some((open + 1, j))
}

/// [R3] hits inside one output macro's argument slice: a secret-named format
/// capture in a message string, or a secret-named identifier argument.
fn output_macro_violations(args: &[Token], display_path: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for token in args {
        match token {
            Token::Str { line, content } | Token::RawStr { line, content } => {
                if let Some(name) = sensitive_format_capture(content) {
                    violations.push(format!(
                        "{display_path}:{line}: [R3] output macro message formats the \
                         secret identifier `{name}`"
                    ));
                }
            }
            Token::Ident { line, name } if is_sensitive_log_identifier(name) => {
                violations.push(format!(
                    "{display_path}:{line}: [R3] output macro argument `{name}` may \
                     disclose a secret value"
                ));
            }
            Token::Ident { .. } | Token::Punct { .. } => {}
        }
    }
    violations
}

/// The first secret-named format capture of a format string, if any. Only
/// named captures (`{password}`, `{password:?}`, `{password:>8}`) count;
/// positional `{}` and escaped `{{`/`}}` do not.
fn sensitive_format_capture(content: &str) -> Option<String> {
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '{' {
            i += 1;
            continue;
        }
        if chars.get(i + 1) == Some(&'{') {
            i += 2;
            continue;
        }
        let mut j = i + 1;
        let mut name = String::new();
        while j < chars.len() && chars[j] != '}' && chars[j] != ':' {
            name.push(chars[j]);
            j += 1;
        }
        if !name.is_empty() && is_sensitive_log_identifier(&name) {
            return Some(name);
        }
        while j < chars.len() && chars[j] != '}' {
            j += 1;
        }
        i = j + 1;
    }
    None
}

/// [R1] + [R2] + [R3] hits for one tokenized file, with test scope tracked
/// from `initial_test` (integration-test baseline) plus the file's own
/// `#[cfg(test)]`/`#[test]` structure.
fn scan_file(source: &SourceTokens, initial_test: bool) -> Vec<String> {
    let tokens = &source.tokens;
    let mut scope = ScopeTracker::new(initial_test);
    let mut violations = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Punct { ch: '{', .. } => {
                scope.open_brace();
                i += 1;
            }
            Token::Punct { ch: '}', .. } => {
                scope.close_brace();
                i += 1;
            }
            Token::Punct { ch: ';', .. } => {
                scope.semicolon();
                i += 1;
            }
            Token::Punct { ch: '#', .. } => {
                if let Some((inner, next, _)) = attribute_contents(tokens, i) {
                    scope.on_attribute(attribute_is_test(&inner));
                    i = next;
                } else {
                    i += 1;
                }
            }
            Token::Ident { name, line } => {
                if let Some((open, close)) = output_macro_span(tokens, i) {
                    if !scope.current() {
                        violations.extend(output_macro_violations(
                            &tokens[open..close],
                            &source.display_path,
                        ));
                    }
                    i = close;
                } else if name == CATALOG_MACRO
                    && matches!(tokens.get(i + 1), Some(Token::Punct { ch: '!', .. }))
                    && matches!(tokens.get(i + 2), Some(Token::Punct { ch: '{', .. }))
                {
                    // The `{` that follows opens the catalog body, where
                    // [R1] is exempt by structure (see CATALOG_MACRO).
                    scope.on_catalog_macro();
                    i += 1;
                } else {
                    if !scope.current()
                        && !scope.in_catalog()
                        && is_sensitive_identifier(name)
                        && let Some(literal) = assigned_literal(tokens, i)
                        && !is_allowed_constant(&source.display_path, *line, name, &literal)
                    {
                        violations.push(format!(
                            "{}:{}: [R1] hardcoded secret: `{name}` is set to the \
                             non-empty string literal `{literal}`",
                            source.display_path, line,
                        ));
                    }
                    i += 1;
                }
            }
            Token::Str { line, content } | Token::RawStr { line, content } => {
                if !scope.current() && embedded_private_key(content) {
                    violations.push(format!(
                        "{}:{}: [R2] embedded private-key material: a string literal \
                         contains a complete PEM private-key block",
                        source.display_path, line,
                    ));
                }
                i += 1;
            }
            Token::Punct { .. } => i += 1,
        }
    }
    violations
}

/// The workspace root: `security/..` (this crate's manifest directory).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

/// The workspace crate names in sorted order: top-level directories that
/// carry a `src/` or `tests/` tree. Hidden directories and `target` are
/// never crates, which keeps the scan off `.claude` worktrees and build
/// artifacts.
fn crate_directories(root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut crates = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || name == "target" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() && (path.join("src").is_dir() || path.join("tests").is_dir()) {
            crates.push(name);
        }
    }
    crates.sort();
    Ok(crates)
}

/// The `src/` and `tests/` `.rs` files of one crate, sorted deterministically
/// (depth-first, name order at each level), relative to the crate directory.
fn crate_source_files(crate_dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();
    for tree in ["src", "tests"] {
        let directory = crate_dir.join(tree);
        if directory.is_dir() {
            collect_rs_files(&directory, crate_dir, &mut files)?;
        }
    }
    Ok(files)
}

fn collect_rs_files(
    directory: &Path,
    base: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, base, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path.strip_prefix(base)?;
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

/// One tokenized workspace file with its test-scope baseline.
struct WorkspaceFile {
    absolute: PathBuf,
    display: String,
    tokens: Vec<Token>,
    initial_test: bool,
}

/// Whole-file test flags for one tokenized file: an inner `#![cfg(test)]`
/// attribute makes the whole file test scope, and a `#[cfg(test)] mod name;`
/// declaration names an out-of-line test module (resolved to its sibling
/// file by the caller).
fn file_level_test_flags(
    tokens: &[Token],
    declaring_file: &Path,
) -> (bool, Vec<(PathBuf, String)>) {
    let mut whole_file_test = false;
    let mut declarations = Vec::new();
    let mut pending_test = false;
    let mut i = 0;
    while i < tokens.len() {
        if matches!(&tokens[i], Token::Punct { ch: '#', .. })
            && let Some((inner, next, is_inner)) = attribute_contents(tokens, i)
        {
            if attribute_is_test(&inner) {
                if is_inner {
                    whole_file_test = true;
                } else {
                    pending_test = true;
                }
            }
            i = next;
            continue;
        }
        if pending_test {
            match &tokens[i] {
                Token::Ident { name, .. } if name == "mod" => {
                    if let (Some(Token::Ident { name, .. }), Some(Token::Punct { ch: ';', .. })) =
                        (tokens.get(i + 1), tokens.get(i + 2))
                    {
                        let parent = declaring_file.parent().unwrap_or(declaring_file);
                        declarations.push((parent.to_path_buf(), name.clone()));
                        pending_test = false;
                        i += 3;
                        continue;
                    }
                }
                Token::Punct {
                    ch: ';' | '{' | '}',
                    ..
                } => pending_test = false,
                _ => {}
            }
        }
        i += 1;
    }
    (whole_file_test, declarations)
}

/// The full workspace scan: tokenize every file, resolve out-of-line test
/// modules, then run [R1]–[R3] per file. The violation list is deterministic
/// (sorted files, token order).
fn scan_workspace() -> Result<Vec<String>, Box<dyn Error>> {
    let root = workspace_root();
    let mut files = Vec::new();
    let mut declarations = Vec::new();
    for crate_name in crate_directories(&root)? {
        let crate_dir = root.join(&crate_name);
        for relative in crate_source_files(&crate_dir)? {
            let absolute = crate_dir.join(&relative);
            let source = fs::read_to_string(&absolute)?;
            let display = format!(
                "{}/{}",
                crate_name,
                relative.to_string_lossy().replace('\\', "/")
            );
            let tokens = tokenize(&display, &source);
            let (whole_file_test, file_declarations) =
                file_level_test_flags(&tokens.tokens, &absolute);
            declarations.extend(file_declarations);
            files.push(WorkspaceFile {
                absolute,
                display,
                tokens: tokens.tokens,
                initial_test: relative.starts_with("tests")
                    || whole_file_test
                    || crate_name == "test-support",
            });
        }
    }
    // Resolve `#[cfg(test)] mod name;` to `name.rs` / `name/mod.rs` siblings.
    let mut test_module_files = HashSet::new();
    for (parent, name) in &declarations {
        let candidates = [
            parent.join(format!("{name}.rs")),
            parent.join(name).join("mod.rs"),
        ];
        for file in &files {
            if candidates
                .iter()
                .any(|candidate| candidate == &file.absolute)
            {
                test_module_files.insert(file.absolute.clone());
            }
        }
    }
    let mut violations = Vec::new();
    for file in &files {
        let initial_test = file.initial_test || test_module_files.contains(&file.absolute);
        violations.extend(scan_file(
            &SourceTokens {
                display_path: file.display.clone(),
                tokens: file.tokens.clone(),
            },
            initial_test,
        ));
    }
    Ok(violations)
}

/// The number of files the workspace walk covers (self-proof that the walk
/// is not silently empty).
fn scanned_file_count() -> Result<usize, Box<dyn Error>> {
    let root = workspace_root();
    let mut count = 0;
    for crate_name in crate_directories(&root)? {
        count += crate_source_files(&root.join(&crate_name))?.len();
    }
    Ok(count)
}

/// Runs [R1]–[R3] over one synthetic source (used by the matcher self-tests;
/// `initial_test` simulates an integration-test file).
fn scan_source_sample(source: &str, initial_test: bool) -> Vec<String> {
    let tokens = tokenize("self-test", source);
    scan_file(&tokens, initial_test)
}

#[test]
fn workspace_sources_have_no_hardcoded_secrets_or_plaintext_disclosure()
-> Result<(), Box<dyn Error>> {
    let violations = scan_workspace()?;
    assert!(
        violations.is_empty(),
        "workspace sources violate the §10/§16.3 secret-leak gate:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

#[test]
fn workspace_scan_is_deterministic() -> Result<(), Box<dyn Error>> {
    let first = scan_workspace()?;
    let second = scan_workspace()?;
    assert_eq!(
        first, second,
        "re-scanning the workspace must produce the identical violation list"
    );
    Ok(())
}

#[test]
fn workspace_scan_covers_the_expected_source_population() -> Result<(), Box<dyn Error>> {
    let count = scanned_file_count()?;
    assert!(
        count > 100,
        "the gate covered only {count} source files; the workspace walk is likely broken"
    );
    Ok(())
}

#[test]
fn hardcoded_secret_rule_flags_production_assignments() {
    let flagged: &[(&str, &str)] = &[
        ("let password = \"hunter2\";", "`password`"),
        ("let passwd = \"hunter2\";", "`passwd`"),
        ("let pwd = \"hunter2\";", "`pwd`"),
        ("let passphrase = \"hunter2\";", "`passphrase`"),
        ("let secret = \"hunter2\";", "`secret`"),
        ("let api_key = \"hunter2\";", "`api_key`"),
        ("let apikey = \"hunter2\";", "`apikey`"),
        ("let token = \"hunter2\";", "`token`"),
        ("let session_token = \"hunter2\";", "`session_token`"),
        ("let csrf_token = \"hunter2\";", "`csrf_token`"),
        ("let master_key = \"hunter2\";", "`master_key`"),
        ("let bootstrap_code = \"hunter2\";", "`bootstrap_code`"),
        ("let account_password = \"hunter2\";", "`account_password`"),
        ("let totp_secret = \"hunter2\";", "`totp_secret`"),
        (
            "let admin_password: SecretString = \"hunter2\";",
            "`admin_password`",
        ),
        ("let password: SecretString = \"hunter2\";", "`password`"),
        ("let password = &\"hunter2\";", "`password`"),
        ("password: \"hunter2\",", "`password`"),
        ("let PASSWORD = \"hunter2\";", "`PASSWORD`"),
        ("let Secret = \"hunter2\";", "`Secret`"),
    ];
    for (sample, needle) in flagged {
        let violations = scan_source_sample(sample, false);
        assert!(
            !violations.is_empty(),
            "sample `{sample}` must be flagged by [R1]"
        );
        assert!(
            violations.join("\n").contains(needle),
            "sample `{sample}` must mention `{needle}`, got:\n{}",
            violations.join("\n")
        );
    }
    let passing: &[&str] = &[
        "let secret = \"\";",
        "let password = format!(\"x\");",
        "if password == \"hunter2\" { }",
        "let x = \"password = \\\"hunter2\\\"\";",
        "uri.starts_with(\"otpauth://totp/Rutilus:admin?secret=\")",
        "let credential_id = \"hunter2\";",
        "let password_hash = \"hunter2\";",
        "fn password() -> String { String::new() }",
    ];
    for sample in passing {
        let violations = scan_source_sample(sample, false);
        assert!(
            violations.is_empty(),
            "sample `{sample}` must pass [R1], got:\n{}",
            violations.join("\n")
        );
    }
}

#[test]
fn test_scope_exempts_fixtures_but_wasm_production_stays_covered() {
    let exempt: &[&str] = &[
        "#[cfg(test)]\nmod tests {\n    let password = \"hunter2\";\n}",
        "#[test]\nfn claim() {\n    let secret = \"hunter2\";\n}",
        "#[tokio::test]\nasync fn claim() {\n    let token = \"hunter2\";\n}",
        "#[cfg(all(test, feature = \"x\"))]\nmod m {\n    let passphrase = \"x\";\n}",
        "#[cfg(test)]\nfn helper() -> Result<(), ()> {\n    let password = \"x\";\n    Ok(())\n}",
        "let password = \"hunter2\";",
    ];
    for sample in exempt {
        let violations = if sample.starts_with("let password") {
            scan_source_sample(sample, true)
        } else {
            scan_source_sample(sample, false)
        };
        assert!(
            violations.is_empty(),
            "test-scope sample must be exempt, got:\n{}",
            violations.join("\n")
        );
    }
    // `any(target_arch = "wasm32", test)` ships the wasm build: production.
    let wasm =
        "#[cfg(any(target_arch = \"wasm32\", test))]\nmod ui {\n    let password = \"hunter2\";\n}";
    let violations = scan_source_sample(wasm, false);
    assert_eq!(
        violations.len(),
        1,
        "wasm-shipped code must stay in [R1] scope, got:\n{}",
        violations.join("\n")
    );
    // Test scope closes again after the module: the function after it is
    // production and must be flagged on its own line.
    let mixed = "#[cfg(test)]\nmod tests {\n    let password = \"x\";\n}\nfn production() {\n    let password = \"y\";\n}";
    let violations = scan_source_sample(mixed, false);
    assert_eq!(
        violations.len(),
        1,
        "only the production function must be flagged, got:\n{}",
        violations.join("\n")
    );
    assert!(
        violations[0].contains(":6:"),
        "hit must point at the production line, got: {}",
        violations[0]
    );
}

#[test]
fn strings_catalog_macro_bodies_are_copy_construction_not_secret_assignments() {
    // The catalog macro declares copy keys: the field name is an i18n key
    // and the literal is bilingual message copy — even when the key reads
    // like a secret (`error_bootstrap_code`, `field_password`), the binding
    // is not a secret assignment. The exemption is structural (the macro
    // body), so no value can be smuggled in as "catalog copy".
    let catalog = "\
strings_catalog! {
    label_bootstrap_code: \"Bootstrap code\", zh: \"引导码\",
    error_bootstrap_code: \"bootstrap failed\", zh: \"引导失败\",
    field_password: \"Password\", zh: \"密码\",
    label_totp_secret: \"Secret from your authenticator app\", zh: \"认证器应用中的密钥\",
}";
    let violations = scan_source_sample(catalog, false);
    assert!(
        violations.is_empty(),
        "catalog entries are copy, not secrets, got:\n{}",
        violations.join("\n")
    );
    // The exemption is the macro body, not the file: a secret assignment
    // after the closing brace is production and must be flagged.
    let after = "strings_catalog! {}\nlet password = \"hunter2\";";
    let violations = scan_source_sample(after, false);
    assert_eq!(
        violations.len(),
        1,
        "code after the catalog macro stays in [R1] scope, got:\n{}",
        violations.join("\n")
    );
}

#[test]
fn private_key_rule_requires_a_complete_block() {
    let full_blocks: &[&str] = &[
        "let pem = \"-----BEGIN RSA PRIVATE KEY-----\\nAAAA\\n-----END RSA PRIVATE KEY-----\\n\";",
        "let pem = \"-----BEGIN EC PRIVATE KEY-----\\nAAAA\\n-----END EC PRIVATE KEY-----\\n\";",
        "let pem = \"-----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\n-----END OPENSSH PRIVATE KEY-----\\n\";",
        "let pem = r\"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\";",
    ];
    for sample in full_blocks {
        let violations = scan_source_sample(sample, false);
        assert_eq!(
            violations.len(),
            1,
            "a complete PEM private-key block must be flagged by [R2], got:\n{}",
            violations.join("\n")
        );
        assert!(
            violations[0].contains("[R2]"),
            "unexpected violation: {}",
            violations[0]
        );
    }
    let passing: &[&str] = &[
        "let pem = \"-----BEGIN PRIVATE KEY-----\";",
        "let pem = \"-----END PRIVATE KEY-----\";",
        "let pem = \"-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----\\n\";",
        "let _ = writeln!(pem, \"-----BEGIN {label}-----\");",
    ];
    for sample in passing {
        let violations = scan_source_sample(sample, false);
        assert!(
            violations.is_empty(),
            "incomplete or non-key PEM text must pass [R2], got:\n{}",
            violations.join("\n")
        );
    }
}

#[test]
fn output_macro_rule_flags_secret_identifiers() {
    let flagged: &[(&str, &str)] = &[
        ("println!(\"{}\", password);", "`password`"),
        ("println!(\"{password}\");", "`password`"),
        ("eprintln!(\"{secret:?}\");", "`secret`"),
        ("tracing::error!(\"{credential}\");", "`credential`"),
        ("tracing::warn!(\"{session_token}\");", "`session_token`"),
        ("dbg!(token);", "`token`"),
        ("println!(\"{}\", raw_password);", "`raw_password`"),
    ];
    for (sample, needle) in flagged {
        let violations = scan_source_sample(sample, false);
        assert!(
            !violations.is_empty(),
            "sample `{sample}` must be flagged by [R3]"
        );
        assert!(
            violations.join("\n").contains(needle),
            "sample `{sample}` must mention `{needle}`, got:\n{}",
            violations.join("\n")
        );
    }
    let passing: &[&str] = &[
        "tracing::warn!(\"endpoint {endpoint_id} failed: {error}\");",
        "println!(\"total {count}\");",
        "println!(\"Rutilus bootstrap code: {raw_code}\");",
        "format!(\"{password:?}\");",
        "writeln!(f, \"{}\", password);",
        "tracing::info!(endpoint_id = 7, \"a structured record\");",
        "println!(\"{{password}}\");",
        "println!(\"Enter the code to set the administrator password.\");",
    ];
    for sample in passing {
        let violations = scan_source_sample(sample, false);
        assert!(
            violations.is_empty(),
            "sample `{sample}` must pass [R3], got:\n{}",
            violations.join("\n")
        );
    }
}
