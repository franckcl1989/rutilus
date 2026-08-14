//! §七 (known-limitations) down-order gate — mechanical enforcement of the
//! child-first drop discipline.
//!
//! The design's migration discipline (`docs/known-limitations.md` §七, the
//! deep-review batch commit 1711329) says a multi-table `down` drops every
//! referencing child table before the parent table it names — the foreign
//! key order — so the drop never cascades into rows the `down` is supposed
//! to remove. `m20260805_000005_operations.rs` drops `operation_targets`
//! before `operations`; `m20260805_000009_telemetry.rs` drops
//! `telemetry_samples` before `telemetry_series`. This gate mechanizes that
//! review discipline: it statically scans every `migration/src` migration
//! and fails when a `down` drops a parent before a child that references it.
//!
//! The dependency graph is extracted from the migration sources themselves —
//! no database, no compiled schema, the same pure-static shape as
//! `tests/bare_sql_gate.rs` (whose lexer this file shares verbatim so each
//! gate stays self-contained). Every `ForeignKey::create()` chain in a file
//! yields the edge `child → parent`, resolved from the `DeriveIden` enums
//! through the `#[sea_orm(iden = "...")]` table names, and raw
//! `ALTER TABLE ... ADD COLUMN ... REFERENCES ...` statements (the only way
//! `SQLite` adds a live foreign key, `m20260805_000011`'s `batch_id` link)
//! yield their edges too. The `REFERENCES` clauses of raw `CREATE TABLE`
//! rebuild DDL yield theirs as well — `m20260810_000001`'s six cascade
//! children and `m20260810_000002`'s `role_assignments` — with the
//! `*_rebuild` staging name normalized to the live table it is renamed into
//! (`SQLite` rewrites references on rename, so the live foreign key is the
//! renamed one). Edges from every file form one global graph — a
//! `down` may drop tables whose foreign keys were created in earlier
//! migrations: `m20260810_000001`'s rebuild drops `endpoints` and its six
//! children (`endpoint_addresses`, `endpoint_trust`, `endpoint_credentials`
//! — FKs in `m20260805_000001`; `endpoint_capabilities` — FK in
//! `m20260805_000002`; `resources` and its child `resource_snapshots` —
//! FKs in `m20260805_000003`), edges no single-file scan could see — and
//! each file's drop sequences are checked against that graph.
//!
//! Two drop sequences are checked per file:
//! - the `down` function body's `drop_table(Table::drop().table(X::Table))`
//!   calls and raw `DROP TABLE` statements, in source order;
//! - the file's drop statements file-wide, in source order — the builder
//!   `drop_table(...)` calls and the raw `DROP TABLE` statements merged by
//!   line. The `SQLite` rebuild helpers (`create_resource_tables_with`,
//!   `rebuild_audit_events`, `rebuild`, ...) that `up` and `down` both call
//!   keep their drops outside the `down` body — builder-style or raw — and
//!   the child-first discipline applies to them in both directions (the
//!   drop of the old parent would cascade into the old children either
//!   way). A helper's builder drops were once invisible to the file-wide
//!   scan (only the raw `DROP TABLE` statements were collected outside the
//!   `down` body); the scan now covers both shapes, so a parent-first order
//!   inside any helper the `down` calls is rejected like the same order
//!   written inline.
//!
//! False positives are controlled the same way `bare_sql_gate` controls
//! theirs: comments, doc comments, and attribute strings are stripped by the
//! lexer, and only `execute_unprepared` string literals (inline,
//! `const`-named, or an if/else over either) are scanned for raw SQL — prose
//! can never participate. A single-table `down` is never constrained (no
//! pair to order), and a pair without a foreign-key edge may drop in any
//! order. A circular pair (`A → B` and `B → A` both present) is not
//! constrained either: no total order satisfies a cycle, so the migration
//! must break it explicitly (000001 NULLs `credentials.active_version_id`
//! before dropping `credential_versions`) and the migration tests verify
//! that the resulting drops actually run. A drop whose table ident cannot be
//! resolved, or an unrecognized drop/foreign-key shape, is a gate failure —
//! never a silent skip, the same honesty rule as `bare_sql_gate`.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Lexer — copied verbatim from `bare_sql_gate.rs` (same lexing rules, so the
// two gates cannot disagree about what a comment or a string is).
// ---------------------------------------------------------------------------

/// One lexed token with the source line it started on.
#[derive(Debug, Clone)]
enum Token {
    Ident { line: usize, name: String },
    Str { line: usize, content: String },
    RawStr { line: usize, content: String },
    Punct { line: usize, ch: char },
}

impl Token {
    fn line(&self) -> usize {
        match self {
            Token::Ident { line, .. }
            | Token::Str { line, .. }
            | Token::RawStr { line, .. }
            | Token::Punct { line, .. } => *line,
        }
    }

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
            // Byte strings scan like their text counterparts.
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
            tokens.push(Token::Punct { line, ch: c });
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

// ---------------------------------------------------------------------------
// Raw-SQL statement helpers.
// ---------------------------------------------------------------------------

/// The bare SQL identifier of one whitespace-delimited word: surrounding
/// whitespace trimmed, bracket/quote characters stripped, a trailing
/// statement terminator (`;`) removed — a raw string may carry several
/// statements, so the terminator must never stick to the identifier — and
/// everything from an opening `(` (a column list like
/// `batch_operations(id)`) discarded. The column list is split off before
/// the quote stripping, so a quoted name with a column list
/// (`"weird;name"(id)`) loses both its quotes and its list.
fn sql_identifier(word: &str) -> &str {
    let name = word.split('(').next().unwrap_or(word);
    name.trim()
        .trim_start_matches(['[', '"', '`'])
        .trim_end_matches([']', '"', '`'])
        .trim_end_matches(';')
}

/// Strips SQL comments from one statement: `--` line comments (to the end
/// of the line, newline consumed) and `/* ... */` block comments, each
/// replaced by a single space so the words around it stay separate words.
///
/// Quoted regions are preserved verbatim — a `--` or `/*` inside them is
/// text, not a comment — in every spelling the `SQLite` grammar allows:
/// single-quoted string literals (`'...'`, a doubled `''` being the escaped
/// quote), double-quoted identifiers (`"..."`, a doubled `""` the escaped
/// quote), backtick-quoted identifiers (`` `...` ``), and bracket-quoted
/// identifiers (`[...]`, closed by the first `]`). An unterminated quote
/// runs to the end of the string, so a fragment never strips mid-quote.
/// (The same implementation `bare_sql_gate.rs` uses — the same quote
/// states the statement split [`split_sql_statements`] uses — so the two
/// gates cannot disagree about what a comment or a quoted region is.) A
/// comment between the words of a raw statement (`DROP /* reason */ TABLE
/// parents`) would otherwise hide the shape from the word scan, and comment
/// content could read like a shape; a comment marker inside a quoted
/// identifier (`DROP TABLE "weird--name"`) is identifier text, so the drop
/// names the whole quoted identifier and a following `;`-separated
/// statement survives the strip like any other.
fn strip_sql_comments(statement: &str) -> String {
    let chars: Vec<char> = statement.chars().collect();
    let mut stripped = String::with_capacity(statement.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '-' && chars.get(i + 1) == Some(&'-') {
            // A `--` line comment: replaced by one space, consumed through
            // the terminating newline — a comment glued to its neighbors
            // (`AS--c\nSELECT`) must still separate them.
            stripped.push(' ');
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            if i < chars.len() {
                i += 1;
            }
        } else if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            stripped.push(' ');
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
        } else if chars[i] == '\'' {
            stripped.push('\'');
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        stripped.push_str("''");
                        i += 2;
                        continue;
                    }
                    stripped.push('\'');
                    i += 1;
                    break;
                }
                stripped.push(chars[i]);
                i += 1;
            }
        } else if chars[i] == '"' || chars[i] == '`' {
            // A double-quoted or backtick-quoted `SQLite` identifier is
            // preserved verbatim, a doubled quote being the escaped quote.
            let quote = chars[i];
            stripped.push(quote);
            i += 1;
            while i < chars.len() {
                if chars[i] == quote {
                    if chars.get(i + 1) == Some(&quote) {
                        stripped.push(quote);
                        stripped.push(quote);
                        i += 2;
                        continue;
                    }
                    stripped.push(quote);
                    i += 1;
                    break;
                }
                stripped.push(chars[i]);
                i += 1;
            }
        } else if chars[i] == '[' {
            // A bracket-quoted `SQLite` identifier is preserved verbatim,
            // closed by the first `]`.
            stripped.push('[');
            i += 1;
            while i < chars.len() && chars[i] != ']' {
                stripped.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                stripped.push(']');
                i += 1;
            }
        } else {
            stripped.push(chars[i]);
            i += 1;
        }
    }
    stripped
}

/// Splits a raw SQL string into its `;`-separated statements. A `;` inside
/// a quoted identifier or string literal does not terminate the statement —
/// `SQLite` quotes identifiers with double quotes (`"..."`), backticks
/// (`` `...` ``), and square brackets (`[...]`), and string literals with
/// single quotes (`'...'`, a doubled `''` being the escaped quote) — so
/// `DROP TABLE "weird;name"` stays one statement and the quoted name keeps
/// its `;`. An unterminated quote runs to the end of the string, so a
/// fragment never splits mid-quote, and empty segments (a trailing
/// terminator) are dropped.
fn split_sql_statements(sql: &str) -> Vec<&str> {
    let chars: Vec<char> = sql.chars().collect();
    let mut statements = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\'' => {
                i += 1;
                while i < chars.len() {
                    if chars[i] == '\'' {
                        if chars.get(i + 1) == Some(&'\'') {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            '"' | '`' => {
                let quote = chars[i];
                i += 1;
                while i < chars.len() {
                    if chars[i] == quote {
                        if chars.get(i + 1) == Some(&quote) {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            '[' => {
                i += 1;
                while i < chars.len() && chars[i] != ']' {
                    i += 1;
                }
                if i < chars.len() {
                    i += 1;
                }
            }
            ';' => {
                if start < i {
                    statements.push(&sql[start..i]);
                }
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < sql.len() {
        statements.push(&sql[start..]);
    }
    statements
}

/// The whitespace words of every statement of one raw SQL string: SQL
/// comments are stripped first — a comment between keywords (`DROP /*
/// reason */ TABLE parents`) must not hide or fake a shape — and the
/// statements are then split quote-aware ([`split_sql_statements`]), so a
/// `;` inside a quoted identifier (`DROP TABLE "weird;name"`) never splits
/// the name, and a terminator glued to the next keyword (`parents;DROP`)
/// never hides the second statement.
fn statement_words(sql: &str) -> Vec<Vec<String>> {
    let stripped = strip_sql_comments(sql);
    split_sql_statements(&stripped)
        .into_iter()
        .map(|statement| statement.split_whitespace().map(str::to_owned).collect())
        .collect()
}

/// The tables a raw SQL string drops, in statement order: every `DROP TABLE`
/// (optionally `IF EXISTS`) occurrence with the following identifier. SQL
/// comments are stripped and the statements split quote-aware first
/// ([`statement_words`]), so a comment between the `DROP` and its `TABLE`
/// can no longer hide the drop from the scan, and a `;` inside a quoted
/// table name can no longer split it into a fictional drop.
fn drop_table_names(sql: &str) -> Vec<String> {
    let mut drops = Vec::new();
    for words in statement_words(sql) {
        let mut i = 0;
        while i < words.len() {
            if words[i].eq_ignore_ascii_case("DROP")
                && words
                    .get(i + 1)
                    .is_some_and(|w| w.eq_ignore_ascii_case("TABLE"))
            {
                let mut name_index = i + 2;
                if words
                    .get(name_index)
                    .is_some_and(|w| w.eq_ignore_ascii_case("IF"))
                {
                    name_index += 1;
                }
                if words
                    .get(name_index)
                    .is_some_and(|w| w.eq_ignore_ascii_case("EXISTS"))
                {
                    name_index += 1;
                }
                if let Some(name) = words.get(name_index) {
                    drops.push(sql_identifier(name).to_owned());
                }
                i = name_index + 1;
            } else {
                i += 1;
            }
        }
    }
    drops
}

/// Collects `const NAME: &str = <string literal>` declarations as
/// `name -> (line, statement)`.
fn const_literals(tokens: &[Token]) -> HashMap<String, (usize, String)> {
    let mut literals = HashMap::new();
    let mut i = 0;
    while i < tokens.len() {
        let is_const = matches!(&tokens[i], Token::Ident { name, .. } if name == "const")
            && matches!(&tokens.get(i + 1), Some(Token::Ident { .. }))
            && matches!(&tokens.get(i + 2), Some(Token::Punct { ch: ':', .. }));
        if !is_const {
            i += 1;
            continue;
        }
        let Token::Ident { name, .. } = &tokens[i + 1] else {
            i += 1;
            continue;
        };
        let mut value = None;
        let mut j = i + 3;
        while let Some(token) = tokens.get(j) {
            if token.is_punct('=') {
                if let Some(Token::Str { line, content } | Token::RawStr { line, content }) =
                    tokens.get(j + 1)
                {
                    value = Some((*line, content.clone()));
                }
                break;
            }
            if token.is_punct(';') {
                break;
            }
            j += 1;
        }
        if let Some(value) = value {
            literals.insert(name.clone(), value);
        }
        i += 1;
    }
    literals
}

/// The token slice inside every `execute_unprepared(...)` argument list.
fn execute_unprepared_arguments(tokens: &[Token]) -> Vec<Vec<Token>> {
    let mut arguments = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let is_call = matches!(&tokens[i], Token::Ident { name, .. } if name == "execute_unprepared")
            && matches!(&tokens.get(i + 1), Some(Token::Punct { ch: '(', .. }));
        if !is_call {
            i += 1;
            continue;
        }
        let mut depth = 1;
        let mut inner = Vec::new();
        let mut j = i + 2;
        while j < tokens.len() && depth > 0 {
            match &tokens[j] {
                Token::Punct { ch: '(', .. } => depth += 1,
                Token::Punct { ch: ')', .. } => depth -= 1,
                _ => {}
            }
            if depth > 0 {
                inner.push(tokens[j].clone());
            }
            j += 1;
        }
        arguments.push(inner);
        i = j;
    }
    arguments
}

/// The `(line, statement)` pairs one `execute_unprepared` argument runs.
///
/// An inline literal or an if/else over literals yields one entry per
/// literal; a plain `const` name (optionally `&`-referenced) resolves to the
/// const's literal. Anything else is rejected so a new argument shape shows
/// up as a gate failure instead of a silent skip.
fn argument_statements(
    argument: &[Token],
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(usize, String)>, String> {
    let inline: Vec<(usize, String)> = argument
        .iter()
        .filter_map(|token| match token {
            Token::Str { line, content } | Token::RawStr { line, content } => {
                Some((*line, content.clone()))
            }
            Token::Ident { .. } | Token::Punct { .. } => None,
        })
        .collect();
    // Honest gap: an argument containing any string literal is taken as that
    // statement regardless of the wrapper around it — a macro-wrapped inline
    // string (`sql!(...)`, `format!(...)`, ...) would be scanned verbatim and
    // the unrecognized wrapper would never fail the gate. None of the 23
    // current migrations has such a shape; if one appears, the scan could
    // miss what actually executes.
    if !inline.is_empty() {
        return Ok(inline);
    }
    let identifiers: Vec<&str> = argument
        .iter()
        .filter_map(|token| match token {
            Token::Ident { name, .. } => Some(name.as_str()),
            Token::Str { .. } | Token::RawStr { .. } | Token::Punct { .. } => None,
        })
        .collect();
    let [name] = identifiers.as_slice() else {
        return Err(
            "argument is neither a string literal, a `const` name, nor an if/else over literals"
                .to_owned(),
        );
    };
    let Some((line, statement)) = consts.get(*name) else {
        return Err(format!(
            "argument `{name}` does not name a `const` SQL statement"
        ));
    };
    Ok(vec![(*line, statement.clone())])
}

/// Collects the `.rs` files under `directory`, depth-first in name order,
/// as paths relative to `base` (the scanned tree's root).
fn collect_rs(
    directory: &Path,
    base: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, base, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.strip_prefix(base)?.to_path_buf());
        }
    }
    Ok(())
}

/// Lists every `migration/src` source file for scanning, relative to
/// `CARGO_MANIFEST_DIR`. The walk is recursive, so a `.rs` file in a newly
/// added subdirectory is covered automatically.
fn scanned_sources() -> Result<Vec<SourceTokens>, Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&directory, &directory, &mut files)?;
    files.sort();
    let mut sources = Vec::new();
    for file in files {
        let display = file.to_string_lossy().replace('\\', "/");
        let display_path = format!("src/{display}");
        let source = fs::read_to_string(directory.join(&file))?;
        sources.push(tokenize(&display_path, &source));
    }
    Ok(sources)
}

// ---------------------------------------------------------------------------
// Schema facts extracted from one file.
// ---------------------------------------------------------------------------

/// The token range `(start, end)` of the `async fn down` body, or `None`.
///
/// The signature holds no braces, so the first `{` after `fn down` opens the
/// body; braces inside string literals never become tokens, so brace
/// matching is exact.
fn down_body_range(tokens: &[Token]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i + 1 < tokens.len() {
        let is_down = matches!(&tokens[i], Token::Ident { name, .. } if name == "fn")
            && matches!(&tokens[i + 1], Token::Ident { name, .. } if name == "down");
        if !is_down {
            i += 1;
            continue;
        }
        let open = i
            + 2
            + tokens[i + 2..]
                .iter()
                .position(|token| token.is_punct('{'))?;
        let mut depth = 1;
        let mut j = open + 1;
        while j < tokens.len() && depth > 0 {
            match &tokens[j] {
                Token::Punct { ch: '{', .. } => depth += 1,
                Token::Punct { ch: '}', .. } => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        if depth == 0 {
            return Some((open + 1, j - 1));
        }
        return None;
    }
    None
}

/// Maps each `DeriveIden` enum to the SQL table name of its `Table` variant,
/// read from the `#[sea_orm(iden = "...")]` attribute directly above it.
///
/// Variants without that attribute (columns, `*_rebuild` shapes) never match
/// the attribute-plus-`Table` pattern, so they cannot pollute the map.
fn enum_table_names(tokens: &[Token]) -> HashMap<String, String> {
    let mut names = HashMap::new();
    let mut current_enum: Option<String> = None;
    let mut enum_depth = 0;
    let mut i = 0;
    while i < tokens.len() {
        if enum_depth == 0 {
            if matches!(&tokens[i], Token::Ident { name, .. } if name == "enum")
                && let Some(Token::Ident { name, .. }) = tokens.get(i + 1)
                && tokens.get(i + 2).is_some_and(|token| token.is_punct('{'))
            {
                current_enum = Some(name.clone());
                enum_depth = 1;
                i += 3;
                continue;
            }
            i += 1;
            continue;
        }
        match &tokens[i] {
            Token::Punct { ch: '{', .. } => enum_depth += 1,
            Token::Punct { ch: '}', .. } => {
                enum_depth -= 1;
                if enum_depth == 0 {
                    current_enum = None;
                }
            }
            Token::Str { content, .. } | Token::RawStr { content, .. }
                if tokens.get(i - 1).is_some_and(|token| token.is_punct('='))
                    && matches!(&tokens.get(i - 2), Some(Token::Ident { name, .. }) if name == "iden")
                    && tokens.get(i - 3).is_some_and(|token| token.is_punct('('))
                    && matches!(&tokens.get(i - 4), Some(Token::Ident { name, .. }) if name == "sea_orm")
                    && tokens.get(i - 5).is_some_and(|token| token.is_punct('['))
                    && tokens.get(i - 6).is_some_and(|token| token.is_punct('#'))
                    && tokens.get(i + 1).is_some_and(|token| token.is_punct(')'))
                    && tokens.get(i + 2).is_some_and(|token| token.is_punct(']'))
                    && matches!(&tokens.get(i + 3), Some(Token::Ident { name, .. }) if name == "Table") =>
            {
                if let Some(enum_name) = &current_enum {
                    names.insert(enum_name.clone(), content.clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    names
}

/// The foreign-key edges `child → parent` of one file, from every
/// `ForeignKey::create()` chain, resolved to SQL table names through the
/// file's iden map. Both the `from`/`to` and the `from_tbl`/`to_tbl` forms
/// are recognized.
fn foreign_key_edges(
    tokens: &[Token],
    enum_tables: &HashMap<String, String>,
) -> Result<Vec<(String, String)>, String> {
    let mut edges = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let anchor = matches!(&tokens[i], Token::Ident { name, .. } if name == "ForeignKey")
            && tokens.get(i + 1).is_some_and(|token| token.is_punct(':'))
            && tokens.get(i + 2).is_some_and(|token| token.is_punct(':'))
            && matches!(&tokens.get(i + 3), Some(Token::Ident { name, .. }) if name == "create")
            && tokens.get(i + 4).is_some_and(|token| token.is_punct('('));
        if !anchor {
            i += 1;
            continue;
        }
        let mut child = None;
        let mut parent = None;
        let mut j = i + 5;
        while j < tokens.len() {
            if matches!(&tokens[j], Token::Ident { name, .. } if name == "to_owned") {
                break;
            }
            let Token::Ident { name, .. } = &tokens[j] else {
                j += 1;
                continue;
            };
            let is_table_method = matches!(name.as_str(), "from" | "from_tbl" | "to" | "to_tbl")
                && tokens.get(j + 1).is_some_and(|token| token.is_punct('('));
            if is_table_method {
                let Some(Token::Ident {
                    name: enum_name, ..
                }) = tokens.get(j + 2)
                else {
                    return Err(format!(
                        "foreign key `{name}` does not take an enum table ident"
                    ));
                };
                if !(tokens.get(j + 3).is_some_and(|token| token.is_punct(':'))
                    && tokens.get(j + 4).is_some_and(|token| token.is_punct(':'))
                    && matches!(
                        &tokens.get(j + 5),
                        Some(Token::Ident { name, .. }) if name == "Table"
                    ))
                {
                    return Err(format!(
                        "foreign key `{name}` does not reference `SomeEnum::Table`"
                    ));
                }
                let Some(table) = enum_tables.get(enum_name) else {
                    return Err(format!(
                        "enum `{enum_name}` has no `#[sea_orm(iden)]` Table variant"
                    ));
                };
                match name.as_str() {
                    "from" | "from_tbl" => child = Some(table.clone()),
                    _ => parent = Some(table.clone()),
                }
            }
            j += 1;
        }
        // Honest gap: a chain whose `from`/`to` do not pair (one side
        // missing) silently yields no edge instead of a gate failure — the
        // edge, and any ordering constraint it would carry, is simply absent.
        // Every current migration writes both sides; a future unpaired chain
        // would be silently skipped, not reported.
        if let (Some(child), Some(parent)) = (child, parent) {
            edges.push((child, parent));
        }
        i += 1;
    }
    Ok(edges)
}

/// The foreign-key edges `child → parent` defined by raw SQL: every
/// `ALTER TABLE <table> ... REFERENCES <other>(...)` statement adds the edge
/// `<table> → <other>`. This is the only way `SQLite` adds a live foreign
/// key to an existing table (`m20260805_000011`'s `operations.batch_id`
/// link, `m20260810_000001`'s `endpoints.site_id`). The statements are
/// scanned comment-stripped and one by one ([`statement_words`]), so a
/// comment or a second `;`-separated statement can neither hide nor fake a
/// `REFERENCES` clause. The rebuild `RENAME TO` tails never carry a
/// `REFERENCES` clause, so they contribute nothing here — the edges of the
/// raw `CREATE TABLE` rebuild DDL itself are read by
/// [`raw_create_table_references`], and the live-table renames by
/// [`raw_renames`].
fn raw_alter_references(
    tokens: &[Token],
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(String, String)>, String> {
    let mut edges = Vec::new();
    for argument in execute_unprepared_arguments(tokens) {
        for (_line, statement) in argument_statements(&argument, consts)? {
            for words in statement_words(&statement) {
                if !words
                    .first()
                    .is_some_and(|word| word.eq_ignore_ascii_case("ALTER"))
                {
                    continue;
                }
                let Some(altered) = words.get(2).map(|word| sql_identifier(word)) else {
                    continue;
                };
                let Some(position) = words
                    .iter()
                    .position(|word| word.eq_ignore_ascii_case("REFERENCES"))
                else {
                    continue;
                };
                if let Some(referenced) = words.get(position + 1).map(|word| sql_identifier(word)) {
                    edges.push((altered.to_owned(), referenced.to_owned()));
                }
            }
        }
    }
    Ok(edges)
}

/// Whether `name` is one of the staging patterns the rebuild normalization
/// already covers (`*_rebuild`, `*_new`, `*_old`): a `RENAME TO` a staging
/// name is part of a rebuild dance, never a live table being renamed.
fn is_staging_name(name: &str) -> bool {
    ["_rebuild", "_new", "_old"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// The live-table renames of one file's raw SQL: every
/// `ALTER TABLE <x> RENAME TO <y>` statement whose new name is a live table
/// — not one of the staging patterns ([`is_staging_name`]) the existing
/// normalization covers. Renaming a live table redirects every reference to
/// it (`SQLite` rewrites the foreign keys of tables that name the renamed
/// table), so the FK edge set must follow the rename — the semantic is
/// rename-means-references-follow. [`apply_renames`] re-points the global
/// edges from `x` to `y` (an edge that already names `y` merges with the
/// redirected one). The current tree's `RENAME` statements are all rebuild
/// tails (`x_rebuild RENAME TO x`, `x_new RENAME TO x`, ...): the raw-rebuild
/// edges are normalized to the live names already and the builder-staging
/// edges get normalized by exactly this redirect, so the closure stays
/// coherent — and the guard on `y` keeps the reverse dance (`RENAME TO
/// x_new`) a no-op.
fn raw_renames(
    tokens: &[Token],
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(String, String)>, String> {
    let mut renames = Vec::new();
    for argument in execute_unprepared_arguments(tokens) {
        for (_line, statement) in argument_statements(&argument, consts)? {
            for words in statement_words(&statement) {
                let is_rename = words
                    .first()
                    .is_some_and(|word| word.eq_ignore_ascii_case("ALTER"))
                    && words
                        .get(1)
                        .is_some_and(|word| word.eq_ignore_ascii_case("TABLE"))
                    && words
                        .get(3)
                        .is_some_and(|word| word.eq_ignore_ascii_case("RENAME"))
                    && words
                        .get(4)
                        .is_some_and(|word| word.eq_ignore_ascii_case("TO"));
                if !is_rename {
                    continue;
                }
                let Some(from) = words.get(2).map(|word| sql_identifier(word)) else {
                    continue;
                };
                let Some(to) = words.get(5).map(|word| sql_identifier(word)) else {
                    continue;
                };
                if is_staging_name(to) {
                    continue;
                }
                renames.push((from.to_owned(), to.to_owned()));
            }
        }
    }
    Ok(renames)
}

/// Applies every raw `ALTER TABLE x RENAME TO y` to the FK edge set: an
/// edge naming the renamed table on either side follows the rename — the
/// referencing children (`children → x` is the live `children → y` after
/// the rename) and the renamed table's own outgoing edges (`x → p` is the
/// live `y → p`). An edge that already names `y` merges with the redirected
/// one; the callers dedup afterwards.
fn apply_renames(edges: &mut [(String, String)], renames: &[(String, String)]) {
    for (from, to) in renames {
        for edge in edges.iter_mut() {
            if edge.0 == *from {
                edge.0.clone_from(to);
            }
            if edge.1 == *from {
                edge.1.clone_from(to);
            }
        }
    }
}

/// The live table a `*_rebuild` staging name stands for: the `_rebuild`
/// suffix is stripped, because the rebuild tail renames the staging table
/// into the live table and `SQLite` rewrites its foreign keys on rename.
fn live_table_name(name: &str) -> &str {
    name.strip_suffix("_rebuild").unwrap_or(name)
}

/// The foreign-key edges `child → parent` defined by raw `CREATE TABLE`
/// rebuild DDL: every `REFERENCES <other>(...)` clause in the created
/// table's body adds the edge `<table> → <other>`, whether the clause is
/// inline in a column definition (`site_id UUID NULL REFERENCES
/// instances(id)`) or inside a table-level `CONSTRAINT ... FOREIGN KEY`
/// (`m20260810_000002`'s two `principals(id)` links).
///
/// The rebuild staging tables are created under the `<table>_rebuild` name
/// and renamed into place afterwards
/// (`ALTER TABLE <table>_rebuild RENAME TO <table>`), so
/// [`live_table_name`] is applied to both sides of every
/// edge: `role_assignments_rebuild REFERENCES instances(id)` is the live
/// `role_assignments → instances` edge, the six `endpoints_rebuild`
/// children of `m20260810_000001` normalize to their live `→ endpoints`
/// edges, and a staging table referencing its own `*_rebuild` parent
/// (`endpoints_rebuild → endpoints_rebuild`) normalizes to a self-edge that
/// the order check skips. A `CREATE TABLE IF NOT EXISTS` statement (none in
/// the current migrations) is skipped by the `IF` guard rather than
/// misread.
fn raw_create_table_references(
    tokens: &[Token],
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(String, String)>, String> {
    let mut edges = Vec::new();
    for argument in execute_unprepared_arguments(tokens) {
        for (_line, statement) in argument_statements(&argument, consts)? {
            // The statements are scanned comment-stripped and one by one,
            // like [`raw_alter_references`]: a comment between `CREATE` and
            // `TABLE` — or between the shape's words — must not hide the
            // statement, and a second `;`-separated statement must be read
            // on its own.
            for words in statement_words(&statement) {
                if !(words
                    .first()
                    .is_some_and(|word| word.eq_ignore_ascii_case("CREATE"))
                    && words
                        .get(1)
                        .is_some_and(|word| word.eq_ignore_ascii_case("TABLE")))
                {
                    continue;
                }
                if words
                    .get(2)
                    .is_some_and(|word| word.eq_ignore_ascii_case("IF"))
                {
                    continue;
                }
                let Some(created) = words.get(2).map(|word| sql_identifier(word)) else {
                    continue;
                };
                let created = live_table_name(created).to_owned();
                for position in words.iter().enumerate().filter_map(|(position, word)| {
                    word.eq_ignore_ascii_case("REFERENCES").then_some(position)
                }) {
                    let Some(referenced) = words.get(position + 1).map(|word| sql_identifier(word))
                    else {
                        continue;
                    };
                    edges.push((created.clone(), live_table_name(referenced).to_owned()));
                }
            }
        }
    }
    Ok(edges)
}

// ---------------------------------------------------------------------------
// Drop sequences.
// ---------------------------------------------------------------------------

/// The tables dropped by every `drop_table(...)` call in a token slice,
/// resolved through the file's iden map, in source order. A drop whose
/// argument is not the `table(X::Table)` shape, or whose `X` has no iden
/// mapping, is a gate failure — a new drop shape must never silently skip
/// the check.
fn builder_drop_targets(
    tokens: &[Token],
    enum_tables: &HashMap<String, String>,
) -> Result<Vec<(usize, String)>, String> {
    let mut drops = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let is_drop = matches!(&tokens[i], Token::Ident { name, .. } if name == "drop_table")
            && tokens.get(i + 1).is_some_and(|token| token.is_punct('('));
        if !is_drop {
            i += 1;
            continue;
        }
        let line = tokens[i].line();
        let mut target = None;
        let mut depth = 1;
        let mut j = i + 2;
        while j < tokens.len() && depth > 0 {
            match &tokens[j] {
                Token::Punct { ch: '(', .. } => depth += 1,
                Token::Punct { ch: ')', .. } => depth -= 1,
                _ => {}
            }
            if depth == 1
                && matches!(&tokens[j], Token::Ident { name, .. } if name == "table")
                && tokens.get(j + 1).is_some_and(|token| token.is_punct('('))
                && let Some(Token::Ident {
                    name: enum_name, ..
                }) = tokens.get(j + 2)
                && tokens.get(j + 3).is_some_and(|token| token.is_punct(':'))
                && tokens.get(j + 4).is_some_and(|token| token.is_punct(':'))
                && matches!(
                    &tokens.get(j + 5),
                    Some(Token::Ident { name, .. }) if name == "Table"
                )
            {
                let Some(table) = enum_tables.get(enum_name) else {
                    return Err(format!(
                        "`{enum_name}::Table` has no `#[sea_orm(iden)]` mapping"
                    ));
                };
                target = Some(table.clone());
                break;
            }
            j += 1;
        }
        let Some(target) = target else {
            return Err(format!(
                "drop_table call on line {line} has no `table(X::Table)` argument shape"
            ));
        };
        drops.push((line, target));
        i = j + 1;
    }
    Ok(drops)
}

/// The raw `DROP TABLE` statements of every `execute_unprepared` argument in
/// a token slice, resolved through the file's `const` literals.
fn raw_drop_statements(
    tokens: &[Token],
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(usize, String)>, String> {
    let mut drops = Vec::new();
    for argument in execute_unprepared_arguments(tokens) {
        for (line, statement) in argument_statements(&argument, consts)? {
            for table in drop_table_names(&statement) {
                drops.push((line, table));
            }
        }
    }
    Ok(drops)
}

/// Keeps one entry per table (its first occurrence), preserving order.
fn distinct_first(mut drops: Vec<(usize, String)>) -> Vec<(usize, String)> {
    let mut seen = std::collections::HashSet::new();
    drops.retain(|(_, table)| seen.insert(table.clone()));
    drops
}

/// The `down` body's drop sequence: builder drops and raw `DROP TABLE`
/// statements merged in source order, one entry per table.
fn down_drop_sequence(
    tokens: &[Token],
    range: (usize, usize),
    enum_tables: &HashMap<String, String>,
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(usize, String)>, String> {
    let body = &tokens[range.0..range.1];
    let mut drops = builder_drop_targets(body, enum_tables)?;
    drops.extend(raw_drop_statements(body, consts)?);
    drops.sort_by_key(|(line, _)| *line);
    Ok(distinct_first(drops))
}

/// The file-wide drop sequence (first occurrence per table): every builder
/// `drop_table(...)` call and every raw `DROP TABLE` statement merged in
/// source order — the `SQLite` rebuild helpers that `up` and `down` both
/// call keep their drops outside the `down` body, builder-style or raw.
///
/// The builder shape is collected file-wide exactly like the raw shape
/// (T1-3): a helper's drops were previously invisible to this sequence
/// unless the `down` body itself named them, so a parent-first order inside
/// a shared helper slipped past the gate.
fn file_wide_drop_sequence(
    tokens: &[Token],
    enum_tables: &HashMap<String, String>,
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(usize, String)>, String> {
    let mut drops = builder_drop_targets(tokens, enum_tables)?;
    drops.extend(raw_drop_statements(tokens, consts)?);
    drops.sort_by_key(|(line, _)| *line);
    Ok(distinct_first(drops))
}

// ---------------------------------------------------------------------------
// The check.
// ---------------------------------------------------------------------------

/// Violations of the child-first rule in one drop sequence: every FK edge
/// whose two tables both appear must drop the child before the parent. A
/// pair without an edge, or a single-table sequence, is never constrained.
///
/// Edges of a circular pair (`A → B` and `B → A` both present) are not
/// constrained: no total drop order satisfies a cycle, so the migration must
/// break the cycle explicitly — `m20260805_000001` NULLs
/// `credentials.active_version_id` before dropping `credential_versions` —
/// and the migration tests verify that the resulting drops actually run.
fn check_order(path: &str, drops: &[(usize, String)], edges: &[(String, String)]) -> Vec<String> {
    let positions: HashMap<&str, usize> = drops
        .iter()
        .enumerate()
        .map(|(position, (_, table))| (table.as_str(), position))
        .collect();
    // `(parent, child)` for every edge, so an edge is circular exactly when
    // its reversed form is present.
    let reversed: std::collections::HashSet<(&str, &str)> = edges
        .iter()
        .map(|(child, parent)| (parent.as_str(), child.as_str()))
        .collect();
    let mut violations = Vec::new();
    for (child, parent) in edges {
        if child == parent {
            continue;
        }
        if reversed.contains(&(child.as_str(), parent.as_str())) {
            continue;
        }
        let (Some(&child_position), Some(&parent_position)) = (
            positions.get(child.as_str()),
            positions.get(parent.as_str()),
        ) else {
            continue;
        };
        if child_position < parent_position {
            continue;
        }
        let (parent_line, _) = drops[parent_position];
        let (child_line, _) = drops[child_position];
        violations.push(format!(
            "{path}:{parent_line}: `down` drops `{parent}` before its referencing child \
             `{child}` (dropped at line {child_line}); the FK {child} -> {parent} requires \
             the child first",
        ));
    }
    violations.sort();
    violations
}

/// All child-first violations of one migration file against the given
/// (global) FK edge set.
fn order_violations_for(
    source: &SourceTokens,
    edges: &[(String, String)],
) -> Result<Vec<String>, String> {
    let enum_tables = enum_table_names(&source.tokens);
    let consts = const_literals(&source.tokens);
    let mut violations = Vec::new();
    if let Some(range) = down_body_range(&source.tokens) {
        let drops = down_drop_sequence(&source.tokens, range, &enum_tables, &consts)?;
        violations.extend(check_order(&source.display_path, &drops, edges));
    }
    let file_drops = file_wide_drop_sequence(&source.tokens, &enum_tables, &consts)?;
    violations.extend(check_order(&source.display_path, &file_drops, edges));
    Ok(violations)
}

/// The full gate: every migration file's drop sequences must drop every FK
/// child before its parent. The FK edge set is aggregated across all files,
/// because a `down` may drop tables whose foreign keys were created in an
/// earlier migration (`m20260810_000001`'s rebuild drops `endpoints` and its
/// six children — FKs spread across `m20260805_000001`, `m20260805_000002`,
/// and `m20260805_000003`).
fn migration_down_order_violations() -> Result<Vec<String>, Box<dyn Error>> {
    let sources = scanned_sources()?;
    let mut edges = Vec::new();
    let mut renames = Vec::new();
    for source in &sources {
        let enum_tables = enum_table_names(&source.tokens);
        let consts = const_literals(&source.tokens);
        edges.extend(foreign_key_edges(&source.tokens, &enum_tables)?);
        edges.extend(raw_alter_references(&source.tokens, &consts)?);
        edges.extend(raw_create_table_references(&source.tokens, &consts)?);
        renames.extend(raw_renames(&source.tokens, &consts)?);
    }
    apply_renames(&mut edges, &renames);
    edges.sort();
    edges.dedup();
    let mut violations = Vec::new();
    for source in &sources {
        violations.extend(order_violations_for(source, &edges)?);
    }
    Ok(violations)
}

#[test]
fn migration_down_drops_children_before_parents() -> Result<(), Box<dyn Error>> {
    let violations = migration_down_order_violations()?;
    assert!(
        violations.is_empty(),
        "migration/src violates the child-first drop discipline:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate self-checks: a regression in the gate itself (a dropped shape, a
// missed edge source, a loosened check) must fail these tests, exactly like
// the checks they guard.
// ---------------------------------------------------------------------------

/// Builds the FK edge set of one synthetic file the way the full gate does.
fn synthetic_edges(tokens: &[Token]) -> Result<Vec<(String, String)>, String> {
    let enum_tables = enum_table_names(tokens);
    let consts = const_literals(tokens);
    let mut edges = foreign_key_edges(tokens, &enum_tables)?;
    edges.extend(raw_alter_references(tokens, &consts)?);
    edges.extend(raw_create_table_references(tokens, &consts)?);
    let renames = raw_renames(tokens, &consts)?;
    apply_renames(&mut edges, &renames);
    edges.sort();
    edges.dedup();
    Ok(edges)
}

/// A two-table migration (`children` referencing `parents`) whose `down`
/// drops the tables in the requested order. The parent-first variant is the
/// exact violation the gate exists to catch.
fn two_table_source(drop_child_first: bool) -> String {
    let down = if drop_child_first {
        "manager.drop_table(Table::drop().table(Child::Table).to_owned()).await?;
         manager.drop_table(Table::drop().table(Parent::Table).to_owned()).await"
    } else {
        "manager.drop_table(Table::drop().table(Parent::Table).to_owned()).await?;
         manager.drop_table(Table::drop().table(Child::Table).to_owned()).await"
    };
    format!(
        r#"use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        manager
            .create_table(
                Table::create()
                    .table(Parent::Table)
                    .col(ColumnDef::new(Parent::Id).uuid().not_null().primary_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Child::Table)
                    .col(ColumnDef::new(Child::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Child::ParentId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_children_parent")
                            .from(Child::Table, Child::ParentId)
                            .to(Parent::Table, Parent::Id)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        {down}
    }}
}}

#[derive(DeriveIden)]
enum Parent {{
    #[sea_orm(iden = "parents")]
    Table,
    Id,
}}

#[derive(DeriveIden)]
enum Child {{
    #[sea_orm(iden = "children")]
    Table,
    Id,
    ParentId,
}}
"#
    )
}

#[test]
fn gate_rejects_parent_before_child_down() -> Result<(), Box<dyn Error>> {
    let source = tokenize("synthetic_two_table.rs", &two_table_source(false));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.iter().any(|violation| {
            violation.contains("synthetic_two_table.rs")
                && violation.contains("parents")
                && violation.contains("children")
        }),
        "expected a child-first violation, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

#[test]
fn gate_accepts_child_before_parent_down() -> Result<(), Box<dyn Error>> {
    let source = tokenize("synthetic_two_table.rs", &two_table_source(true));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "child-first down must pass, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A two-table migration whose `down` drops the tables through raw
/// `execute_unprepared("DROP TABLE ...")` statements instead of the builder.
fn raw_drop_source(parent_first: bool) -> String {
    let drops = if parent_first {
        r#"connection.execute_unprepared("DROP TABLE parents").await?;
        connection.execute_unprepared("DROP TABLE children").await"#
    } else {
        r#"connection.execute_unprepared("DROP TABLE children").await?;
        connection.execute_unprepared("DROP TABLE parents").await"#
    };
    format!(
        r#"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        manager
            .create_table(
                Table::create()
                    .table(Parent::Table)
                    .col(ColumnDef::new(Parent::Id).uuid().not_null().primary_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Child::Table)
                    .col(ColumnDef::new(Child::ParentId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Child::Table, Child::ParentId)
                            .to(Parent::Table, Parent::Id)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        let connection = manager.get_connection();
        {drops}
    }}
}}

#[derive(DeriveIden)]
enum Parent {{
    #[sea_orm(iden = "parents")]
    Table,
    Id,
}}

#[derive(DeriveIden)]
enum Child {{
    #[sea_orm(iden = "children")]
    Table,
    Id,
    ParentId,
}}
"#
    )
}

#[test]
fn gate_checks_raw_sql_drop_order_in_down_body() -> Result<(), Box<dyn Error>> {
    let source = tokenize("synthetic_raw_drop.rs", &raw_drop_source(true));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("parents")),
        "raw parent-first drops must be rejected, got:\n{}",
        violations.join("\n"),
    );
    let source = tokenize("synthetic_raw_drop.rs", &raw_drop_source(false));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "raw child-first drops must pass, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A two-table migration whose `down` drops both tables through ONE raw
/// `execute_unprepared` string carrying the two statements separated by a
/// semicolon, in the requested order.
fn semicolon_drop_source(parent_first: bool) -> String {
    let drops = if parent_first {
        r#"connection.execute_unprepared("DROP TABLE parents; DROP TABLE children").await"#
    } else {
        r#"connection.execute_unprepared("DROP TABLE children; DROP TABLE parents").await"#
    };
    format!(
        r#"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        manager
            .create_table(
                Table::create()
                    .table(Parent::Table)
                    .col(ColumnDef::new(Parent::Id).uuid().not_null().primary_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Child::Table)
                    .col(ColumnDef::new(Child::ParentId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Child::Table, Child::ParentId)
                            .to(Parent::Table, Parent::Id)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        let connection = manager.get_connection();
        {drops}
    }}
}}

#[derive(DeriveIden)]
enum Parent {{
    #[sea_orm(iden = "parents")]
    Table,
    Id,
}}

#[derive(DeriveIden)]
enum Child {{
    #[sea_orm(iden = "children")]
    Table,
    Id,
    ParentId,
}}
"#
    )
}

/// The semicolon blind spot (R6-D-1): a raw string carrying several `DROP
/// TABLE` statements separated by `;` used to leave the terminator glued to
/// the identifier (`parents;`), so the drop never matched its FK edge and
/// the parent-first order passed silently. The statements must be split and
/// checked in statement order — a parent-first pair inside one string is a
/// violation exactly like the same pair in two calls.
#[test]
fn gate_checks_multi_statement_raw_drops_separated_by_semicolons() -> Result<(), Box<dyn Error>> {
    let source = tokenize("synthetic_semicolon.rs", &semicolon_drop_source(true));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations
            .iter()
            .any(|violation| { violation.contains("parents") && violation.contains("children") }),
        "parent-first drops inside one semicolon-separated string must be rejected, got:\n{}",
        violations.join("\n"),
    );
    let source = tokenize("synthetic_semicolon.rs", &semicolon_drop_source(false));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "child-first drops inside one semicolon-separated string must pass, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A two-table migration whose `down` drops both tables through ONE raw
/// `execute_unprepared` string with a SQL comment between the `DROP` and
/// the `TABLE` keyword, in the requested order.
fn comment_drop_source(parent_first: bool, comment: &str) -> String {
    let order = if parent_first {
        "parents; DROP TABLE children"
    } else {
        "children; DROP TABLE parents"
    };
    format!(
        r#"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE children ADD COLUMN parent_id UUID NULL REFERENCES parents(id)",
            )
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        let connection = manager.get_connection();
        connection
            .execute_unprepared("DROP {comment} TABLE {order}")
            .await
    }}
}}
"#
    )
}

/// The W7-D-5 blind spot ①: a SQL comment inside a drop statement used to
/// hide the drop from the word scan — `DROP /* reason */ TABLE parents`
/// leaves `/*` as the word after `DROP`, the drop vanished from the
/// sequence, and the parent-first order passed silently. Comments are
/// stripped before the words are compared, in both the `/* */` and the `--`
/// spellings, so the hidden drop constrains the order like any other.
#[test]
fn gate_checks_sql_comments_cannot_hide_raw_drops() -> Result<(), Box<dyn Error>> {
    // The `--` comment must end its line (a line comment runs to the
    // newline), so the block form splits the keywords in place while the
    // line form splits across the newline — both must surface the drop.
    for comment in ["/* retired shape */", "-- retired shape\n"] {
        let source = tokenize(
            "synthetic_comment_drop.rs",
            &comment_drop_source(true, comment),
        );
        let edges = synthetic_edges(&source.tokens)?;
        assert!(
            edges.contains(&("children".to_owned(), "parents".to_owned())),
            "the raw ALTER REFERENCES clause must yield the edge, got: {edges:?}",
        );
        let violations = order_violations_for(&source, &edges)?;
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("parents") && violation.contains("children")),
            "the comment-hidden parent-first drop must be rejected, got:\n{}",
            violations.join("\n"),
        );
        let source = tokenize(
            "synthetic_comment_drop.rs",
            &comment_drop_source(false, comment),
        );
        let edges = synthetic_edges(&source.tokens)?;
        let violations = order_violations_for(&source, &edges)?;
        assert!(
            violations.is_empty(),
            "the child-first order must pass with the comment stripped, got:\n{}",
            violations.join("\n"),
        );
    }
    Ok(())
}

/// A two-table migration whose `up` links `children` to `parents` through a
/// raw `ALTER ... REFERENCES` statement and renames `parents` to
/// `ancestors`; the `down` drops the tables in the requested order.
fn rename_source(parent_first: bool) -> String {
    let drops = if parent_first {
        r#"connection.execute_unprepared("DROP TABLE ancestors").await?;
        connection.execute_unprepared("DROP TABLE children").await"#
    } else {
        r#"connection.execute_unprepared("DROP TABLE children").await?;
        connection.execute_unprepared("DROP TABLE ancestors").await"#
    };
    format!(
        r#"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        let connection = manager.get_connection();
        connection
            .execute_unprepared(
                "ALTER TABLE children ADD COLUMN parent_id UUID NULL REFERENCES parents(id)",
            )
            .await?;
        connection
            .execute_unprepared("ALTER TABLE parents RENAME TO ancestors")
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        let connection = manager.get_connection();
        {drops}
    }}
}}
"#
    )
}

/// The W7-D-5 blind spot ②: `ALTER TABLE x RENAME TO y` on a live table
/// used to leave the FK edge set pointing at the old name — the edge
/// extraction read only `REFERENCES` clauses — so a `down` that drops the
/// renamed table before its referencing children was never constrained.
/// Rename means references follow (`SQLite` rewrites them on rename): the
/// edges naming the old table on either side are re-pointed at the new
/// name, and the parent-first drop of the new name is rejected against the
/// redirected edge.
#[test]
fn gate_redirects_fk_edges_through_live_table_renames() -> Result<(), Box<dyn Error>> {
    let source = tokenize("synthetic_rename.rs", &rename_source(true));
    let edges = synthetic_edges(&source.tokens)?;
    assert!(
        edges.contains(&("children".to_owned(), "ancestors".to_owned())),
        "the rename must redirect the edge to the live name, got: {edges:?}",
    );
    assert!(
        !edges.iter().any(|(_, parent)| parent == "parents"),
        "no edge may keep the pre-rename name, got: {edges:?}",
    );
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("ancestors") && violation.contains("children")),
        "dropping the renamed parent before its child must be rejected, got:\n{}",
        violations.join("\n"),
    );

    let source = tokenize("synthetic_rename.rs", &rename_source(false));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "the child-first drop must pass with the redirected edge, got:\n{}",
        violations.join("\n"),
    );

    // A second edge already naming the new table merges with the redirected
    // one — the aggregate dedups, so no duplicate constraint is reported.
    let merged = rename_source(false).replace(
        "ALTER TABLE parents RENAME TO ancestors",
        "ALTER TABLE parents RENAME TO ancestors; \
         ALTER TABLE siblings ADD COLUMN parent_id UUID NULL REFERENCES ancestors(id)",
    );
    let source = tokenize("synthetic_rename.rs", &merged);
    let edges = synthetic_edges(&source.tokens)?;
    let redirected = edges
        .iter()
        .filter(|(_, parent)| parent == "ancestors")
        .count();
    assert_eq!(
        redirected, 2,
        "the redirected edge must merge with the pre-existing one, got: {edges:?}",
    );

    // A `RENAME TO` a staging name is a rebuild dance, not a live rename:
    // the edge set must keep the original name.
    let staging = rename_source(false).replace(
        "ALTER TABLE parents RENAME TO ancestors",
        "ALTER TABLE parents RENAME TO parents_rebuild",
    );
    let source = tokenize("synthetic_rename.rs", &staging);
    let edges = synthetic_edges(&source.tokens)?;
    assert!(
        edges.contains(&("children".to_owned(), "parents".to_owned())),
        "a staging-pattern rename must not redirect, got: {edges:?}",
    );
    Ok(())
}

/// The W7-D-5 blind spot ③: a `;` inside a quoted identifier used to split
/// the statement — `DROP TABLE "weird;name"` recorded a fictional drop of
/// `"weird` while the real drop was skipped. The statement split is
/// quote-aware, so the quoted name stays whole, and an FK edge built
/// against the quoted name constrains the drop like any other.
#[test]
fn gate_keeps_quoted_identifiers_whole_across_statement_splitting() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        drop_table_names(r#"DROP TABLE "weird;name"; DROP TABLE children"#),
        vec!["weird;name", "children"],
        "a `;` inside a double-quoted identifier must not split the name",
    );
    assert_eq!(
        drop_table_names("DROP TABLE [weird;name]; DROP TABLE `other;x`"),
        vec!["weird;name", "other;x"],
        "bracket- and backtick-quoted names must stay whole too",
    );
    // The quoted name participates in the child-first check end to end: an
    // edge built against `weird;name` constrains a drop that names it. The
    // SQL strings are written as raw strings so the quotes reach the gate
    // lexer unescaped (the lexer keeps `\"` verbatim).
    let source = r##"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE TABLE children (parent_id UUID NOT NULL REFERENCES "weird;name"(id))"#,
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared(r#"DROP TABLE "weird;name""#)
            .await?;
        connection.execute_unprepared("DROP TABLE children").await
    }
}
"##;
    let source = tokenize("synthetic_quoted_name.rs", source);
    let edges = synthetic_edges(&source.tokens)?;
    assert!(
        edges.contains(&("children".to_owned(), "weird;name".to_owned())),
        "the quoted REFERENCES clause must yield the edge, got: {edges:?}",
    );
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("weird;name") && violation.contains("children")),
        "the parent-first drop of the quoted name must be rejected, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// The W9-T-3 unterminated-quote shape: a quote that never closes runs to
/// the end of the string — the stripper keeps every character past the
/// opening quote (a `--` or `/*` there is identifier text, not a comment)
/// and the splitter never terminates the statement on a `;` inside the
/// unclosed region, so a raw `DROP TABLE` is never cut short into a
/// fictional drop. Unreachable in the tree (every raw statement is
/// well-formed DDL), but the documented "run to end of string" semantics
/// are pinned here — the same shape is pinned in `bare_sql_gate.rs`, and
/// the sister-gate comparison test asserts the two implementations agree
/// on it.
#[test]
fn gate_runs_unterminated_quotes_to_the_end_of_the_string() {
    // ① The statement split: the `;` inside the unclosed region is not a
    // terminator — one statement holding every following word, not two.
    assert_eq!(
        split_sql_statements(r#"DROP TABLE "unterminated; DROP TABLE children"#),
        vec![r#"DROP TABLE "unterminated; DROP TABLE children"#],
        "a `;` inside an unterminated quote is not a terminator"
    );
    // ② The stripper: a `--` past the unclosed quote is identifier text,
    // never a comment — the stripped result is the input verbatim.
    assert_eq!(
        strip_sql_comments(r#"DROP TABLE "unterminated -- not a comment"#),
        r#"DROP TABLE "unterminated -- not a comment"#,
        "a comment marker inside an unterminated quote is text"
    );
    // ③ End to end: the unclosed fragment yields one drop whose name is
    // the whole swallowed text — the trailing `;` is identifier
    // punctuation, stripped from the name, and the following `DROP TABLE`
    // is part of the same statement, not a second drop.
    assert_eq!(
        drop_table_names(r#"DROP TABLE "unterminated; DROP TABLE children"#),
        vec!["unterminated", "children"],
        "the unclosed quote swallows the `;` and the following drop into \
         one statement"
    );
}

/// The W8-W-1 blind spot: the stripper used to protect only single-quoted
/// literals, so a comment marker inside a quoted identifier (`"a--b"`,
/// `` `a--b` ``, `[a--b]`) was read as a comment start. `DROP TABLE
/// "weird--name"` recorded a fictional drop of `weird` while the real drop
/// was skipped, and a `;`-separated drop after the quoted name was swallowed
/// with the comment — a parent-first pair could pass with its child drop
/// erased, and a fictional drop could constrain an unrelated pair. All four
/// quote spellings are preserved verbatim now (the same quote states
/// `bare_sql_gate`'s stripper uses, so the two gates cannot disagree), so
/// the quoted name drops whole and the following statement still constrains
/// the order.
#[test]
fn gate_keeps_quoted_identifiers_whole_against_comment_markers() -> Result<(), Box<dyn Error>> {
    // ① A `--` inside a double-quoted identifier is identifier text, not a
    // comment: the drop names the whole quoted identifier, never a fiction.
    assert_eq!(
        drop_table_names(r#"DROP TABLE "weird--name""#),
        vec!["weird--name"],
        "a `--` inside a double-quoted identifier must not split the name",
    );
    // ② The swallowed-comment shape used to erase a `;`-separated drop that
    // followed the quoted name — the parent-first pair passed with its
    // child drop gone. The following drop survives the strip now.
    assert_eq!(
        drop_table_names(r#"DROP TABLE "parents--note"; DROP TABLE children"#),
        vec!["parents--note", "children"],
        "a `;`-separated drop after the quoted name must survive the strip",
    );
    // ③ Backtick- and bracket-quoted names hold `--` whole too.
    assert_eq!(
        drop_table_names("DROP TABLE [weird--name]; DROP TABLE `other--x`"),
        vec!["weird--name", "other--x"],
        "bracket- and backtick-quoted names must stay whole too",
    );
    // ④ A single-quoted literal keeps the existing behavior: `--` inside it
    // is text, never a comment, so it can neither fake nor hide a drop, and
    // a `REFERENCES` clause after a literal containing `--` is still read.
    assert_eq!(
        drop_table_names("DROP TABLE parents; ALTER TABLE t ADD COLUMN c TEXT DEFAULT 'a--b'"),
        vec!["parents"],
        "a `--` inside a single-quoted literal must not fake a drop",
    );

    // The quoted `--` name participates in the child-first check end to end:
    // an edge built against `weird--name` constrains a drop that names it.
    // The SQL strings are raw strings so the quotes reach the gate lexer
    // unescaped (the lexer keeps `\"` verbatim).
    let source = r##"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE TABLE children (parent_id UUID NOT NULL REFERENCES "weird--name"(id))"#,
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared(r#"DROP TABLE "weird--name""#)
            .await?;
        connection.execute_unprepared("DROP TABLE children").await
    }
}
"##;
    let source = tokenize("synthetic_quoted_comment_name.rs", source);
    let edges = synthetic_edges(&source.tokens)?;
    assert!(
        edges.contains(&("children".to_owned(), "weird--name".to_owned())),
        "the quoted REFERENCES clause must yield the edge, got: {edges:?}",
    );
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("weird--name") && violation.contains("children")),
        "the parent-first drop of the quoted name must be rejected, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A migration whose `down` delegates its drops to a shared helper outside
/// the `down` body — the rebuild-helper pattern — with the helper's builder
/// `drop_table(...)` calls in the requested order.
fn helper_drop_source(parent_first: bool) -> String {
    let helper = if parent_first {
        "manager.drop_table(Table::drop().table(Parent::Table).to_owned()).await?;
         manager.drop_table(Table::drop().table(Child::Table).to_owned()).await"
    } else {
        "manager.drop_table(Table::drop().table(Child::Table).to_owned()).await?;
         manager.drop_table(Table::drop().table(Parent::Table).to_owned()).await"
    };
    format!(
        r#"use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        manager
            .create_table(
                Table::create()
                    .table(Parent::Table)
                    .col(ColumnDef::new(Parent::Id).uuid().not_null().primary_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Child::Table)
                    .col(ColumnDef::new(Child::ParentId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Child::Table, Child::ParentId)
                            .to(Parent::Table, Parent::Id)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        // The drops live in the shared helper below, outside this body.
        drop_the_tables(manager).await
    }}
}}

async fn drop_the_tables(manager: &SchemaManager) -> Result<(), DbErr> {{
    {helper}
}}

#[derive(DeriveIden)]
enum Parent {{
    #[sea_orm(iden = "parents")]
    Table,
    Id,
}}

#[derive(DeriveIden)]
enum Child {{
    #[sea_orm(iden = "children")]
    Table,
    Id,
    ParentId,
}}
"#
    )
}

/// The T1-3 blind spot: a `down` whose drops live in a helper outside its
/// body was invisible to the gate unless the helper dropped through raw
/// `execute_unprepared` statements — builder-style `drop_table(...)` calls
/// in helpers were never collected file-wide. The file-wide sequence now
/// merges builder drops with the raw statements, so a parent-first order
/// inside any helper the `down` calls is rejected with the exact line of
/// the offending drop.
#[test]
fn gate_checks_builder_drops_in_helpers_outside_the_down_body() -> Result<(), Box<dyn Error>> {
    let source = tokenize("synthetic_helper.rs", &helper_drop_source(true));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    let parent_line = source
        .tokens
        .iter()
        .find_map(|token| match token {
            Token::Ident { line, name } if name == "drop_table" => Some(*line),
            _ => None,
        })
        .ok_or_else(|| "no drop_table call in the synthetic source".to_owned())?;
    assert!(
        violations.iter().any(|violation| {
            violation.starts_with(&format!("synthetic_helper.rs:{parent_line}:"))
                && violation.contains("parents")
                && violation.contains("children")
        }),
        "the helper's parent-first builder drops must be rejected, got:\n{}",
        violations.join("\n"),
    );
    let source = tokenize("synthetic_helper.rs", &helper_drop_source(false));
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "the helper's child-first builder drops must pass, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// The `m20260805_000011` pattern: the child link is a raw
/// `ALTER TABLE ... ADD COLUMN ... REFERENCES ...` statement. The gate must
/// read the edge from it.
#[test]
fn gate_reads_fk_edges_from_raw_alter_statements() -> Result<(), Box<dyn Error>> {
    let source = r#"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Batch::Table)
                    .col(ColumnDef::new(Batch::Id).uuid().not_null().primary_key())
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE operations ADD COLUMN batch_id uuid_text NULL \
                 REFERENCES batch_operations(id) ON DELETE CASCADE",
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The parent first: `operations.batch_id` still references
        // `batch_operations`, so this order violates the discipline.
        manager
            .drop_table(Table::drop().table(Batch::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Operations::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Batch {
    #[sea_orm(iden = "batch_operations")]
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Operations {
    #[sea_orm(iden = "operations")]
    Table,
    Id,
    BatchId,
}
"#;
    let source = tokenize("synthetic_raw_alter.rs", source);
    let edges = synthetic_edges(&source.tokens)?;
    assert!(
        edges.contains(&("operations".to_owned(), "batch_operations".to_owned())),
        "the raw ALTER REFERENCES clause must yield the edge, got: {edges:?}",
    );
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.iter().any(|violation| {
            violation.contains("operations") && violation.contains("batch_operations")
        }),
        "dropping `operations` before `batch_operations` must be rejected, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A raw `CREATE TABLE` with an inline `REFERENCES` clause — the rebuild-DDL
/// shape, here against a live parent — must yield the edge, and a `down`
/// that drops the parent first must be rejected with the exact `file:line`
/// of the offending drop in the message.
#[test]
fn gate_reads_fk_edges_from_raw_create_table_references() -> Result<(), Box<dyn Error>> {
    let source = r#"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TABLE children (\
                 id UUID NOT NULL PRIMARY KEY,\
                 parent_id UUID NOT NULL REFERENCES parents(id) ON DELETE CASCADE)",
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection.execute_unprepared("DROP TABLE parents").await?;
        connection.execute_unprepared("DROP TABLE children").await
    }
}
"#;
    let source = tokenize("synthetic_raw_create.rs", source);
    let edges = synthetic_edges(&source.tokens)?;
    assert!(
        edges.contains(&("children".to_owned(), "parents".to_owned())),
        "the raw CREATE TABLE REFERENCES clause must yield the edge, got: {edges:?}",
    );
    let violations = order_violations_for(&source, &edges)?;
    let parent_line = source
        .tokens
        .iter()
        .find_map(|token| match token {
            Token::Str { line, content } if content.contains("DROP TABLE parents") => Some(*line),
            _ => None,
        })
        .ok_or_else(|| "no `DROP TABLE parents` literal in the synthetic source".to_owned())?;
    assert!(
        violations.iter().any(|violation| {
            violation.starts_with(&format!("synthetic_raw_create.rs:{parent_line}:"))
                && violation.contains("parents")
                && violation.contains("children")
        }),
        "the parent-first `down` must be rejected with the exact line, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A raw-rebuild migration in the `m20260810_000002` shape: `up` creates the
/// `children_rebuild` staging table with a `REFERENCES parents(id)` clause,
/// drops the old table, and renames the staging table into place; `down`
/// drops both tables in the requested order through raw
/// `execute_unprepared` statements.
fn raw_create_rebuild_source(drop_parent_first: bool) -> String {
    let drops = if drop_parent_first {
        r#"connection.execute_unprepared("DROP TABLE parents").await?;
        connection.execute_unprepared("DROP TABLE children").await"#
    } else {
        r#"connection.execute_unprepared("DROP TABLE children").await?;
        connection.execute_unprepared("DROP TABLE parents").await"#
    };
    format!(
        r#"use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        let connection = manager.get_connection();
        connection
            .execute_unprepared(
                "CREATE TABLE children_rebuild (\
                 id UUID NOT NULL PRIMARY KEY,\
                 parent_id UUID NOT NULL REFERENCES parents(id) ON DELETE CASCADE)",
            )
            .await?;
        connection.execute_unprepared("DROP TABLE children").await?;
        connection
            .execute_unprepared("ALTER TABLE children_rebuild RENAME TO children")
            .await
    }}

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {{
        let connection = manager.get_connection();
        {drops}
    }}
}}
"#
    )
}

/// The `m20260810_000002` blind spot: the raw rebuild `CREATE TABLE` names
/// the `*_rebuild` staging table while its `REFERENCES` clauses name the
/// live parents. The gate must normalize the staging name to the live table
/// it is renamed into — `role_assignments_rebuild REFERENCES
/// instances(id)` is the live `role_assignments → instances` edge — so the
/// live edge is scanned and a `down` that drops the parent before the child
/// is rejected against it, naming the live tables, never the staging name.
#[test]
fn gate_normalizes_raw_create_rebuild_references_to_live_edges() -> Result<(), Box<dyn Error>> {
    let source = raw_create_rebuild_source(true);
    let source = tokenize("synthetic_raw_create_rebuild.rs", &source);
    let edges = synthetic_edges(&source.tokens)?;
    assert!(
        edges.contains(&("children".to_owned(), "parents".to_owned())),
        "the staging REFERENCES clause must normalize to the live edge, got: {edges:?}",
    );
    assert!(
        !edges
            .iter()
            .any(|(child, parent)| child.contains("_rebuild") || parent.contains("_rebuild")),
        "no edge may keep a `*_rebuild` staging name, got: {edges:?}",
    );
    let violations = order_violations_for(&source, &edges)?;
    let parent_line = source
        .tokens
        .iter()
        .find_map(|token| match token {
            Token::Str { line, content } if content.contains("DROP TABLE parents") => Some(*line),
            _ => None,
        })
        .ok_or_else(|| "no `DROP TABLE parents` literal in the synthetic source".to_owned())?;
    assert!(
        violations.iter().any(|violation| {
            violation.starts_with(&format!("synthetic_raw_create_rebuild.rs:{parent_line}:"))
                && violation.contains("parents")
                && violation.contains("children")
                && !violation.contains("children_rebuild")
        }),
        "the parent-first `down` must be rejected against the live edge, got:\n{}",
        violations.join("\n"),
    );

    let source = raw_create_rebuild_source(false);
    let source = tokenize("synthetic_raw_create_rebuild.rs", &source);
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "the child-first `down` must pass with the normalized edge, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A `down` that drops a single table is never constrained, even when an FK
/// edge exists to a table the `down` does not drop.
#[test]
fn gate_skips_single_table_downs() -> Result<(), Box<dyn Error>> {
    let source = two_table_source(true).replace(
        "manager.drop_table(Table::drop().table(Parent::Table).to_owned()).await",
        "// the parent outlives this migration's down",
    );
    let source = tokenize("synthetic_single.rs", &source);
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "a single-table down must be skipped, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// Comments and non-DDL string literals must never participate: the lexer
/// strips comments, and only `execute_unprepared` arguments are scanned, so
/// a `DROP TABLE` mentioned in prose cannot create a drop or an edge.
#[test]
fn gate_ignores_comments_and_non_ddl_strings() -> Result<(), Box<dyn Error>> {
    let source = r#"// The review note says: DROP TABLE parents before children.
const NARRATIVE: &str = "DROP TABLE parents, then children";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Parent::Table)
                    .col(ColumnDef::new(Parent::Id).uuid().not_null().primary_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Child::Table)
                    .col(ColumnDef::new(Child::ParentId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Child::Table, Child::ParentId)
                            .to(Parent::Table, Parent::Id)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Child::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Parent::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Parent {
    #[sea_orm(iden = "parents")]
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Child {
    #[sea_orm(iden = "children")]
    Table,
    Id,
    ParentId,
}
"#;
    let source = tokenize("synthetic_prose.rs", source);
    let enum_tables = enum_table_names(&source.tokens);
    let consts = const_literals(&source.tokens);
    let file_drops = file_wide_drop_sequence(&source.tokens, &enum_tables, &consts)?;
    // The file-wide sequence may only name the down body's real builder
    // drops — the comment and the `NARRATIVE` const must contribute nothing.
    let tables: Vec<&str> = file_drops.iter().map(|(_, table)| table.as_str()).collect();
    assert_eq!(
        tables,
        vec!["children", "parents"],
        "only the down body's real drops may appear, got: {file_drops:?}",
    );
    let edges = synthetic_edges(&source.tokens)?;
    let violations = order_violations_for(&source, &edges)?;
    assert!(
        violations.is_empty(),
        "the parent-first prose must not be read as a drop, got:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

/// A drop whose table ident cannot be resolved (no `DeriveIden` enum with an
/// iden-mapped `Table` variant in the file) is a gate failure, never a
/// silent skip.
#[test]
fn gate_rejects_unresolvable_drop_targets() -> Result<(), Box<dyn Error>> {
    let source = two_table_source(true).replace(
        "manager.drop_table(Table::drop().table(Child::Table).to_owned()).await?;\n         manager.drop_table(Table::drop().table(Parent::Table).to_owned()).await",
        "manager.drop_table(Table::drop().table(Mystery::Table).to_owned()).await",
    );
    let source = tokenize("synthetic_unresolvable.rs", &source);
    let edges = synthetic_edges(&source.tokens)?;
    let error = order_violations_for(&source, &edges)
        .err()
        .ok_or_else(|| "expected the unresolvable-table gate failure".to_owned())?;
    assert!(
        error.contains("Mystery"),
        "the failure must name the unresolvable table, got: {error}",
    );
    Ok(())
}

/// A `.rs` migration placed in a subdirectory of `migration/src` is a source
/// like any other: the walk must reach it, sorted with its subdirectory path
/// in its name, exactly as it reaches a top-level file.
#[test]
fn scanned_sources_walk_is_recursive() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let nested = directory.path().join("nested/deeper");
    fs::create_dir_all(&nested)?;
    fs::write(directory.path().join("top.rs"), "// top")?;
    fs::write(nested.join("deep.rs"), "// deep")?;
    fs::write(directory.path().join("ignored.txt"), "not rust")?;
    let mut files = Vec::new();
    collect_rs(directory.path(), directory.path(), &mut files)?;
    files.sort();
    let names: Vec<String> = files
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect();
    assert_eq!(
        names,
        vec!["nested/deeper/deep.rs", "top.rs"],
        "the source walk must cover `.rs` files in subdirectories, name-sorted"
    );
    Ok(())
}

/// W9-T-3 (2026-08-14): sister-gate stripper parity, enforced statically.
/// `bare_sql_gate.rs` carries its own copy of the strip-then-split
/// implementation (each gate is self-contained by design), and both file
/// headers claim the copies cannot disagree about what a comment or a
/// quoted region is. Compiling the sister file into this binary is not
/// possible as-is — its `//!` crate doc is only legal at file scope and
/// its own tests would re-run here — so parity is asserted on the source
/// text instead: the two stripper function bodies must be identical
/// character for character. That is a stronger claim than output equality
/// on a sample set: it cannot drift on inputs the sample misses.
#[test]
fn the_sister_gate_stripper_bodies_are_identical() -> Result<(), Box<dyn Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ours = fs::read_to_string(manifest.join("tests/down_order_gate.rs"))?;
    let sister = fs::read_to_string(manifest.join("tests/bare_sql_gate.rs"))?;
    for name in ["strip_sql_comments", "split_sql_statements"] {
        let ours_body =
            fn_body(&ours, name).ok_or_else(|| format!("this gate no longer defines {name}"))?;
        let sister_body = fn_body(&sister, name)
            .ok_or_else(|| format!("the sister gate no longer defines {name}"))?;
        assert_eq!(
            ours_body, sister_body,
            "the two gates' {name} implementations must stay identical"
        );
    }
    Ok(())
}

/// The text of one `fn name(...) { ... }` definition — from the `fn`
/// keyword to the brace-matched closing `}` of its body.
fn fn_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let start = source.find(&format!("fn {name}("))?;
    let brace = source[start..].find('{')? + start;
    let mut depth = 0usize;
    for (i, ch) in source[brace..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[start..=(brace + i)]);
                }
            }
            _ => {}
        }
    }
    None
}
