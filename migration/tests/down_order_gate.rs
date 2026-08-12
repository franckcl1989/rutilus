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
//! yield their edges too. Edges from every file form one global graph — a
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
//! - the file's raw `DROP TABLE` statements file-wide, in source order —
//!   the `SQLite` rebuild helpers (`create_resource_tables_with`,
//!   `rebuild_audit_events`, `rebuild`, ...) that `up` and `down` both call
//!   keep their drops outside the `down` body, and the child-first
//!   discipline applies to them in both directions (the drop of the old
//!   parent would cascade into the old children either way).
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
use std::path::Path;

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

/// The bare SQL identifier of one whitespace-delimited word: bracket/quote
/// characters stripped, and everything from an opening `(` (a column list
/// like `batch_operations(id)`) discarded.
fn sql_identifier(word: &str) -> &str {
    let word = word
        .trim_start_matches(['[', '"', '`'])
        .trim_end_matches([']', '"', '`']);
    word.split('(').next().unwrap_or(word)
}

/// The tables a raw SQL string drops, in statement order: every `DROP TABLE`
/// (optionally `IF EXISTS`) occurrence with the following identifier.
fn drop_table_names(sql: &str) -> Vec<String> {
    let words: Vec<&str> = sql.split_whitespace().collect();
    let mut drops = Vec::new();
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

/// Lists `migration/src/*.rs` for scanning, relative to `CARGO_MANIFEST_DIR`
/// so newly added migration files are covered automatically.
fn scanned_sources() -> Result<Vec<SourceTokens>, Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    files.sort();
    let mut sources = Vec::new();
    for file in files {
        let display_path = format!(
            "src/{}",
            file.file_name()
                .ok_or("source file without a name")?
                .to_string_lossy()
        );
        let source = fs::read_to_string(&file)?;
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
/// key (`m20260805_000011`'s `operations.batch_id` link,
/// `m20260810_000001`'s `endpoints.site_id`); the `REFERENCES` clauses of
/// raw `CREATE TABLE` rebuild DDL name the `*_rebuild` staging tables, not
/// the live schema, so they are deliberately not read.
fn raw_alter_references(
    tokens: &[Token],
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(String, String)>, String> {
    let mut edges = Vec::new();
    for argument in execute_unprepared_arguments(tokens) {
        for (_line, statement) in argument_statements(&argument, consts)? {
            let words: Vec<&str> = statement.split_whitespace().collect();
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

/// The file-wide raw `DROP TABLE` sequence (first occurrence per table) —
/// the `SQLite` rebuild helpers that `up` and `down` both call keep their
/// drops outside the `down` body.
fn file_wide_raw_drop_sequence(
    tokens: &[Token],
    consts: &HashMap<String, (usize, String)>,
) -> Result<Vec<(usize, String)>, String> {
    let mut drops = raw_drop_statements(tokens, consts)?;
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
    let raw_drops = file_wide_raw_drop_sequence(&source.tokens, &consts)?;
    violations.extend(check_order(&source.display_path, &raw_drops, edges));
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
    for source in &sources {
        let enum_tables = enum_table_names(&source.tokens);
        let consts = const_literals(&source.tokens);
        edges.extend(foreign_key_edges(&source.tokens, &enum_tables)?);
        edges.extend(raw_alter_references(&source.tokens, &consts)?);
    }
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
    let consts = const_literals(&source.tokens);
    let raw_drops = file_wide_raw_drop_sequence(&source.tokens, &consts)?;
    assert!(
        raw_drops.is_empty(),
        "prose must not produce raw drops, got: {raw_drops:?}",
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
