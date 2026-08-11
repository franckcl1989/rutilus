//! §7.3 bare-SQL gate — mechanical enforcement of the DDL-only exception.
//!
//! The design's bare-SQL ban (§7.3, 0.8.0 acceptance "裸 SQL = 0") leaves one
//! production carve-out: the migration crate may run raw SQL through
//! `execute_unprepared` for the `SQLite` DDL the `SeaQuery` builders cannot
//! express — `ALTER TABLE ... ADD COLUMN` with a `CHECK`/`REFERENCES`
//! clause, table-rebuild `CREATE`/`DROP`/`RENAME`, and partial-index
//! `WHERE` clauses. Every such statement must start with `CREATE`, `ALTER`,
//! `DROP`, or `PRAGMA`; DML (`SELECT`, `INSERT`, `UPDATE`, `DELETE`,
//! `VACUUM`, `REINDEX`, ...) is forbidden everywhere, including the
//! rebuilds' data copies, which go through the `SeaQuery` query builder
//! (`INSERT ... SELECT` via `select_from`).
//!
//! Persistence holds the second carve-out: its tests run `PRAGMA` statements
//! on a dedicated writer connection to simulate rows written by an older
//! build (the upgrade-order discipline), so raw SQL there is `PRAGMA`-only.
//! The migration crate's own tests seed those upgrade scenarios with raw
//! `INSERT` statements; like the persistence `PRAGMA`s, that is test scope,
//! not production code.
//!
//! The scans read the crate sources from disk relative to
//! `CARGO_MANIFEST_DIR` (the release-baseline gate in `rutilus-infra-redfish`
//! uses the same pattern), so newly added migration files are covered
//! automatically. Files are scanned token-wise: comments, doc comments, and
//! attribute strings are ignored, and both plain (`"..."`) and raw
//! (`r"..."` / `r#"..."#`) string literals are recognized, so the checks
//! cannot be fooled by quoting.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::Path;

/// The only statement kinds the migration crate may run raw (`SQLite` DDL).
const DDL_FIRST_WORDS: [&str; 4] = ["CREATE", "ALTER", "DROP", "PRAGMA"];

/// Statement kinds that must never appear as raw SQL: the DML families the
/// §7.3 ban names, plus the forms that carry DML (`WITH` CTEs, `REPLACE`
/// upserts, `EXPLAIN`/`VACUUM`/`REINDEX` maintenance).
const DML_FIRST_WORDS: [&str; 9] = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "WITH", "VACUUM", "REINDEX", "EXPLAIN",
];

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

/// The first whitespace-delimited word of a SQL statement.
fn first_keyword(sql: &str) -> &str {
    sql.split_whitespace().next().unwrap_or_default()
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

/// Lists `migration/src/*.rs` and `persistence/src/*.rs` for scanning.
fn scanned_sources(relative_dir: &str) -> Result<Vec<SourceTokens>, Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_dir);
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
            "{}/{}",
            relative_dir,
            file.file_name()
                .ok_or("source file without a name")?
                .to_string_lossy()
        );
        let source = fs::read_to_string(&file)?;
        sources.push(tokenize(&display_path, &source));
    }
    Ok(sources)
}

/// The migration gate: every `execute_unprepared` statement must start with
/// a DDL keyword, and no string literal anywhere may start with a DML
/// keyword (comments and doc examples are not string literals, so they
/// cannot trip the scan).
fn migration_violations() -> Result<Vec<String>, Box<dyn Error>> {
    let mut violations = Vec::new();
    for source in scanned_sources("src")? {
        let consts = const_literals(&source.tokens);
        for token in &source.tokens {
            let content = match token {
                Token::Str { content, .. } | Token::RawStr { content, .. } => content,
                Token::Ident { .. } | Token::Punct { .. } => continue,
            };
            let keyword = first_keyword(content);
            if DML_FIRST_WORDS
                .iter()
                .any(|forbidden| keyword.eq_ignore_ascii_case(forbidden))
            {
                violations.push(format!(
                    "{}:{}: string literal starts with the forbidden DML keyword `{keyword}`: {content}",
                    source.display_path, token.line(),
                ));
            }
        }
        for argument in execute_unprepared_arguments(&source.tokens) {
            let statements = argument_statements(&argument, &consts).map_err(|reason| {
                format!("{}: execute_unprepared: {reason}", source.display_path)
            })?;
            for (line, statement) in statements {
                let keyword = first_keyword(&statement);
                if !DDL_FIRST_WORDS
                    .iter()
                    .any(|allowed| keyword.eq_ignore_ascii_case(allowed))
                {
                    violations.push(format!(
                        "{}:{}: execute_unprepared statement starts with `{keyword}`, \
                         only CREATE/ALTER/DROP/PRAGMA are allowed: {statement}",
                        source.display_path, line,
                    ));
                }
            }
        }
    }
    Ok(violations)
}

/// The persistence gate: raw SQL there is the test-scope PRAGMA exception
/// (tests simulate rows written by an older build), so every
/// `execute_unprepared` statement must start with `PRAGMA`.
fn persistence_violations() -> Result<Vec<String>, Box<dyn Error>> {
    let mut violations = Vec::new();
    for source in scanned_sources("../persistence/src")? {
        let consts = const_literals(&source.tokens);
        for argument in execute_unprepared_arguments(&source.tokens) {
            let statements = argument_statements(&argument, &consts).map_err(|reason| {
                format!("{}: execute_unprepared: {reason}", source.display_path)
            })?;
            for (line, statement) in statements {
                let keyword = first_keyword(&statement);
                if !keyword.eq_ignore_ascii_case("PRAGMA") {
                    violations.push(format!(
                        "{}:{}: execute_unprepared statement starts with `{keyword}`, \
                         only PRAGMA (test-scope exception) is allowed: {statement}",
                        source.display_path, line,
                    ));
                }
            }
        }
    }
    Ok(violations)
}

#[test]
fn migration_bare_sql_is_ddl_only() -> Result<(), Box<dyn Error>> {
    let violations = migration_violations()?;
    assert!(
        violations.is_empty(),
        "migration/src violates the §7.3 DDL-only exception:\n{}",
        violations.join("\n"),
    );
    Ok(())
}

#[test]
fn persistence_raw_sql_is_test_only_pragma() -> Result<(), Box<dyn Error>> {
    let violations = persistence_violations()?;
    assert!(
        violations.is_empty(),
        "persistence/src violates the §7.3 test-scope PRAGMA exception:\n{}",
        violations.join("\n"),
    );
    Ok(())
}
