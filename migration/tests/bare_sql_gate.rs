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
//! automatically; the walk is recursive, so `.rs` files in subdirectories of
//! `migration/src` or `persistence/src` are covered too. Files are scanned
//! token-wise: comments, doc comments, and attribute strings are ignored,
//! and both plain (`"..."`) and raw (`r"..."` / `r#"..."#`) string literals
//! are recognized, so the checks cannot be fooled by quoting.
//!
//! The first-word check alone is not sufficient: a statement may start with
//! a DDL keyword and still smuggle DML past the carve-out's edge. A raw
//! string may also carry several `;`-separated statements, and only the
//! first word of the whole string used to be judged — `ALTER TABLE x ADD
//! COLUMN y; DELETE FROM z` is a `DELETE` the first-keyword scan never saw.
//! Every `execute_unprepared` string is therefore split into its
//! `;`-separated statements (SQL comments stripped first, quote-aware —
//! a `;` inside a quoted identifier or literal, or inside a comment, is
//! not a terminator — the same strip-then-split shape the `down_order_gate`
//! uses), and each statement is checked on its own: the whole string's raw
//! first word still gates the string's own leading position (a leading
//! comment is not a DDL first word), and every segment must pass the
//! first-word check and the embedded-DML scan independently.
//!
//! Two embedded-DML shapes are checked inside every statement that passes
//! the first-word gate: the `CREATE ... AS SELECT` shapes — the CTAS data
//! copy (`CREATE TABLE x AS SELECT`) and the `CREATE VIEW ... AS SELECT`
//! row query — and DML statements inside a `CREATE TRIGGER` body
//! (`BEGIN ... INSERT/UPDATE/DELETE/... END`). The trigger's own metadata
//! words (`AFTER INSERT`, `INSTEAD OF UPDATE`, the `WHEN` clause) appear
//! before `BEGIN` and are not DML.
//!
//! The `AS SELECT` family is checked in every spelling the `SQLite`
//! select-stmt allows: the plain pair, the parenthesized form (`CREATE
//! TABLE x AS (SELECT ...)`, a select-stmt may be wrapped in parentheses),
//! and the CTE form (`CREATE TABLE x AS WITH cte AS (...) SELECT ...`, the
//! WITH-clause-headed select-stmt). The no-space spellings on the `AS` side
//! (`AS(SELECT`, `AS(WITH`) are recognized too, where a whitespace split
//! would otherwise hide the pair in one word.
//!
//! Two spelling families are registered residues of this scan. A bare
//! `VALUES (...)` is also a select-stmt, so the `AS VALUES` data copies
//! `CREATE TABLE t AS VALUES (1)`, `CREATE TABLE t AS (VALUES (1))`, and
//! `CREATE TABLE t AS(VALUES (1))` are legal CTAS that pass unflagged. And
//! the mirrored no-space spellings on the `SELECT` side — `AS SELECT(1)`,
//! `AS SELECT*FROM` — are missed too: the word-level match is the exact
//! word `SELECT`, so a `SELECT` glued to a following `(` or `*` never
//! matches (pre-existing, the mirror of the `AS`-side glue recognized
//! above). No statement in the current tree holds either family, so both
//! boundaries are registered, not expanded.
//!
//! The embedded-DML scan first strips SQL comments (`--` line comments and
//! `/* ... */` block comments; see [`strip_sql_comments`]), so a comment
//! between the shape's words can no longer hide it — `CREATE TABLE x AS --
//! comment\nSELECT ...` reads as the `AS SELECT` pair once the comment is
//! gone, and comment content can never read like DML. The check is
//! word-level and therefore has a registered false-positive boundary: a
//! quoted SQL string literal that contains a spaced word sequence (`CHECK
//! (a <> ' AS SELECT ')`, `DEFAULT 'TRIGGER BEGIN SELECT END'`) reads like
//! the embedded shape. The new spellings widen the same boundary: a literal
//! holding a spaced `AS ( SELECT` or `AS WITH ... SELECT` sequence (`CHECK
//! (a <> ' AS ( SELECT ')`) reads like the new shapes, while a sequence
//! glued to the quotes (`'AS ( SELECT'`) does not form the pair. Quoted
//! regions — literals and quoted identifiers — are preserved verbatim by
//! the stripper — a `--` or `/*` inside them is text, not a comment — so
//! the boundary stands unchanged.
//! Outside quoted literals the new shapes have no false-positive surface
//! per the `SQLite` grammar: in DDL the `AS` keyword is followed either by
//! the select-stmt (`CREATE TABLE/VIEW ... AS`) or by a type name (a column
//! type, `CAST(x AS TEXT)`), never by `(` in another role except the
//! generated-column `AS (expr)` form (`GENERATED ALWAYS AS (a + b)`), where
//! `SQLite` forbids subqueries in generated-column expressions so no
//! `SELECT` can sit in that slot, and never by `WITH` in another role. The
//! false-positive residue is keyword-as-identifier DDL (a column named
//! `AS`): the spaced `CREATE TABLE t ( AS WITH , b INT CHECK (b IN (SELECT
//! ...)))` reads like the CTE shape though no `WITH` clause is meant — the
//! glued `(AS WITH, ...)` spelling cannot trigger it, the `(` gluing to the
//! `AS` and the `,` to the `WITH`. No statement in the current tree holds
//! any of these, so the boundary is registered, not expanded.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

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
/// The embedded-DML scan runs on the stripped statement, so a comment
/// sitting between the shape's words (`CREATE TABLE x AS -- comment
/// SELECT ...`) can no longer hide the `AS SELECT` pair or a trigger-body
/// DML word, and comment content can never read like DML — while a quoted
/// table name like `"a--b"` or `` `a--b` `` stays whole, so a comment
/// marker inside an identifier can neither hide a shape nor fake one. (The
/// first-word gate keeps scanning the raw statement: a leading comment is
/// not a DDL first word, so a comment-first statement still fails the
/// carve-out.)
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
/// `DROP TABLE "weird;name"` stays one statement and `DEFAULT 'x;y'` keeps
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

/// The `;`-separated statements of one raw SQL string, trimmed of the
/// surrounding whitespace: SQL comments are stripped first — a `;` inside a
/// comment is comment text, not a terminator, and comment content can never
/// read like a statement — and the split is then quote-aware
/// ([`split_sql_statements`]). Empty segments (a trailing terminator) are
/// dropped. The same strip-then-split shape `down_order_gate.rs` uses for
/// its raw statement scans, so the two gates cannot disagree about what one
/// statement is.
fn sql_statements(statement: &str) -> Vec<String> {
    split_sql_statements(&strip_sql_comments(statement))
        .into_iter()
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether `word` is the `AS` keyword, optionally glued to a following `(`
/// (`AS(SELECT`), which a whitespace split would otherwise hide in one word.
fn is_as_word(word: &str) -> bool {
    let bytes = word.as_bytes();
    bytes.len() >= 2
        && bytes[0].eq_ignore_ascii_case(&b'a')
        && bytes[1].eq_ignore_ascii_case(&b's')
        && (bytes.len() == 2 || bytes[2] == b'(')
}

/// Classifies the token right after `AS`: the plain `AS SELECT` pair, the
/// parenthesized `AS ( SELECT` form, or the `AS WITH ... SELECT` CTE form —
/// the last by scanning `rest` (the word stream after the `WITH`) for the
/// `SELECT` that every WITH-clause select-stmt must contain.
fn as_select_clause(cand: &str, rest: &[&str], statement: &str) -> Option<String> {
    if cand.eq_ignore_ascii_case("SELECT") {
        return Some(format!(
            "the `AS SELECT` clause copies data through raw SQL: {statement}"
        ));
    }
    let bare = cand.trim_start_matches('(').trim_end_matches(')');
    if cand.starts_with('(') && bare.eq_ignore_ascii_case("SELECT") {
        return Some(format!(
            "the parenthesized `AS ( SELECT` clause copies data through raw SQL: {statement}"
        ));
    }
    if bare.eq_ignore_ascii_case("WITH")
        && rest.iter().any(|word| {
            word.trim_start_matches('(')
                .trim_end_matches(')')
                .eq_ignore_ascii_case("SELECT")
        })
    {
        return Some(format!(
            "the `AS WITH ... SELECT` CTE clause copies data through raw SQL: {statement}"
        ));
    }
    None
}

/// Whether a statement that passed the first-word gate still embeds DML past
/// its first word. Two shapes are recognized, both word-delimited and
/// case-insensitive like `first_keyword`:
///
/// - `CREATE ... AS SELECT`: the CTAS data copy (`CREATE TABLE x AS SELECT`)
///   or the `CREATE VIEW v AS SELECT` row query — a raw-SQL data copy
///   bypasses the `SeaQuery` builder the §7.3 carve-out requires for
///   rebuilds, and a raw view definition bypasses it for reads. The scan
///   covers every spelling of the `SQLite` select-stmt after `AS`: the plain
///   pair, the parenthesized form (`CREATE TABLE x AS (SELECT ...)`), and
///   the CTE form (`CREATE TABLE x AS WITH cte AS (...) SELECT ...`); the
///   no-space spellings (`AS(SELECT`, `AS(WITH`) are recognized too, where
///   a whitespace split would hide the pair in one word.
/// - `CREATE TRIGGER ... BEGIN ... END`: DML words (`INSERT`, `UPDATE`,
///   `DELETE`, `SELECT`, ...) inside the trigger body. Only the words
///   between the first `BEGIN` and the first `END` after it count: the
///   trigger's own metadata (`AFTER INSERT`, `INSTEAD OF UPDATE`, the
///   `WHEN` clause) legitimately contains DML words before `BEGIN`.
///
/// The scan runs on the [`strip_sql_comments`]-stripped statement, so SQL
/// comments cannot hide a shape: a comment between `AS` and `(SELECT`, or
/// between `BEGIN` and a body DML word, is removed before the words are
/// compared (`CREATE TABLE x AS -- comment\n (SELECT ...)` is caught), and
/// comment content itself never reads like DML (`/* AS ( SELECT */` inside
/// a statement flags nothing).
///
/// The word-level scan has a registered false-positive boundary on quoted
/// SQL string literals: a literal that contains a spaced word sequence reads
/// like the embedded shape (`CHECK (a <> ' AS SELECT ')`, `DEFAULT 'TRIGGER
/// BEGIN SELECT END'`). The new spellings widen the same boundary — a
/// literal holding a spaced `AS ( SELECT` or `AS WITH ... SELECT` sequence
/// (`' AS ( SELECT '`) reads like the shape, while a sequence glued to the
/// quotes (`'AS ( SELECT'`) does not form the pair. The stripper preserves
/// quoted regions verbatim — `--`/`/*` inside a literal or a quoted
/// identifier is text, not a comment — so the boundary stands: a quoted
/// `'AS -- SELECT'` (comment marker inside the literal) is not treated as a
/// comment and does not form the adjacent pair. Outside literals, per the
/// `SQLite` grammar, `AS` in DDL
/// is followed by the select-stmt or by a type name (a column type,
/// `CAST(x AS TEXT)`), never by `(` or `WITH` in another role — so the
/// parenthesized and CTE shapes have no false-positive surface in real DDL,
/// apart from keyword-as-identifier usage (a column named `AS`: `CREATE
/// TABLE t (AS WITH, b INT CHECK (b IN (SELECT ...)))` reads like the CTE
/// shape). No statement in the current tree holds such a literal, so the
/// boundary is documented, not expanded.
fn ddl_embedded_dml(statement: &str) -> Option<String> {
    let statement = strip_sql_comments(statement);
    let words: Vec<&str> = statement.split_whitespace().collect();
    let mut i = 0;
    while i < words.len() {
        let word = words[i];
        if !is_as_word(word) {
            i += 1;
            continue;
        }
        // `AS(SELECT ...)` glues the opening paren to the keyword: the
        // remainder of the word is the token that follows `AS`.
        let glued = word.get(2..).filter(|fragment| !fragment.is_empty());
        let mut j = i + 1;
        while j < words.len() && words[j].bytes().all(|b| b == b'(') {
            j += 1;
        }
        let next = words.get(j).copied();
        let rest = if glued.is_some() {
            &words[i + 1..]
        } else {
            &words[j + 1..]
        };
        for cand in [glued, next].into_iter().flatten() {
            if let Some(reason) = as_select_clause(cand, rest, &statement) {
                return Some(reason);
            }
        }
        i += 1;
    }
    if !words
        .iter()
        .any(|word| word.eq_ignore_ascii_case("TRIGGER"))
    {
        return None;
    }
    let begin = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("BEGIN"))?;
    let end = words[begin + 1..]
        .iter()
        .position(|word| word.eq_ignore_ascii_case("END"))
        .map_or(words.len(), |offset| begin + 1 + offset);
    for word in &words[begin + 1..end] {
        if DML_FIRST_WORDS
            .iter()
            .any(|dml| word.eq_ignore_ascii_case(dml))
        {
            return Some(format!(
                "`{word}` runs DML inside the `CREATE TRIGGER` body: {statement}"
            ));
        }
    }
    None
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

/// Lists the `.rs` files under `migration/src` and `persistence/src` for
/// scanning. The walk is recursive, so a `.rs` file in a newly added
/// subdirectory is covered automatically.
fn scanned_sources(relative_dir: &str) -> Result<Vec<SourceTokens>, Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_dir);
    let mut files = Vec::new();
    collect_rs(&directory, &directory, &mut files)?;
    files.sort();
    let mut sources = Vec::new();
    for file in files {
        let display_path = format!(
            "{}/{}",
            relative_dir,
            file.to_string_lossy().replace('\\', "/")
        );
        let source = fs::read_to_string(directory.join(&file))?;
        sources.push(tokenize(&display_path, &source));
    }
    Ok(sources)
}

/// Checks one raw SQL string against the `allowed` first words, returning
/// the violations.
///
/// The whole string's first word is judged on the raw text — a leading
/// comment is not an allowed first word, so a comment-first string still
/// fails the carve-out — and, when it passes, the string is split into its
/// `;`-separated statements ([`sql_statements`]) and every segment must
/// pass the first-word check and the [`ddl_embedded_dml`] scan on its own:
/// a DML tail after the first statement (`ALTER TABLE x ADD COLUMN y;
/// DELETE FROM z`) used to ride the first statement's DDL first word past
/// the gate. A segment that begins with a comment in the raw text passes
/// the first-word check once the comment is stripped (the boundary is the
/// string's own leading position, which keeps the strict raw rule).
fn raw_statement_violations(statement: &str, allowed: &[&str], allowance: &str) -> Vec<String> {
    let keyword = first_keyword(statement);
    if !allowed
        .iter()
        .any(|allowed| keyword.eq_ignore_ascii_case(allowed))
    {
        return vec![format!(
            "execute_unprepared statement starts with `{keyword}`, {allowance}: {statement}"
        )];
    }
    let mut violations = Vec::new();
    for segment in sql_statements(statement) {
        let keyword = first_keyword(&segment);
        if !allowed
            .iter()
            .any(|allowed| keyword.eq_ignore_ascii_case(allowed))
        {
            violations.push(format!(
                "execute_unprepared statement segment starts with `{keyword}`, \
                 {allowance}: {segment}"
            ));
        } else if let Some(reason) = ddl_embedded_dml(&segment) {
            violations.push(format!(
                "execute_unprepared statement embeds DML past its first word: {reason}"
            ));
        }
    }
    violations
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
                for violation in raw_statement_violations(
                    &statement,
                    &DDL_FIRST_WORDS,
                    "only CREATE/ALTER/DROP/PRAGMA are allowed",
                ) {
                    violations.push(format!("{}:{line}: {violation}", source.display_path));
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
                for violation in raw_statement_violations(
                    &statement,
                    &["PRAGMA"],
                    "only PRAGMA (test-scope exception) is allowed",
                ) {
                    violations.push(format!("{}:{line}: {violation}", source.display_path));
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

#[test]
fn ddl_embedded_dml_is_flagged() {
    // Negative samples: DDL that passes the first-word check but embeds DML
    // past it — the two shapes the first-keyword-only scan used to miss.
    let flagged: &[&str] = &[
        // CTAS: a raw-SQL data copy bypasses the SeaQuery builder.
        "CREATE TABLE audit_backup AS SELECT * FROM audit;",
        "CREATE VIEW active_users AS SELECT id, name FROM users;",
        "create table x as select * from y;",
        "CREATE TABLE daily_snapshot AS\n  SELECT * FROM telemetry;",
        // CREATE TRIGGER bodies: DML words between BEGIN and END. The
        // metadata words before BEGIN (`AFTER INSERT`) are not DML.
        "CREATE TRIGGER audit_trigger AFTER INSERT ON users \
         BEGIN UPDATE users SET updated_at = 1; END;",
        "CREATE TRIGGER t AFTER DELETE ON a BEGIN INSERT INTO log VALUES ('x'); END;",
        "CREATE TRIGGER t INSTEAD OF UPDATE ON v WHEN new.a > 1 \
         BEGIN DELETE FROM t2 WHERE id = new.id; END;",
        // Parenthesized and CTE spellings of the AS SELECT shape: the SQLite
        // select-stmt after `AS` may itself be parenthesized or headed by a
        // `WITH` clause — both valid, both raw-SQL data copies.
        "CREATE TABLE t AS (SELECT * FROM src);",
        "CREATE VIEW v AS (SELECT id FROM users);",
        "create table t as (select * from src);",
        "CREATE TABLE t AS ( SELECT * FROM src );",
        "CREATE TABLE t AS((SELECT * FROM src));",
        "CREATE TABLE t AS(SELECT * FROM src);",
        "CREATE TABLE t AS (WITH cte AS (SELECT 1) SELECT * FROM cte);",
        "CREATE TABLE t AS WITH cte AS (SELECT 1) SELECT * FROM cte;",
        "CREATE VIEW v AS WITH cte AS (SELECT 1) SELECT * FROM cte;",
        "CREATE TABLE t AS WITH cte AS (VALUES (1)) SELECT * FROM cte;",
        // Comment-split shapes: a SQL comment between the shape's words used
        // to hide the pair/body from the word window. The `--` and `/* */`
        // forms are stripped before the scan, so the split form is caught,
        // including between `AS` and the parenthesized/CTE select-stmt.
        "CREATE TABLE audit_backup AS -- the data copy\nSELECT * FROM audit;",
        "CREATE TABLE audit_backup AS /* inline comment */ SELECT * FROM audit;",
        "CREATE VIEW v AS/*no spaces around the comment*/SELECT id FROM users;",
        "CREATE TABLE t AS -- one comment\n -- then another\n SELECT 1;",
        "CREATE TABLE t AS -- cte\n WITH cte2 AS (SELECT 1) SELECT * FROM cte2;",
        "CREATE TABLE t AS -- c\n (SELECT * FROM src);",
        "CREATE TRIGGER t AFTER INSERT ON a BEGIN -- the insert\n \
         INSERT INTO log VALUES ('x');\nEND;",
        // The registered quoted-literal boundary, extended to the new
        // spellings: a spaced word sequence inside a literal reads like the
        // shape (quoted text, not DML — flagged by design; no statement in
        // the tree holds such a literal).
        "CREATE TABLE pairs (a TEXT CHECK (a <> ' AS ( SELECT '), b TEXT);",
        "CREATE TABLE pairs (a TEXT CHECK (a <> ' AS WITH SELECT '), b TEXT);",
    ];
    for statement in flagged {
        assert!(
            ddl_embedded_dml(statement).is_some(),
            "statement must be flagged for embedded DML: {statement}"
        );
    }
    // Positive samples: the carve-out's real shapes hold no DML past the
    // first word, including DROP TRIGGER and trigger metadata without a body.
    let clean: &[&str] = &[
        "CREATE TABLE settings (id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
        "ALTER TABLE users ADD COLUMN role TEXT REFERENCES roles(id);",
        "CREATE INDEX idx_users_name ON users (name) WHERE role != 'admin';",
        "DROP TRIGGER audit_trigger;",
        "PRAGMA user_version = 12;",
        "CREATE TABLE pairs (a TEXT CHECK (a <> 'AS SELECT'), b TEXT);",
        // Comment content is stripped, never read as DML: a comment that
        // contains the shape, or a trigger body that is only a comment,
        // must pass — the word-level scan used to flag both.
        "CREATE TABLE x /* AS SELECT in a comment */ (id INTEGER);",
        "CREATE TABLE x -- AS SELECT in a comment\n (id INTEGER);",
        "CREATE TRIGGER t AFTER INSERT ON a BEGIN /* INSERT INTO log VALUES ('x'); */ END;",
        // Quoted literals are preserved verbatim: a `--` or `/*` inside a
        // literal is text, not a comment — the registered quoted-sequence
        // boundary, including comment markers inside the quotes.
        "CREATE TABLE pairs (a TEXT CHECK (a <> 'AS -- SELECT'), b TEXT);",
        "CREATE TABLE pairs (a TEXT CHECK (a <> 'AS /* x */ SELECT'), b TEXT);",
        // The new spellings must not widen the carve-out's real shapes: an
        // `AS` that is followed by a type name, not a select-stmt; the
        // new-shape sequences glued to the quotes (the boundary is the
        // spaced sequence, so these form no pair); and keyword-as-identifier
        // DDL whose `AS WITH` is followed by no SELECT.
        "CREATE TABLE t (a TEXT CHECK (CAST(a AS TEXT) <> 'x'), b TEXT);",
        "CREATE TABLE t (a TEXT CHECK (a <> 'AS ( SELECT'), b TEXT);",
        "CREATE TABLE t (a TEXT CHECK (a <> 'AS WITH SELECT'), b TEXT);",
        "CREATE TABLE t (AS WITH, b INT);",
    ];
    for statement in clean {
        assert!(
            ddl_embedded_dml(statement).is_none(),
            "statement must pass the embedded-DML check: {statement}"
        );
    }
}

#[test]
fn strip_sql_comments_removes_comment_text_and_keeps_literals() {
    // The stripper's own contract, exercised directly: comment text goes
    // away (replaced by one separating space), quoted literals keep every
    // character including comment markers, and a doubled `''` is an escaped
    // quote, not the end of the literal.
    assert_eq!(
        strip_sql_comments("CREATE TABLE x AS -- comment\nSELECT 1;"),
        "CREATE TABLE x AS  SELECT 1;"
    );
    assert_eq!(
        strip_sql_comments("CREATE TABLE x AS/*c*/SELECT 1;"),
        "CREATE TABLE x AS SELECT 1;"
    );
    assert_eq!(
        strip_sql_comments("CREATE TRIGGER t AFTER INSERT ON a /* BEFORE */ BEGIN END;"),
        "CREATE TRIGGER t AFTER INSERT ON a   BEGIN END;"
    );
    assert_eq!(
        strip_sql_comments("SELECT '-- not a comment', '/* not a comment */', 'it''s';"),
        "SELECT '-- not a comment', '/* not a comment */', 'it''s';"
    );
    assert_eq!(
        strip_sql_comments("SELECT 'a */ b' /* real comment */ FROM t;"),
        "SELECT 'a */ b'   FROM t;"
    );
    assert_eq!(
        strip_sql_comments("CREATE TABLE x AS -- trailing comment (no newline)"),
        "CREATE TABLE x AS  "
    );
}

/// The W8-S-2 blind spot: the stripper used to protect only single-quoted
/// literals, so a comment marker inside a quoted identifier (`"a--b"`,
/// `` `a--b` ``, `[a--b]`) was read as a comment start and the rest of the
/// statement — a real `AS SELECT` pair, or a `;`-separated DML tail — was
/// swallowed to the end of the line: `CREATE TABLE "a--b" AS SELECT ...`
/// stripped to `CREATE TABLE "a` with no `AS` pair left, and
/// `DROP TABLE "a--b"; DELETE FROM operations` lost its DML tail with the
/// comment. All four quote spellings the `SQLite` grammar allows are
/// preserved verbatim now — the same quote states
/// [`split_sql_statements`] uses, so the strip and the split cannot
/// disagree about what is quoted — and the hidden shapes surface like any
/// other, while a legal table name holding `--` flags nothing.
#[test]
fn quoted_identifiers_cannot_hide_ctas_or_dml_from_the_stripper() {
    let allowance = "only CREATE/ALTER/DROP/PRAGMA are allowed";
    // ① A CTAS whose table name carries `--` in double quotes used to strip
    // to `CREATE TABLE "a` — no `AS` pair left — and pass. The quoted name
    // is preserved, so the `AS SELECT` data copy is flagged.
    let ctas = r#"CREATE TABLE "a--b" AS SELECT * FROM src"#;
    assert_eq!(
        strip_sql_comments(ctas),
        ctas,
        "a quoted identifier is not comment text"
    );
    assert!(
        !raw_statement_violations(ctas, &DDL_FIRST_WORDS, allowance).is_empty(),
        "the double-quoted-name CTAS must be flagged: {ctas}"
    );
    // ② The same quote swallowing used to eat a `;`-separated DML tail along
    // with the rest of the line — the whole string then passed on the one
    // remaining segment. The tail survives the strip and fails the segment
    // check on its own.
    let dml_tail = r#"DROP TABLE "a--b"; DELETE FROM operations"#;
    assert!(
        !raw_statement_violations(dml_tail, &DDL_FIRST_WORDS, allowance).is_empty(),
        "the DML tail after the quoted name must be flagged: {dml_tail}"
    );
    // ③ Backtick- and bracket-quoted table names holding `--` are legal
    // `SQLite` identifiers; preserving them must not flag the statement.
    for clean in [
        "CREATE TABLE `a--b` (id INTEGER PRIMARY KEY)",
        "DROP TABLE [weird--name]",
        "CREATE TABLE [t--x] (id INTEGER PRIMARY KEY); DROP INDEX [ix--y]",
    ] {
        assert_eq!(
            strip_sql_comments(clean),
            clean,
            "a quoted identifier is not comment text: {clean}"
        );
        assert!(
            raw_statement_violations(clean, &DDL_FIRST_WORDS, allowance).is_empty(),
            "a legal quoted name must pass: {clean}"
        );
    }
    // ④ Single-quoted literals keep the existing behavior: `--` inside a
    // literal is text, not a comment, and no shape forms around it.
    let literal = "CREATE TABLE pairs (a TEXT CHECK (a <> 'AS -- SELECT'), b TEXT)";
    assert_eq!(
        strip_sql_comments(literal),
        literal,
        "a single-quoted literal is preserved verbatim"
    );
    assert!(
        raw_statement_violations(literal, &DDL_FIRST_WORDS, allowance).is_empty(),
        "a literal containing `--` must not flag the statement: {literal}"
    );
    // The doubled-quote escape of every quote spelling stays a quote, not a
    // terminator: the region runs on to the real closing quote, so the
    // comment after it is still stripped.
    assert_eq!(
        strip_sql_comments(r#"DROP TABLE "weird""name" -- done"#),
        r#"DROP TABLE "weird""name"  "#,
        "a doubled `\"` is an escaped quote, not the end of the identifier"
    );
    assert_eq!(
        strip_sql_comments("DROP TABLE `weird``name` -- done"),
        "DROP TABLE `weird``name`  ",
        "a doubled backtick is an escaped quote, not the end of the identifier"
    );
    assert_eq!(
        strip_sql_comments("DROP TABLE [weird--name] -- done"),
        "DROP TABLE [weird--name]  ",
        "a bracket identifier runs to its closing bracket"
    );
}

/// The W7-D-6 blind spot: a raw string carrying several `;`-separated
/// statements used to pass the carve-out on the first statement's first
/// word — `ALTER TABLE x ADD COLUMN y; DELETE FROM z` is a `DELETE` the
/// first-keyword scan never saw. Every segment must pass the first-word and
/// embedded-DML checks on its own, while pure multi-statement DDL passes
/// and single-statement strings behave exactly as before.
#[test]
fn raw_statement_splitting_checks_every_semicolon_separated_segment() {
    let allowance = "only CREATE/ALTER/DROP/PRAGMA are allowed";
    // A DML tail after the first statement rides the first statement's DDL
    // first word past the gate unless every segment is checked on its own.
    let flagged: &[&str] = &[
        "ALTER TABLE operations ADD COLUMN batch_id TEXT; DELETE FROM operations",
        "DROP TABLE parents; SELECT * FROM children",
        "CREATE INDEX ix ON t (a); UPDATE t SET a = 1",
        "ALTER TABLE a ADD COLUMN b; INSERT INTO b VALUES (1)",
        "CREATE TABLE a (id INTEGER); CREATE VIEW v AS SELECT 1",
        "PRAGMA user_version = 1; VACUUM",
    ];
    for statement in flagged {
        assert!(
            !raw_statement_violations(statement, &DDL_FIRST_WORDS, allowance).is_empty(),
            "the DML tail must be flagged: {statement}"
        );
    }
    // The persistence PRAGMA gate flags a DML tail the same way.
    assert!(
        !raw_statement_violations(
            "PRAGMA user_version = 1; DELETE FROM x",
            &["PRAGMA"],
            "only PRAGMA (test-scope exception) is allowed",
        )
        .is_empty(),
        "the persistence gate must flag the DML tail"
    );
    // Pure multi-statement DDL passes, including quoted `;`s that are part
    // of identifiers or literals, not terminators.
    let clean: &[&str] = &[
        "CREATE TABLE a (id INTEGER PRIMARY KEY); CREATE TABLE b (id INTEGER PRIMARY KEY)",
        "ALTER TABLE a ADD COLUMN b TEXT; DROP INDEX ix_a",
        "DROP TABLE a; PRAGMA user_version = 1",
        "DROP TABLE \"weird;name\"; CREATE TABLE t (a TEXT DEFAULT 'x;y')",
        "DROP TABLE a; -- done; next\nDROP TABLE b",
    ];
    for statement in clean {
        assert!(
            raw_statement_violations(statement, &DDL_FIRST_WORDS, allowance).is_empty(),
            "pure multi-statement DDL must pass: {statement}"
        );
    }
    // Single-statement strings behave exactly as before, and the documented
    // comment-first strictness stays: a leading comment is not a DDL first
    // word on the raw whole string.
    for statement in [
        "CREATE TABLE settings (id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
        "PRAGMA user_version = 12;",
        "ALTER TABLE users ADD COLUMN role TEXT REFERENCES roles(id)",
    ] {
        assert!(
            raw_statement_violations(statement, &DDL_FIRST_WORDS, allowance).is_empty(),
            "single DDL statements must pass unchanged: {statement}"
        );
    }
    assert!(
        !raw_statement_violations(
            "-- note\nALTER TABLE a ADD COLUMN b",
            &DDL_FIRST_WORDS,
            allowance,
        )
        .is_empty(),
        "a comment-first string must still fail the carve-out"
    );
    assert!(
        !raw_statement_violations("DELETE FROM x", &DDL_FIRST_WORDS, allowance).is_empty(),
        "a plain DML statement must still fail"
    );
}

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
