//! Edits the config file's TOML text, keeping the user's comments and order.

use onetdns_config::Config;

use crate::atomic_file::atomic_write;
use crate::config_apply::config_write_lock;
use crate::native_config::stable_resource_id;

pub(crate) fn persist_config_string_array(
    path: &std::path::Path,
    key: &str,
    values: &[String],
) -> std::io::Result<()> {
    use onetdns_core::MutexExt;
    let _write_guard = config_write_lock().lock_recover();
    let text =
        onetdns_core::SecretString::from(Config::read_text(path).map_err(std::io::Error::other)?);
    let updated = onetdns_core::SecretString::from(
        rewrite_config_string_array(&text, key, values).map_err(std::io::Error::other)?,
    );
    atomic_write(path, updated.as_bytes())
}

pub(crate) fn rewrite_config_string_array<T: AsRef<str>>(
    text: &str,
    key: &str,
    values: &[T],
) -> Result<String, String> {
    rewrite_config_kv(text, key, &toml_string_array(values))
}

type TomlEntry = onetdns_config::toml::TopEntry;

/// The span one top-level item occupies in the config text.
struct TomlBlock {
    root: String,
    is_array: bool,
    /// Index of the header in the entries.
    header_idx: usize,
    start: usize,
    end: usize,
}

fn toml_blocks(entries: &[TomlEntry]) -> Vec<TomlBlock> {
    let mut blocks: Vec<TomlBlock> = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        match entry {
            TomlEntry::Header {
                name,
                is_array,
                start,
                end,
            } => blocks.push(TomlBlock {
                root: name.split('.').next().unwrap_or(name).to_string(),
                is_array: *is_array,
                header_idx: idx,
                start: *start,
                end: *end,
            }),
            TomlEntry::Assign {
                table: Some(header),
                end,
                ..
            } => {
                if let Some(block) = blocks.last_mut() {
                    if block.header_idx == *header {
                        block.end = block.end.max(*end);
                    }
                }
            }
            TomlEntry::Assign { .. } => {}
        }
    }
    blocks
}

/// Ranges are byte offsets into the original `text`.
fn splice_config_edits(text: &str, mut edits: Vec<(usize, usize, String)>) -> String {
    edits.sort_by_key(|(start, end, _)| (*start, *end));
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end, replacement) in edits {
        if start > cursor {
            out.push_str(&text[cursor..start]);
        }
        out.push_str(&replacement);
        cursor = cursor.max(end);
    }
    out.push_str(&text[cursor..]);
    out
}

/// Removing a key differs from emptying it: removal restores the default, or turns an optional item
/// off. Without this, an optional item once set could not be undone.
///
/// Only top-level keys; a key of the same name inside a table is left alone. Returns the text
/// unchanged when the key was absent.
pub(crate) fn remove_config_key(text: &str, key: &str) -> Result<String, String> {
    let text = &drop_config_tables(text, key)?;
    let entries = onetdns_config::toml::top_entries(text)?;
    let mut cuts = Vec::new();
    for entry in &entries {
        if let TomlEntry::Assign {
            key: existing,
            table: None,
            start,
            end,
            ..
        } = entry
        {
            if existing == key {
                cuts.push((*start, *end, String::new()));
            }
        }
    }
    if cuts.is_empty() {
        return Ok(text.to_string());
    }
    Ok(splice_config_edits(text, cuts))
}

/// A top-level value for `key` replaces its `[key]` and `[[key]]` blocks. Left in place, the key
/// would appear twice and the table would win, so an empty array could not remove the last entry.
fn drop_config_tables(text: &str, key: &str) -> Result<String, String> {
    let entries = onetdns_config::toml::top_entries(text)?;
    let cuts: Vec<(usize, usize, String)> = toml_blocks(&entries)
        .into_iter()
        .filter(|block| block.root == key)
        .map(|block| (block.start, block.end, String::new()))
        .collect();
    if cuts.is_empty() {
        return Ok(text.to_string());
    }
    Ok(splice_config_edits(text, cuts))
}

/// Replaces the top-level value, or adds it before the first table header when absent, since a
/// key after a header would belong to that table.
pub(crate) fn rewrite_config_kv(text: &str, key: &str, rhs: &str) -> Result<String, String> {
    let text = &drop_config_tables(text, key)?;
    let entries = onetdns_config::toml::top_entries(text)?;
    let line = format!("{key} = {rhs}\n");
    for entry in &entries {
        if let TomlEntry::Assign {
            key: existing,
            table: None,
            start,
            end,
            ..
        } = entry
        {
            if existing == key {
                return Ok(splice_config_edits(text, vec![(*start, *end, line)]));
            }
        }
    }
    let first_header = entries.iter().find_map(|entry| match entry {
        TomlEntry::Header { start, .. } => Some(*start),
        _ => None,
    });
    Ok(match first_header {
        Some(pos) => splice_config_edits(text, vec![(pos, pos, line)]),
        None => {
            let mut out = text.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&line);
            out
        }
    })
}

/// Keys the snippet does not touch, and comments, stay as they are.
pub(crate) fn merge_config_snippet(current: &str, snippet: &str) -> Result<String, String> {
    let snip_entries = onetdns_config::toml::top_entries(snippet)?;
    if snip_entries.is_empty() {
        return Ok(current.to_string());
    }
    let mut base = current.to_string();
    for entry in &snip_entries {
        if let TomlEntry::Assign {
            key, table: None, ..
        } = entry
        {
            base = drop_config_tables(&base, key)
                .map_err(|error| format!("Could not parse the current configuration: {error}"))?;
        }
    }
    let current = base.as_str();
    let cur_entries = onetdns_config::toml::top_entries(current)
        .map_err(|error| format!("Could not parse the current configuration: {error}"))?;
    let fragment = |source: &str, start: usize, end: usize| {
        let mut piece = source[start..end].to_string();
        if !piece.ends_with('\n') {
            piece.push('\n');
        }
        piece
    };

    let snip_blocks = toml_blocks(&snip_entries);
    let replaced_tables: std::collections::HashSet<&str> = snip_blocks
        .iter()
        .map(|block| block.root.as_str())
        .collect();
    let first_header = cur_entries.iter().find_map(|entry| match entry {
        TomlEntry::Header { start, .. } => Some(*start),
        _ => None,
    });

    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut tail = String::new();
    'assign: for entry in &snip_entries {
        let TomlEntry::Assign {
            key,
            table: None,
            start,
            end,
            ..
        } = entry
        else {
            continue;
        };
        let piece = fragment(snippet, *start, *end);
        for cur in &cur_entries {
            if let TomlEntry::Assign {
                key: existing,
                table: None,
                start,
                end,
                ..
            } = cur
            {
                if existing == key {
                    edits.push((*start, *end, piece));
                    continue 'assign;
                }
            }
        }
        match first_header {
            Some(pos) => edits.push((pos, pos, piece)),
            None => tail.push_str(&piece),
        }
    }
    for block in toml_blocks(&cur_entries) {
        if replaced_tables.contains(block.root.as_str()) {
            edits.push((block.start, block.end, String::new()));
        }
    }
    let mut out = splice_config_edits(current, edits);
    for block in &snip_blocks {
        tail.push_str(&fragment(snippet, block.start, block.end));
    }
    if !tail.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&tail);
    }
    Ok(out)
}

pub(crate) fn toml_quote(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for character in s.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control.is_control() => {
                let code = control as u32;
                if code <= 0xffff {
                    let _ = write!(out, "\\u{code:04X}");
                } else {
                    let _ = write!(out, "\\U{code:08X}");
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Does not reveal the token.
pub(crate) fn token_id(tok: &str) -> String {
    stable_resource_id("token", tok)
}

/// Removes the control tokens whose fingerprint matches, returning the new text and the count.
/// Fails when none matches; returning the text unchanged would make the caller rewrite the file and
/// restart the service.
pub(crate) fn remove_token_by_id(text: &str, id: &str) -> Result<(String, usize), String> {
    let cur = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
    let before = cur.control_admin_tokens.len() + cur.control_readonly_tokens.len();
    let admin: Vec<_> = cur
        .control_admin_tokens
        .into_iter()
        .filter(|t| token_id(t) != id)
        .collect();
    let ro: Vec<_> = cur
        .control_readonly_tokens
        .into_iter()
        .filter(|t| token_id(t) != id)
        .collect();
    let removed = before - (admin.len() + ro.len());
    if removed == 0 {
        return Err(
            "No matching token, or the token is the primary control token, which cannot be deleted"
                .to_string(),
        );
    }
    let out = rewrite_config_string_array(text, "control_admin_tokens", &admin)?;
    let out = rewrite_config_string_array(&out, "control_readonly_tokens", &ro)?;
    Ok((out, removed))
}

pub(crate) fn token_mask(tok: &str) -> String {
    let count = tok.chars().count();
    if count > 10 {
        let head: String = tok.chars().take(6).collect();
        let tail: String = tok.chars().skip(count - 2).collect();
        format!("{head}…{tail}")
    } else {
        "••••••".to_string()
    }
}

pub(crate) fn rewrites_to_toml(rw: &[onetdns_config::Rewrite]) -> String {
    let items: Vec<String> = rw
        .iter()
        .map(|r| {
            format!(
                "{{ domain = {}, answer = {} }}",
                toml_quote(&r.domain),
                toml_quote(&r.answer)
            )
        })
        .collect();
    format!("[{}]", items.join(", "))
}

fn toml_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// A mode change without `acl_allow` also writes that mode's default ACL.
pub(crate) fn materialize_mode_acl_patch(
    pairs: &mut Vec<(String, onetdns_core::json::Json)>,
) -> Result<(), String> {
    if pairs.iter().any(|(key, _)| key == "acl_allow") {
        return Ok(());
    }
    let Some((_, value)) = pairs.iter().find(|(key, _)| key == "mode") else {
        return Ok(());
    };
    let mode = value
        .as_str()
        .ok_or_else(|| "mode must be the string personal or public".to_string())?;
    let mode = match mode.to_ascii_lowercase().as_str() {
        "personal" => onetdns_config::Mode::Personal,
        "public" => onetdns_config::Mode::Public,
        _ => return Err("Mode must be personal or public".into()),
    };
    pairs.push((
        "acl_allow".into(),
        onetdns_core::json::Json::Arr(
            mode.preset_acl_allow()
                .into_iter()
                .map(|cidr| onetdns_core::json::Json::Str(cidr.to_string()))
                .collect(),
        ),
    ));
    Ok(())
}

/// Rejects a redacted value sent back as is; saving it would overwrite the real secret with the
/// mask.
pub(crate) fn validate_config_patch_values(
    pairs: &[(String, onetdns_core::json::Json)],
) -> Result<(), String> {
    use onetdns_core::json::Json;
    const TOKEN_ARRAYS: &[&str] = &["control_admin_tokens", "control_readonly_tokens"];
    /// Accepted on write, never read back.
    const WRITE_ONLY_STRINGS: &[&str] = &[
        "control_token",
        "cluster_raft_secret",
        "cluster_raft_node_key",
        "zones_etcd_password",
        "cachedb_redis_secret",
        "cachedb_redis_password",
    ];
    /// Shown redacted because they embed passwords.
    const REDACTED_URLS: &[&str] = &["zones_postgres", "zones_mysql"];

    for (key, value) in pairs {
        // null deletes the key; values are checked only when set.
        if matches!(value, Json::Null) {
            continue;
        }
        if TOKEN_ARRAYS.contains(&key.as_str()) {
            return Err(format!(
                "{key} cannot be changed in the general settings editor; use the access token screen"
            ));
        }
        if REDACTED_URLS.contains(&key.as_str()) {
            let Some(text) = value.as_str() else {
                return Err(format!("{key} needs a connection string"));
            };
            let lowered = text.to_ascii_lowercase();
            if text.contains("***") || lowered.contains("redacted") || lowered.contains("masked") {
                return Err(format!(
                    "{key} cannot be saved with a masked value; enter the new connection string"
                ));
            }
        }
        if WRITE_ONLY_STRINGS.contains(&key.as_str()) {
            match value {
                Json::Str(text)
                    if !text.trim().is_empty()
                        && !text.contains("***")
                        && !text.to_ascii_lowercase().contains("redacted") => {}
                _ => {
                    return Err(format!(
                        "{key} is a secret setting whose current value is never shown; enter the new value"
                    ))
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn json_to_toml_literal(v: &onetdns_core::json::Json) -> Result<String, String> {
    use onetdns_core::json::Json;
    Ok(match v {
        Json::Bool(b) => b.to_string(),
        Json::Num(n) => toml_num(*n),
        Json::Str(s) => toml_quote(s),
        Json::Arr(a) => {
            let mut parts = Vec::with_capacity(a.len());
            for it in a {
                parts.push(match it {
                    Json::Str(s) => toml_quote(s),
                    Json::Num(n) => toml_num(*n),
                    Json::Bool(b) => b.to_string(),
                    _ => return Err("Arrays may contain only strings, numbers, or booleans".into()),
                });
            }
            format!("[{}]", parts.join(", "))
        }
        Json::Null => return Err("null is not allowed".into()),
        Json::Obj(_) => {
            return Err(
                "Nested settings must be changed through the DNS zone or client APIs".into(),
            )
        }
    })
}

/// No config value nests deeper.
pub(crate) const MAX_RAFT_VALUE_DEPTH: usize = 8;

/// For the Raft log. Rejects integers beyond 2^53: JSON numbers are doubles, and past that a
/// different number would replicate to every node.
pub(crate) fn toml_value_to_json(
    value: &onetdns_config::toml::Value,
) -> Result<onetdns_core::json::Json, String> {
    use onetdns_config::toml::Value;
    use onetdns_core::json::Json;
    /// The largest integer a double holds exactly.
    const MAX_EXACT: i64 = 9_007_199_254_740_991;
    Ok(match value {
        Value::String(text) => Json::Str(text.to_string()),
        Value::Int(number) if number.unsigned_abs() <= MAX_EXACT as u64 => {
            Json::Num(*number as f64)
        }
        Value::Int(_) => {
            return Err(
                "The configuration contains an integer too large to replicate through Raft".into(),
            )
        }
        Value::Float(number) => Json::Num(*number),
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Array(items) => Json::Arr(
            items
                .iter()
                .map(toml_value_to_json)
                .collect::<Result<_, _>>()?,
        ),
        Value::Table(fields) => Json::Obj(
            fields
                .iter()
                .map(|(key, value)| Ok((key.clone(), toml_value_to_json(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

/// Unlike `json_to_toml_literal`, accepts tables and nested arrays, since the cluster must share
/// table arrays such as `clients` and `local_zones`. Tables become inline tables: the file looks
/// different but parses to the same value.
///
/// Fails on a null inside the value or nesting too deep. A top-level null means deleting the key,
/// and the caller handles it.
pub(crate) fn json_to_raft_toml_literal(
    value: &onetdns_core::json::Json,
    depth: usize,
) -> Result<String, String> {
    use onetdns_core::json::Json;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft configuration value is nested too deeply".into());
    }
    Ok(match value {
        Json::Null => return Err("Raft configuration values cannot contain null".into()),
        Json::Bool(flag) => flag.to_string(),
        Json::Num(number) if number.is_finite() => toml_num(*number),
        Json::Num(_) => return Err("Raft configuration value is not a finite number".into()),
        Json::Str(text) => toml_quote(text),
        Json::Arr(items) => {
            let parts = items
                .iter()
                .map(|item| json_to_raft_toml_literal(item, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            format!("[{}]", parts.join(", "))
        }
        Json::Obj(fields) => {
            let mut parts = Vec::with_capacity(fields.len());
            for (key, value) in fields {
                let bare = !key.is_empty()
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
                let key = if bare { key.clone() } else { toml_quote(key) };
                parts.push(format!(
                    "{key} = {}",
                    json_to_raft_toml_literal(value, depth + 1)?
                ));
            }
            format!("{{ {} }}", parts.join(", "))
        }
    })
}

/// Which config key this upstream entry belongs to.
pub(crate) fn upstream_key(entry: &str) -> &'static str {
    if entry.contains("://") {
        "upstream_urls"
    } else {
        "upstreams"
    }
}

pub(crate) fn upstream_values(cfg: &onetdns_config::Config, key: &str) -> Vec<String> {
    if key == "upstream_urls" {
        cfg.upstream_urls.clone()
    } else {
        cfg.upstreams.iter().map(|ip| ip.to_string()).collect()
    }
}

/// Returns the `[[clients]]` block and the client name.
pub(crate) fn client_block_from_json(body: &str) -> Result<(String, String), String> {
    use onetdns_core::json;
    let j = json::parse(body).map_err(|e| format!("Could not parse the JSON request body: {e}"))?;
    let name = j
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(name) = name else {
        return Err("`name` is required".to_string());
    };
    let arr = |k: &str| -> Vec<String> {
        j.get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let boolean = |k: &str| j.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let mut b = String::from("\n[[clients]]\n");
    b.push_str(&format!("name = {}\n", toml_quote(name)));
    for (k, json_k) in [
        ("ids", "ids"),
        ("client_ids", "client_ids"),
        ("mac", "mac"),
        ("tags", "tags"),
        ("block", "block"),
        ("allow", "allow"),
        ("blocked_services", "blocked_services"),
    ] {
        let v = arr(json_k);
        if !v.is_empty() {
            b.push_str(&format!("{k} = {}\n", toml_string_array(&v)));
        }
    }
    if boolean("disable_filtering") {
        b.push_str("disable_filtering = true\n");
    }
    if boolean("safe_search") {
        b.push_str("safe_search = true\n");
    }
    Ok((b, name.to_string()))
}

pub(crate) fn remove_client_block(text: &str, name: &str) -> Option<String> {
    let entries = onetdns_config::toml::top_entries(text).ok()?;
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for block in toml_blocks(&entries) {
        if !(block.is_array && block.root == "clients") {
            continue;
        }
        let name_matches = entries.iter().any(|entry| {
            matches!(entry, TomlEntry::Assign { key, table: Some(header), value, .. }
                if key == "name" && *header == block.header_idx && value.as_str() == Some(name))
        });
        if name_matches {
            edits.push((block.start, block.end, String::new()));
        }
    }
    if edits.is_empty() {
        return None;
    }
    Some(splice_config_edits(text, edits))
}

fn client_to_toml(client: &onetdns_config::ClientConfig) -> String {
    let mut out = String::from("\n[[clients]]\n");
    out.push_str(&format!("name = {}\n", toml_quote(&client.name)));
    let ids: Vec<String> = client.ids.iter().map(ToString::to_string).collect();
    for (key, values) in [
        ("ids", ids),
        ("client_ids", client.client_ids.clone()),
        ("mac", client.mac.clone()),
        ("tags", client.tags.clone()),
        ("block", client.block.clone()),
        ("allow", client.allow.clone()),
        ("blocked_services", client.blocked_services.clone()),
        ("upstreams", client.upstreams.clone()),
    ] {
        if !values.is_empty() {
            out.push_str(&format!("{key} = {}\n", toml_string_array(&values)));
        }
    }
    if client.disable_filtering {
        out.push_str("disable_filtering = true\n");
    }
    if let Some(value) = client.safe_search {
        out.push_str(&format!("safe_search = {value}\n"));
    }
    if client.ignore_querylog {
        out.push_str("ignore_querylog = true\n");
    }
    if client.ignore_stats {
        out.push_str("ignore_stats = true\n");
    }
    out
}

pub(crate) fn update_client_disable(
    text: &str,
    name: &str,
    disable: bool,
) -> Result<String, String> {
    let cfg = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
    let mut client = cfg
        .clients
        .into_iter()
        .find(|c| c.name == name)
        .ok_or_else(|| format!("Client not found: {name}"))?;
    client.disable_filtering = disable;
    let mut updated =
        remove_client_block(text, name).ok_or_else(|| format!("Client not found: {name}"))?;
    updated.push_str(&client_to_toml(&client));
    Ok(updated)
}

/// Appends the first admin account at the end of the text: a table array entry inserted midway
/// would capture the keys after it. Fails when a `users` entry already exists, so it is only for
/// creating the first account.
pub(crate) fn append_user_block(text: &str, name: &str, hash: &str) -> Result<String, String> {
    let entries = onetdns_config::toml::top_entries(text)?;
    if toml_blocks(&entries)
        .iter()
        .any(|block| block.is_array && block.root == "users")
    {
        return Err("A user account already exists".to_string());
    }
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str("[[users]]\n");
    out.push_str(&format!("name = {}\n", toml_quote(name)));
    out.push_str(&format!("password_hash = {}\n", toml_quote(hash)));
    out.push_str("role = \"admin\"\n");
    Ok(out)
}

pub(crate) fn rewrite_user_password_hash(
    text: &str,
    name: &str,
    hash: &str,
) -> Result<String, String> {
    let entries = onetdns_config::toml::top_entries(text)?;
    let line = format!("password_hash = {}\n", toml_quote(hash));
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut found = false;
    for block in toml_blocks(&entries) {
        if !(block.is_array && block.root == "users") {
            continue;
        }
        let members = || {
            entries.iter().filter_map(|entry| match entry {
                TomlEntry::Assign {
                    key,
                    table: Some(header),
                    start,
                    end,
                    value,
                } if *header == block.header_idx => Some((key, *start, *end, value)),
                _ => None,
            })
        };
        if !members().any(|(key, _, _, value)| key == "name" && value.as_str() == Some(name)) {
            continue;
        }
        found = true;
        let mut wrote = false;
        for (key, start, end, _) in members() {
            if key == "password_hash" {
                edits.push((start, end, line.clone()));
                wrote = true;
            } else if key == "password" {
                edits.push((start, end, String::new()));
            }
        }
        if !wrote {
            edits.push((block.end, block.end, line.clone()));
        }
    }
    if !found {
        return Err(format!("User not found: {name}"));
    }
    Ok(splice_config_edits(text, edits))
}

pub(crate) fn toml_string_array<T: AsRef<str>>(values: &[T]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| toml_quote(value.as_ref()))
        .collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_config::Config;

    use crate::unix_now;

    #[test]
    fn token_ids_are_stable_without_exposing_token_contents() {
        let first = token_id("secret-token-value");
        let same = token_id("secret-token-value");
        let other = token_id("different-token-value");
        assert_eq!(first, same);
        assert_ne!(first, other);
        assert!(first.starts_with("token-"));
        assert!(!first.contains("secret"));
    }

    #[test]
    fn removing_an_unknown_token_id_fails_without_touching_the_config() {
        let admin = "a".repeat(24);
        let ro = "b".repeat(24);
        let text =
            format!("control_admin_tokens = [\"{admin}\"]\ncontrol_readonly_tokens = [\"{ro}\"]\n");

        assert!(remove_token_by_id(&text, "token-없는-지문").is_err());

        let (out, removed) = remove_token_by_id(&text, &token_id(&ro)).unwrap();
        assert_eq!(removed, 1);
        assert!(out.contains(&admin));
        assert!(!out.contains(&ro));
    }

    #[test]
    fn config_patch_rejects_redacted_or_destructive_secret_placeholders() {
        use onetdns_core::json::Json;
        for pair in [
            (
                "zones_postgres",
                Json::Str("postgres://dns:***@localhost/zones".into()),
            ),
            (
                "zones_mysql",
                Json::Str("mysql://dns:<redacted>@localhost/zones".into()),
            ),
            ("cluster_raft_secret", Json::Str(String::new())),
            ("control_admin_tokens", Json::Arr(Vec::new())),
        ] {
            assert!(validate_config_patch_values(&[(pair.0.to_string(), pair.1)]).is_err());
        }
        assert!(validate_config_patch_values(&[(
            "zones_postgres".to_string(),
            Json::Str("postgres://dns:new-secret@localhost/zones".into()),
        )])
        .is_ok());
    }

    #[test]
    fn persist_subscriptions_rewrites_key_preserving_rest() {
        let dir = std::env::temp_dir();

        let stamp = format!("{}-{}", std::process::id(), unix_now());

        let p = dir.join(format!("onetdns-persist-a-{stamp}.toml"));
        std::fs::write(
            &p,
            "# my config\nlisten = [\"0.0.0.0:53\"]\nblocklist_urls = [\"https://old/list.txt\"]\nupstreams = [\"1.1.1.1\"]\n\n[[clients]]\nname = \"kid\"\n",
        )
        .unwrap();
        persist_config_string_array(
            &p,
            "blocklist_urls",
            &[
                "https://new/a.txt".to_string(),
                "https://new/b.txt".to_string(),
            ],
        )
        .unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("blocklist_urls = [\"https://new/a.txt\", \"https://new/b.txt\"]"));
        assert!(!after.contains("old/list.txt"), "기존 값 제거");
        assert!(after.contains("# my config") && after.contains("upstreams = [\"1.1.1.1\"]"));
        assert!(after.contains("[[clients]]") && after.contains("name = \"kid\""));

        assert!(onetdns_config::Config::from_toml_str(&after).is_ok());
        let _ = std::fs::remove_file(&p);

        let p2 = dir.join(format!("onetdns-persist-b-{stamp}.toml"));
        std::fs::write(
            &p2,
            "listen = [\"0.0.0.0:53\"]\n\n[[clients]]\nname = \"x\"\n",
        )
        .unwrap();
        persist_config_string_array(&p2, "blocklist_urls", &["https://x/y.txt".to_string()])
            .unwrap();
        let after2 = std::fs::read_to_string(&p2).unwrap();
        assert!(after2.contains("blocklist_urls = [\"https://x/y.txt\"]"));
        let urls_at = after2.find("blocklist_urls").unwrap();
        let clients_at = after2.find("[[clients]]").unwrap();
        assert!(urls_at < clients_at, "키는 테이블 헤더 앞에 위치");
        assert!(onetdns_config::Config::from_toml_str(&after2).is_ok());
        let _ = std::fs::remove_file(&p2);

        let p3 = dir.join(format!("onetdns-persist-c-{stamp}.toml"));
        std::fs::write(
            &p3,
            "blocklist_urls = [\n  \"https://a\",\n  \"https://b\"\n]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        persist_config_string_array(&p3, "blocklist_urls", &["https://only.txt".to_string()])
            .unwrap();
        let after3 = std::fs::read_to_string(&p3).unwrap();
        assert!(after3.contains("blocklist_urls = [\"https://only.txt\"]"));
        assert!(
            !after3.contains("https://a") && !after3.contains("https://b"),
            "이전 다중 줄 값 제거"
        );
        assert!(after3.contains("upstreams = [\"9.9.9.9\"]"));
        assert!(onetdns_config::Config::from_toml_str(&after3).is_ok());
        let _ = std::fs::remove_file(&p3);
    }

    #[test]
    fn persist_config_array_does_not_create_missing_config() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-persist-missing-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        let _ = std::fs::remove_file(&path);

        let result =
            persist_config_string_array(&path, "block_rules", &["blocked.example".to_string()]);

        assert!(result.is_err());
        assert!(
            !path.exists(),
            "읽지 못한 설정 파일을 새로 만들면 안 됩니다"
        );
    }

    #[test]
    fn client_block_crud_helpers() {
        let (block, name) = client_block_from_json(
            "{\"name\":\"kid\",\"ids\":[\"192.168.1.5/32\"],\"tags\":[\"child\"],\"disable_filtering\":false}",
        )
        .unwrap();
        assert_eq!(name, "kid");
        assert!(block.contains("[[clients]]"));
        assert!(block.contains("name = \"kid\""));
        assert!(block.contains("ids = [\"192.168.1.5/32\"]"));
        assert!(block.contains("tags = [\"child\"]"));
        assert!(!block.contains("disable_filtering"), "false 필드는 생략");
        assert!(
            client_block_from_json("{\"ids\":[]}").is_err(),
            "name 없으면 에러"
        );

        let base = "listen = [\"0.0.0.0:53\"]\n";
        let full = format!("{base}{block}");
        assert!(onetdns_config::Config::from_toml_str(&full).is_ok());
        let removed = remove_client_block(&full, "kid").unwrap();
        assert!(!removed.contains("name = \"kid\""));
        assert!(removed.contains("listen"));
        assert!(onetdns_config::Config::from_toml_str(&removed).is_ok());
        assert!(
            remove_client_block(base, "ghost").is_none(),
            "없는 이름 → None"
        );
    }

    #[test]
    fn remove_client_block_matches_escaped_name() {
        let name = "a\"b\\c";
        let block = format!("[[clients]]\nname = {}\n", toml_quote(name));
        let full = format!("listen = [\"0.0.0.0:53\"]\n{block}");
        assert!(onetdns_config::Config::from_toml_str(&full).is_ok());
        let removed = remove_client_block(&full, name).expect("escape된 이름 삭제");
        assert!(!removed.contains("[[clients]]"));
        assert!(removed.contains("listen"));
    }

    #[test]
    fn removing_a_key_leaves_the_rest_alone() {
        let text = "listen = [\"0.0.0.0:53\"]
    control_listen = \"127.0.0.1:8553\"
    querylog = true

    [[users]]
    name = \"admin\"
    ";
        let out = remove_config_key(text, "control_listen").unwrap();
        assert!(!out.contains("control_listen"), "지운 항목이 남았습니다");
        assert!(out.contains("listen = "), "다른 항목이 함께 지워졌습니다");
        assert!(out.contains("querylog = true"));
        assert!(out.contains("[[users]]"), "테이블이 함께 지워졌습니다");

        // Removing an absent key is not a failure.
        let same = remove_config_key(&out, "control_listen").unwrap();
        assert_eq!(same, out);

        // The same name inside a table is left alone.
        let nested = "[[zones]]
    name = \"a\"
    ";
        assert_eq!(remove_config_key(nested, "name").unwrap(), nested);
    }

    #[test]
    fn deleting_a_key_skips_value_checks() {
        use onetdns_core::json::Json;
        let pairs = vec![("control_token".to_string(), Json::Null)];
        assert!(
            validate_config_patch_values(&pairs).is_ok(),
            "지우기는 넣기 규칙에 걸리면 안 됩니다"
        );
    }

    #[test]
    fn rewrite_config_kv_handles_bracket_in_string() {
        let text = "blocklist_urls = [\n  \"https://x/a]b.txt\",  # note ] here\n  \"https://x/c.txt\",\n]\nupstreams = [\"1.1.1.1\"]\n";
        let out = rewrite_config_kv(text, "blocklist_urls", "[\"https://new.txt\"]").unwrap();
        assert!(out.contains("blocklist_urls = [\"https://new.txt\"]"));
        assert!(!out.contains("a]b.txt"), "기존 배열 완전 제거");
        assert!(!out.contains("c.txt"));
        assert!(out.contains("upstreams = [\"1.1.1.1\"]"), "다른 키 보존");
    }

    #[test]
    fn merge_config_snippet_preserves_unrelated_keys_and_comments() {
        let cur = "# 헤더 주석\ncontrol_token = \"0123456789abcdef01234567\"\ncache_size = 8192\nupstreams = [\"1.1.1.1\", \"1.0.0.1\"]\n";
        let out = merge_config_snippet(
            cur,
            "list_refresh_secs = 3600\nupstream_strategy = \"round_robin\"\n",
        )
        .unwrap();
        assert!(
            out.contains("control_token = \"0123456789abcdef01234567\""),
            "토큰 보존: {out}"
        );
        assert!(out.contains("# 헤더 주석"));
        assert!(out.contains("cache_size = 8192"));
        assert!(out.contains("upstreams = [\"1.1.1.1\", \"1.0.0.1\"]"));
        assert!(out.contains("list_refresh_secs = 3600"));
        assert!(out.contains("upstream_strategy = \"round_robin\""));
        Config::from_toml_str(&out).unwrap();
    }

    #[test]
    fn merge_config_snippet_replaces_existing_and_multiline_arrays() {
        let cur = "cache_size = 1024\nblocklist_urls = [\n  \"https://a.txt\",\n  \"https://b.txt\",\n]\nmin_ttl = 5\n";
        let out = merge_config_snippet(
            cur,
            "blocklist_urls = [\n  \"https://c.txt\",\n]\ncache_size = 2048\n",
        )
        .unwrap();
        assert!(out.contains("cache_size = 2048"));
        assert!(!out.contains("cache_size = 1024"));
        assert!(out.contains("https://c.txt"));
        assert!(!out.contains("a.txt"), "기존 배열 완전 교체: {out}");
        assert!(out.contains("min_ttl = 5"));
        Config::from_toml_str(&out).unwrap();
    }

    #[test]
    fn merge_config_snippet_replaces_table_blocks_by_root() {
        let cur =
            "cache_size = 8192\n[[clients]]\nname = \"old\"\nids = [\"10.0.0.1\"]\nupstreams = [\"9.9.9.9\"]\n";
        let out = merge_config_snippet(
            cur,
            "[[clients]]\nname = \"new\"\nids = [\"10.0.0.2\"]\nupstreams = [\"8.8.8.8\"]\n",
        )
        .unwrap();
        assert!(out.contains("cache_size = 8192"));
        assert!(out.contains("10.0.0.2"));
        assert!(!out.contains("10.0.0.1"), "기존 블록 전부 교체: {out}");
        Config::from_toml_str(&out).unwrap();
    }

    #[test]
    fn merge_config_snippet_empty_or_comment_only_keeps_current() {
        let cur = "cache_size = 8192\n";
        assert_eq!(merge_config_snippet(cur, "").unwrap(), cur);
        assert_eq!(merge_config_snippet(cur, "# 주석뿐\n\n").unwrap(), cur);
    }

    #[test]
    fn upstream_key_classifies() {
        assert_eq!(upstream_key("1.1.1.1"), "upstreams");
        assert_eq!(upstream_key("tls://1.1.1.1#cf"), "upstream_urls");
        assert_eq!(upstream_key("https://8.8.8.8/dns-query"), "upstream_urls");
    }

    #[test]
    /// The dashboard edits table keys only through snippets; without this, the last NOTIFY target
    /// or secondary zone could not be removed.
    fn empty_array_replaces_the_last_table_entry() {
        let current = "listen = [\"127.0.0.1:5300\"]\n\n[[notify]]\naddress = \"192.0.2.9:53\"\n";
        let merged = merge_config_snippet(current, "notify = []\n").unwrap();
        assert!(
            Config::from_toml_str(&merged).unwrap().notify.is_empty(),
            "{merged}"
        );
        let set = rewrite_config_kv(current, "notify", "[]").unwrap();
        assert!(
            Config::from_toml_str(&set).unwrap().notify.is_empty(),
            "{set}"
        );
        let removed = remove_config_key(current, "notify").unwrap();
        assert!(
            Config::from_toml_str(&removed).unwrap().notify.is_empty(),
            "{removed}"
        );
        assert!(merged.contains("listen"), "{merged}");
    }

    #[test]
    fn toml_quote_escapes_control_characters() {
        assert_eq!(toml_quote("a\n\tb\u{7f}"), "\"a\\n\\tb\\u007F\"");
        assert_eq!(
            toml_string_array(&["a\nb".to_string(), "c\"d".to_string()]),
            "[\"a\\nb\", \"c\\\"d\"]"
        );
    }
}
