/*!
 * @brief TOML 파서.
 *
 * @details 설정 파일을 읽는 데 필요한 만큼만 한다. 날짜 같은 이 서버가 안 쓰는 형식은 없다.
 * @warning 중복 키를 거부하고 구분자 규칙도 엄격히 본다. 느슨하면 같은 파일을 다르게
 *          읽는 여지가 생기고, 그것이 곧 의도하지 않은 설정으로 이어진다.
 */

use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq)]
/** @brief TOML 값 하나. */
pub enum Value {
    /** @brief 문자열. */
    String(Zeroizing<String>),
    /** @brief 정수. */
    Int(i64),
    /** @brief 실수. */
    Float(f64),
    /** @brief 참거짓. */
    Bool(bool),
    /** @brief 배열. */
    Array(Vec<Value>),
    /** @brief 테이블. */
    Table(BTreeMap<String, Value>),
}

impl Value {
    /** @brief 문자열이면 내용. */
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    /** @brief 정수면 값. */
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    /** @brief 참거짓이면 값. */
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    /** @brief 배열이면 항목들. */
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /** @brief 표면 내용. */
    pub fn as_table(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }
    /** @brief 테이블에서 키로 값을 찾는다. */
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_table().and_then(|t| t.get(key))
    }
}

/** @brief TOML 문자열을 읽는 파서. */
struct Parser<'a> {
    /** @brief 읽고 있는 글. */
    s: &'a [u8],
    /** @brief 지금 위치. */
    i: usize,
    /** @brief 테이블이 겹친 깊이. 상한이 없으면 스택이 넘친다. */
    depth: usize,
}

/** @brief 파싱 결과. 실패하면 사람이 읽을 사유가 붙는다. */
type PResult<T> = Result<T, String>;
/** @brief 중첩 깊이 상한. 깊게 감싼 문서에서 스택이 넘치는 것을 막는다. */
const MAX_NESTING: usize = 64;

impl<'a> Parser<'a> {
    /** @brief 문자열로 파서를 만든다. */
    fn new(s: &'a str) -> Self {
        Self {
            s: s.as_bytes(),
            i: 0,
            depth: 0,
        }
    }

    /** @brief 다음 바이트를 보되 소비하지 않는다. */
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /** @brief 다음 바이트를 소비한다. */
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek();
        if c.is_some() {
            self.i += 1;
        }
        c
    }

    /** @brief 공백과 주석, 줄바꿈을 건너뛴다. */
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => {
                    self.i += 1;
                }
                b'#' => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.i += 1;
                    }
                }
                _ => break,
            }
        }
    }

    /** @brief 줄 안의 공백만 건너뛴다. 줄바꿈은 남긴다. */
    fn skip_inline_ws(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\r' => self.i += 1,
                b'#' => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.i += 1;
                    }
                }
                _ => break,
            }
        }
    }

    /** @brief 문서 전체를 읽는다. */
    fn parse_root(&mut self) -> PResult<Value> {
        let mut root: BTreeMap<String, Value> = BTreeMap::new();

        let mut cur_path: Vec<String> = vec![];
        let mut cur_is_array = false;

        loop {
            self.skip_ws();
            let c = match self.peek() {
                Some(c) => c,
                None => break,
            };
            if c == b'[' {
                self.bump();
                let array = if self.peek() == Some(b'[') {
                    self.bump();
                    true
                } else {
                    false
                };
                let name = self.parse_bare_key()?;
                self.skip_inline_ws();
                if self.bump() != Some(b']') {
                    return Err(format!("The '{name}' header is missing its closing ']'"));
                }
                if array {
                    if self.bump() != Some(b']') {
                        return Err(format!(
                            "The '{name}' array of tables is missing its closing ']]'"
                        ));
                    }

                    let arr = root
                        .entry(name.clone())
                        .or_insert_with(|| Value::Array(vec![]));
                    if let Value::Array(a) = arr {
                        a.push(Value::Table(BTreeMap::new()));
                    } else {
                        return Err(format!("'{name}' is not an array of tables"));
                    }
                    cur_path = vec![name];
                    cur_is_array = true;
                } else {
                    if root.contains_key(&name) {
                        return Err(format!("Duplicate table header: '[{name}]'"));
                    }
                    root.insert(name.clone(), Value::Table(BTreeMap::new()));
                    cur_path = vec![name];
                    cur_is_array = false;
                }
                self.finish_line()?;
            } else {
                let key = self.parse_bare_key()?;
                self.skip_inline_ws();
                if self.bump() != Some(b'=') {
                    return Err(format!("'{key}' is missing its '='"));
                }
                self.skip_inline_ws();
                let val = self.parse_value()?;
                self.insert(&mut root, &cur_path, cur_is_array, key, val)?;
                self.finish_line()?;
            }
        }
        Ok(Value::Table(root))
    }

    /** @brief 줄 끝을 확인한다. 남은 것이 있으면 오류다. */
    fn finish_line(&mut self) -> PResult<()> {
        self.skip_inline_ws();
        match self.peek() {
            Some(b'\n') => {
                self.i += 1;
                Ok(())
            }
            None => Ok(()),
            Some(other) => Err(format!(
                "Unexpected character '{}' after a value or header (position {})",
                other as char, self.i
            )),
        }
    }

    /**
     * @brief 테이블에 값을 넣는다.
     * @warning 같은 키가 두 번 나오면 거부한다. 뒤엣것으로 덮으면 앞의 설정이 조용히 사라진다.
     */
    fn insert(
        &self,
        root: &mut BTreeMap<String, Value>,
        path: &[String],
        is_array: bool,
        key: String,
        val: Value,
    ) -> PResult<()> {
        if path.is_empty() {
            if root.contains_key(&key) {
                return Err(format!("Duplicate key: '{key}'"));
            }
            root.insert(key, val);
            return Ok(());
        }
        let head = &path[0];
        let target = root
            .get_mut(head)
            .ok_or_else(|| format!("Internal error: table '{head}' not found"))?;
        let table = if is_array {
            match target {
                Value::Array(a) => match a.last_mut() {
                    Some(Value::Table(t)) => t,
                    _ => return Err(format!("An item of array '{head}' is not a table")),
                },
                _ => return Err(format!("'{head}' is not an array")),
            }
        } else {
            match target {
                Value::Table(t) => t,
                _ => return Err(format!("'{head}' is not a table")),
            }
        };
        if table.contains_key(&key) {
            return Err(format!("Duplicate key: '{}.{key}'", path.join(".")));
        }
        table.insert(key, val);
        Ok(())
    }

    /** @brief 따옴표 없는 키를 읽는다. */
    fn parse_bare_key(&mut self) -> PResult<String> {
        self.skip_inline_ws();

        if matches!(self.peek(), Some(b'"') | Some(b'\'')) {
            return self.parse_string();
        }
        let start = self.i;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' {
                self.i += 1;
            } else {
                break;
            }
        }
        if self.i == start {
            return Err(format!("Could not find a key (position {})", self.i));
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    /** @brief 값 하나를 읽는다. */
    fn parse_value(&mut self) -> PResult<Value> {
        self.skip_inline_ws();
        match self.peek() {
            Some(b'"') | Some(b'\'') => Ok(Value::String(Zeroizing::new(self.parse_string()?))),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_inline_table(),
            Some(c) if c == b't' || c == b'f' => self.parse_bool(),
            Some(c) if c == b'-' || c == b'+' || c.is_ascii_digit() => self.parse_number(),
            other => Err(format!("Could not parse the value: {other:?}")),
        }
    }

    /** @brief 문자열을 읽는다. 이스케이프를 푼다. */
    fn parse_string(&mut self) -> PResult<String> {
        let quote = self.bump().ok_or("The string has no opening quote")?;
        let mut out: Vec<u8> = Vec::new();
        while let Some(c) = self.bump() {
            if c == quote {
                return String::from_utf8(out)
                    .map_err(|_| "The string is not valid UTF-8".to_string());
            }
            if c == b'\\' && quote == b'"' {
                match self.bump() {
                    Some(b'b') => out.push(0x08),
                    Some(b't') => out.push(b'\t'),
                    Some(b'n') => out.push(b'\n'),
                    Some(b'f') => out.push(0x0c),
                    Some(b'r') => out.push(b'\r'),
                    Some(b'\\') => out.push(b'\\'),
                    Some(b'"') => out.push(b'"'),
                    Some(b'u') => self.push_unicode_escape(4, &mut out)?,
                    Some(b'U') => self.push_unicode_escape(8, &mut out)?,
                    Some(other) => {
                        return Err(format!("Unsupported string escape: \\{}", other as char));
                    }
                    None => return Err("String escape is truncated".into()),
                }
            } else {
                if c < 0x20 && c != b'\t' {
                    return Err("Strings cannot contain raw control characters".into());
                }

                out.push(c);
            }
        }
        Err("String is missing its closing quote".into())
    }

    /** @brief 유니코드 이스케이프를 UTF-8로 푼다. */
    fn push_unicode_escape(&mut self, digits: usize, out: &mut Vec<u8>) -> PResult<()> {
        let end = self
            .i
            .checked_add(digits)
            .filter(|end| *end <= self.s.len())
            .ok_or_else(|| "Unicode escape is truncated".to_string())?;
        let raw = std::str::from_utf8(&self.s[self.i..end])
            .map_err(|_| "Unicode escape is not ASCII".to_string())?;
        let value =
            u32::from_str_radix(raw, 16).map_err(|_| format!("Invalid Unicode escape: {raw}"))?;
        let ch = char::from_u32(value)
            .ok_or_else(|| format!("Unicode scalar not allowed: U+{value:04X}"))?;
        let mut encoded = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
        self.i = end;
        Ok(())
    }

    /** @brief 참거짓을 읽는다. */
    fn parse_bool(&mut self) -> PResult<Value> {
        if self.s[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Value::Bool(true))
        } else if self.s[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Value::Bool(false))
        } else {
            Err("Could not parse bool".into())
        }
    }

    /** @brief 수를 읽는다. */
    fn parse_number(&mut self) -> PResult<Value> {
        let start = self.i;
        let mut is_float = false;
        if matches!(self.peek(), Some(b'-') | Some(b'+')) {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == b'_' {
                self.i += 1;
            } else if c == b'.' || c == b'e' || c == b'E' {
                is_float = true;
                self.i += 1;
            } else {
                break;
            }
        }
        let raw: String = String::from_utf8_lossy(&self.s[start..self.i])
            .chars()
            .filter(|c| *c != '_')
            .collect();
        if is_float {
            raw.parse::<f64>()
                .map(Value::Float)
                .map_err(|e| format!("Could not parse float '{raw}': {e}"))
        } else {
            raw.parse::<i64>()
                .map(Value::Int)
                .map_err(|e| format!("Could not parse integer '{raw}': {e}"))
        }
    }

    /** @brief 배열을 읽는다. 깊이를 세며 들어간다. */
    fn parse_array(&mut self) -> PResult<Value> {
        if self.depth >= MAX_NESTING {
            return Err(format!(
                "Arrays and tables can nest at most {MAX_NESTING} levels"
            ));
        }
        self.depth += 1;
        let result = self.parse_array_inner();
        self.depth -= 1;
        result
    }

    /** @brief 배열 내용을 읽는다. */
    fn parse_array_inner(&mut self) -> PResult<Value> {
        self.bump();
        let mut out = vec![];
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(out));
                }
                None => return Err("Array is missing its closing ']'".into()),
                _ => {
                    out.push(self.parse_value()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => {
                            self.bump();
                        }
                        Some(b']') => {}
                        None => return Err("Array is missing its closing ']'".into()),
                        Some(other) => {
                            return Err(format!(
                                "Expected ',' or ']' after array value, found '{}'",
                                other as char
                            ));
                        }
                    }
                }
            }
        }
    }

    /** @brief 인라인 테이블를 읽는다. */
    fn parse_inline_table(&mut self) -> PResult<Value> {
        if self.depth >= MAX_NESTING {
            return Err(format!(
                "Arrays and tables can nest at most {MAX_NESTING} levels"
            ));
        }
        self.depth += 1;
        let result = self.parse_inline_table_inner();
        self.depth -= 1;
        result
    }

    /** @brief 인라인 테이블의 내용을 읽는다. */
    fn parse_inline_table_inner(&mut self) -> PResult<Value> {
        self.bump();
        let mut t = BTreeMap::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'}') => {
                    self.bump();
                    return Ok(Value::Table(t));
                }
                None => return Err("Inline table is missing its closing '}'".into()),
                _ => {
                    let key = self.parse_bare_key()?;
                    self.skip_inline_ws();
                    if self.bump() != Some(b'=') {
                        return Err(format!("Inline table entry '{key}' is missing '='"));
                    }
                    self.skip_inline_ws();
                    let val = self.parse_value()?;
                    if t.contains_key(&key) {
                        return Err(format!("Inline table has duplicate entry '{key}'"));
                    }
                    t.insert(key, val);
                    self.skip_inline_ws();
                    match self.peek() {
                        Some(b',') => {
                            self.bump();
                        }
                        Some(b'}') => {}
                        None => return Err("Inline table is missing its closing '}'".into()),
                        Some(other) => {
                            return Err(format!(
                                "Expected ',' or '}}' after inline table value, found '{}'",
                                other as char
                            ));
                        }
                    }
                }
            }
        }
    }
}

/** @brief 편집기가 붙이는 BOM. 앞에 있으면 떼어 낸다. */
const UTF8_BOM: &str = "\u{feff}";

/** @brief TOML 문서를 읽는다. */
pub fn parse(s: &str) -> Result<Value, String> {
    Parser::new(s.strip_prefix(UTF8_BOM).unwrap_or(s)).parse_root()
}

#[derive(Debug, Clone, PartialEq)]
/** @brief 최상위 항목 하나와 그 원본 위치. */
pub enum TopEntry {
    /** @brief 항목에 값을 넣는 줄. */
    Assign {
        /** @brief 항목 이름. */
        key: String,
        /** @brief 이 항목이 속한 테이블. 맨 위면 없다. */
        table: Option<usize>,
        /** @brief 텍스트에서 이 줄이 시작하는 위치. */
        start: usize,
        /** @brief 텍스트에서 이 줄이 끝나는 위치. */
        end: usize,
        /** @brief 적힌 값. */
        value: Value,
    },

    /** @brief 테이블이 시작하는 줄. */
    Header {
        /** @brief 테이블 이름. */
        name: String,
        /** @brief 테이블 배열인지. */
        is_array: bool,
        /** @brief 텍스트에서 이 구간이 시작하는 위치. */
        start: usize,
        /** @brief 텍스트에서 이 구간이 끝나는 위치. */
        end: usize,
    },
}

/**
 * @brief 최상위 항목들을 원본 위치와 함께 읽는다.
 * @details 설정을 부분만 고쳐 쓸 때 필요하다. 위치를 알아야 나머지를 건드리지 않고
 *          그 부분만 교체할 수 있다.
 */
pub fn top_entries(s: &str) -> Result<Vec<TopEntry>, String> {
    let Some(body) = s.strip_prefix(UTF8_BOM) else {
        return Parser::new(s).parse_top_entries();
    };
    let shift = UTF8_BOM.len();
    let mut entries = Parser::new(body).parse_top_entries()?;
    for entry in &mut entries {
        let (start, end) = match entry {
            TopEntry::Assign { start, end, .. } | TopEntry::Header { start, end, .. } => {
                (start, end)
            }
        };
        *start += shift;
        *end += shift;
    }
    Ok(entries)
}

impl<'a> Parser<'a> {
    /** @brief 최상위 항목들과 그 범위를 읽는다. */
    fn parse_top_entries(&mut self) -> PResult<Vec<TopEntry>> {
        let mut entries: Vec<TopEntry> = Vec::new();
        let mut current_header: Option<usize> = None;
        let mut top_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut table_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut block_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        loop {
            self.skip_ws();
            let start = self.i;
            let Some(c) = self.peek() else { break };
            if c == b'[' {
                self.bump();
                let is_array = if self.peek() == Some(b'[') {
                    self.bump();
                    true
                } else {
                    false
                };
                let name = self.parse_bare_key()?;
                self.skip_inline_ws();
                if self.bump() != Some(b']') {
                    return Err(format!("Header '{name}' is missing its closing ']'"));
                }
                if is_array {
                    if self.bump() != Some(b']') {
                        return Err(format!("Array table '{name}' is missing its closing ']]'"));
                    }
                } else if !table_names.insert(name.clone()) {
                    return Err(format!("Duplicate table header: '[{name}]'"));
                }
                self.finish_line()?;
                entries.push(TopEntry::Header {
                    name,
                    is_array,
                    start,
                    end: self.i,
                });
                current_header = Some(entries.len() - 1);
                block_keys.clear();
            } else {
                let key = self.parse_bare_key()?;
                self.skip_inline_ws();
                if self.bump() != Some(b'=') {
                    return Err(format!("Missing '=' after '{key}'"));
                }
                self.skip_inline_ws();
                let value = self.parse_value()?;
                self.finish_line()?;
                let duplicate = match current_header {
                    None => !top_keys.insert(key.clone()),
                    Some(_) => !block_keys.insert(key.clone()),
                };
                if duplicate {
                    return Err(format!("Duplicate key: '{key}'"));
                }
                entries.push(TopEntry::Assign {
                    key,
                    table: current_header,
                    start,
                    end: self.i,
                    value,
                });
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
/** @brief 형식별 파싱, 중복과 구분자 엄격성, 그리고 원본 위치의 정확성. */
mod tests {
    use super::*;

    #[test]
    /** @brief 기본 값과 배열. */
    fn scalars_and_arrays() {
        let v = parse(
            r#"
            # 주석
            listen = ["127.0.0.1:53", "::1:53"]
            cache_size = 4096
            rate = 1.5
            on = true
            name = "onetdns"
            "#,
        )
        .unwrap();
        assert_eq!(v.get("cache_size").unwrap().as_int(), Some(4096));
        assert_eq!(v.get("on").unwrap().as_bool(), Some(true));
        assert_eq!(v.get("name").unwrap().as_str(), Some("onetdns"));
        assert_eq!(v.get("listen").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    /** @brief 인라인 테이블와 중첩 배열. */
    fn inline_tables_and_nested_arrays() {
        let v = parse(
            r#"
            rewrites = [{ domain = "router.lan", answer = "192.168.1.1" }, { domain = "x", answer = "1.2.3.4" }]
            local_a = [["router.lan", "192.168.1.1"]]
            "#,
        )
        .unwrap();
        let rw = v.get("rewrites").unwrap().as_array().unwrap();
        assert_eq!(rw.len(), 2);
        assert_eq!(rw[0].get("domain").unwrap().as_str(), Some("router.lan"));
        let la = v.get("local_a").unwrap().as_array().unwrap();
        assert_eq!(la[0].as_array().unwrap()[0].as_str(), Some("router.lan"));
    }

    #[test]
    /** @brief 테이블의 배열. */
    fn array_of_tables() {
        let v = parse(
            r#"
            mode = "public"
            [[clients]]
            name = "kid"
            ids = ["192.168.1.50/32"]
            [[clients]]
            name = "tv"
            "#,
        )
        .unwrap();
        assert_eq!(v.get("mode").unwrap().as_str(), Some("public"));
        let clients = v.get("clients").unwrap().as_array().unwrap();
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].get("name").unwrap().as_str(), Some("kid"));
        assert_eq!(clients[1].get("name").unwrap().as_str(), Some("tv"));
    }

    #[test]
    /** @brief 여러 줄에 걸친 배열. */
    fn multiline_array() {
        let v = parse("blocklists = [\n  \"a.txt\",\n  \"b.txt\",\n]\n").unwrap();
        assert_eq!(v.get("blocklists").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    /** @brief UTF-8과 이스케이프가 보존되는지. */
    fn preserves_utf8_and_unicode_escape() {
        let v = parse("name = \"한글 경로/사용자\"\nescaped = \"\\uD55C\\uAE00\"\n").unwrap();
        assert_eq!(
            v.get("name").and_then(Value::as_str),
            Some("한글 경로/사용자")
        );
        assert_eq!(v.get("escaped").and_then(Value::as_str), Some("한글"));
    }

    #[test]
    /** @brief 중복 키를 거부하는지. 덮으면 앞 설정이 조용히 사라진다. */
    fn duplicate_keys_are_rejected() {
        assert!(parse("do_udp = true\ndo_udp = false\n").is_err());
        assert!(parse("x = { a = 1, a = 2 }\n").is_err());
        assert!(parse("[server]\na = 1\n[server]\nb = 2\n").is_err());
    }

    #[test]
    /** @brief 구분자와 줄 경계를 엄격히 보는지. */
    fn separators_and_line_boundaries_are_strict() {
        assert!(parse("x = [1 2]\n").is_err());
        assert!(parse("x = { a = 1 b = 2 }\n").is_err());
        assert!(parse("a = 1 b = 2\n").is_err());
        assert!(parse("a = 1,\nb = 2\n").is_err());

        assert!(parse("x = [1, 2,]\n").is_ok());
        assert!(parse("x = { a = 1, b = 2 }\n").is_ok());
    }

    #[test]
    /** @brief 깊게 감싼 문서를 스택 넘침 없이 거부하는지. */
    fn excessive_nesting_is_rejected_without_stack_exhaustion() {
        let nested = format!("x = {}0{}\n", "[".repeat(65), "]".repeat(65));
        assert!(parse(&nested).is_err());
    }

    #[test]
    /** @brief BOM이 앞에 있어도 읽히는지. */
    fn utf8_bom_prefixed_document_parses() {
        let body = "listen = [\"127.0.0.1:53\"]\n[server]\nport = 53\n";
        let with_bom = format!("\u{feff}{body}");
        assert_eq!(parse(&with_bom).unwrap(), parse(body).unwrap());
    }

    #[test]
    /** @brief BOM이 있어도 위치가 원본 기준인지. 어긋나면 부분 수정이 엉뚱한 위치를 덮는다. */
    fn top_entries_spans_stay_original_relative_with_bom() {
        let body = "a = \"x\"\n[server]\nport = 53\n";
        let src = format!("\u{feff}{body}");
        let entries = top_entries(&src).unwrap();
        assert_eq!(entries.len(), top_entries(body).unwrap().len());
        match &entries[0] {
            TopEntry::Assign { start, end, .. } => {
                assert_eq!(&src[*start..*end], "a = \"x\"\n");
            }
            other => panic!("Assign 기대: {other:?}"),
        }
        match &entries[1] {
            TopEntry::Header { start, end, .. } => {
                assert_eq!(&src[*start..*end], "[server]\n");
            }
            other => panic!("Header 기대: {other:?}"),
        }
    }

    #[test]
    /** @brief 위치가 원본 조각과 정확히 맞는지. */
    fn top_entries_spans_cover_exact_source_slices() {
        let src = "# 헤더 주석\na = \"val ] ue # not-comment\"\nlist = [\n  \"x]y\",  # 주석\n  \"z\",\n]\n[server]\nport = 53\n[[clients]]\nname = \"kid\"\n";
        let entries = top_entries(src).unwrap();
        let slice = |s: usize, e: usize| &src[s..e];
        match &entries[0] {
            TopEntry::Assign {
                key, start, end, ..
            } => {
                assert_eq!(key, "a");
                assert_eq!(slice(*start, *end), "a = \"val ] ue # not-comment\"\n");
            }
            other => panic!("Assign 기대: {other:?}"),
        }
        match &entries[1] {
            TopEntry::Assign {
                key,
                start,
                end,
                value,
                ..
            } => {
                assert_eq!(key, "list");
                assert!(slice(*start, *end).starts_with("list = [\n"));
                assert!(slice(*start, *end).ends_with("]\n"), "여러 줄 배열 span");
                assert_eq!(value.as_array().unwrap().len(), 2);
            }
            other => panic!("Assign 기대: {other:?}"),
        }
        match &entries[2] {
            TopEntry::Header {
                name,
                is_array,
                start,
                end,
            } => {
                assert_eq!(name, "server");
                assert!(!is_array);
                assert_eq!(slice(*start, *end), "[server]\n");
            }
            other => panic!("Header 기대: {other:?}"),
        }
        match &entries[3] {
            TopEntry::Assign { key, table, .. } => {
                assert_eq!(key, "port");
                assert_eq!(*table, Some(2));
            }
            other => panic!("Assign 기대: {other:?}"),
        }
        match &entries[4] {
            TopEntry::Header { name, is_array, .. } => {
                assert_eq!(name, "clients");
                assert!(is_array);
            }
            other => panic!("Header 기대: {other:?}"),
        }
        match &entries[5] {
            TopEntry::Assign {
                key, table, value, ..
            } => {
                assert_eq!(key, "name");
                assert_eq!(*table, Some(4));
                assert_eq!(value.as_str(), Some("kid"));
            }
            other => panic!("Assign 기대: {other:?}"),
        }
    }

    #[test]
    /** @brief 두 경로가 같은 것을 거부하는지. 갈리면 한쪽으로 우회할 수 있다. */
    fn top_entries_rejects_what_parse_rejects() {
        for bad in [
            "do_udp = true\ndo_udp = false\n",
            "[server]\na = 1\n[server]\nb = 2\n",
            "a = 1 b = 2\n",
            "x = [1 2]\n",
        ] {
            assert!(parse(bad).is_err(), "parse: {bad}");
            assert!(top_entries(bad).is_err(), "top_entries: {bad}");
        }
    }
}
