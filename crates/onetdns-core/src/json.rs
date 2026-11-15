//! JSON parser and serializer for the control API, the etcd client, and dashboard data. Input is
//! untrusted, so size, depth, and item count are all bounded; without the bounds one short input
//! could recurse without limit or exhaust memory.

/// Objects are a Vec, not a map, to keep key order; reordering would change signed bodies and
/// human-readable output on every write. Duplicate keys are rejected at parse time.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_num(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    /// Only exact non-negative integers. JSON numbers are f64 and cannot hold integers past 2^53
    /// exactly; converting past that would silently change the value, so out-of-range, fractional,
    /// and non-finite values are all rejected.
    pub fn as_u64(&self) -> Option<u64> {
        const MAX_SAFE_JSON_INTEGER: f64 = 9_007_199_254_740_991.0;
        let number = self.as_num()?;
        (number.is_finite()
            && number >= 0.0
            && number.fract() == 0.0
            && number <= MAX_SAFE_JSON_INTEGER)
            .then_some(number as u64)
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// parse reads the result back to the same value. Non-finite numbers, absent from JSON, are
    /// written as null.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write_text(&mut out);
        out
    }

    fn write_text(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) if !n.is_finite() => out.push_str("null"),
            Json::Num(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => {
                out.push_str(&(*n as i64).to_string())
            }
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Str(s) => out.push_str(&escape(s)),
            Json::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_text(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&escape(key));
                    out.push(':');
                    value.write_text(out);
                }
                out.push('}');
            }
        }
    }
}

/// Quoted JSON string literal. Control characters become \uXXXX escapes; missing one lets outside
/// input break the JSON structure.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parser cursor over bytes; UTF-8 is decoded only where needed.
struct P<'a> {
    s: &'a [u8],
    i: usize,
}

/// Larger bodies are rejected before parsing starts.
const MAX_JSON_BYTES: usize = 1024 * 1024;

/// The parser is recursive, so this bound is the stack overflow defense: a few kilobytes of [[[[
/// would overflow the stack without it.
const MAX_JSON_DEPTH: usize = 128;

/// Per array or object.
const MAX_JSON_ITEMS: usize = 100_000;

impl<'a> P<'a> {
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    /// Errors instead of recursing once depth passes MAX_JSON_DEPTH.
    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting is too deep".into());
        }
        self.ws();
        match self.s.get(self.i) {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'n') => self.lit("null", Json::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            None => Err("Input ended before a value".into()),
            Some(c) if c.is_ascii_graphic() => Err(format!(
                "Unexpected '{}' where a value was expected",
                *c as char
            )),
            Some(c) => Err(format!(
                "Unexpected byte 0x{c:02x} where a value was expected"
            )),
        }
    }
    fn lit(&mut self, kw: &str, v: Json) -> Result<Json, String> {
        if self
            .s
            .get(self.i..)
            .is_some_and(|s| s.starts_with(kw.as_bytes()))
        {
            self.i += kw.len();
            Ok(v)
        } else {
            Err(format!("Expected '{kw}'"))
        }
    }
    /// Unescapes and checks surrogate pairs fully: a lone high or low surrogate is not a valid
    /// scalar value and would corrupt the string later. Unescaped control characters are rejected
    /// (RFC 8259).
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = String::new();
        while let Some(&c) = self.s.get(self.i) {
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = *self.s.get(self.i).ok_or("Input ended inside an escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'u' => {
                            let first = self.hex4()?;
                            let cp = if (0xd800..=0xdbff).contains(&first) {
                                if self.s.get(self.i..self.i.saturating_add(2)) != Some(b"\\u") {
                                    return Err(
                                        "High surrogate is not followed by a low surrogate".into(),
                                    );
                                }
                                self.i += 2;
                                let second = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err("Invalid low surrogate".into());
                                }
                                0x1_0000
                                    + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err("Lone low surrogate".into());
                            } else {
                                first as u32
                            };
                            out.push(char::from_u32(cp).ok_or("Invalid Unicode escape")?);
                        }
                        _ => return Err("Unsupported JSON escape".into()),
                    }
                }
                0x00..=0x1f => return Err("JSON string contains a control character".into()),
                c if c.is_ascii() => out.push(c as char),
                _ => {
                    self.i -= 1;
                    let tail = std::str::from_utf8(&self.s[self.i..])
                        .map_err(|_| "JSON string is not valid UTF-8")?;
                    let ch = tail
                        .chars()
                        .next()
                        .ok_or("JSON string is not valid UTF-8")?;
                    self.i += ch.len_utf8();
                    out.push(ch);
                }
            }
        }
        Err("String is missing its closing quote".into())
    }
    /// Exactly 4 hex digits after the escape, or an error.
    fn hex4(&mut self) -> Result<u16, String> {
        let end = self.i.checked_add(4).ok_or("Unicode escape overflowed")?;
        let raw = self
            .s
            .get(self.i..end)
            .ok_or("Unicode escape is shorter than 4 digits")?;
        let hex = std::str::from_utf8(raw).map_err(|_| "Unicode escape is not valid UTF-8")?;
        let value =
            u16::from_str_radix(hex, 16).map_err(|_| "Unicode escape is not hexadecimal")?;
        self.i = end;
        Ok(value)
    }
    /// RFC 8259 grammar: rejects leading zeros, a point with no digits after it, and an empty
    /// exponent. Rejects values that overflow to infinity, since they cannot be written back as
    /// JSON.
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.s.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.i += 1;
                while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
            }
            _ => return Err("Invalid integer part in JSON number".into()),
        }
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            let fraction_start = self.i;
            while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                self.i += 1;
            }
            if self.i == fraction_start {
                return Err("Invalid fraction part in JSON number".into());
            }
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            let exponent_start = self.i;
            while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                self.i += 1;
            }
            if self.i == exponent_start {
                return Err("Invalid exponent part in JSON number".into());
            }
        }
        let number = std::str::from_utf8(&self.s[start..self.i])
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|number| number.is_finite())
            .ok_or_else(|| "JSON number is out of range".to_string())?;
        Ok(Json::Num(number))
    }
    /// Stops past MAX_JSON_ITEMS.
    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1;
        let mut out = vec![];
        loop {
            self.ws();
            if self.s.get(self.i) == Some(&b']') {
                self.i += 1;
                return Ok(Json::Arr(out));
            }
            if out.len() >= MAX_JSON_ITEMS {
                return Err("JSON array has too many items".into());
            }
            out.push(self.value(depth)?);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(out));
                }
                _ => return Err("Expected ',' or ']' in JSON array".into()),
            }
        }
    }
    /// Rejects duplicate keys. Taking the last value would let implementations disagree on which
    /// value counts, a path for config injection.
    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1;
        let mut out = vec![];
        let mut seen = std::collections::HashSet::new();
        loop {
            self.ws();
            if self.s.get(self.i) == Some(&b'}') {
                self.i += 1;
                return Ok(Json::Obj(out));
            }
            if out.len() >= MAX_JSON_ITEMS {
                return Err("JSON object has too many entries".into());
            }
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return Err("Object keys must be strings".into());
            }
            let key = self.string()?;
            self.ws();
            if self.s.get(self.i) != Some(&b':') {
                return Err("Object entry is missing ':'".into());
            }
            self.i += 1;
            let val = self.value(depth)?;
            if !seen.insert(key.clone()) {
                return Err("JSON object has a duplicate key".into());
            }
            out.push((key, val));
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(out));
                }
                _ => return Err("Expected ',' or '}' in JSON object".into()),
            }
        }
    }
}

pub fn parse(s: &str) -> Result<Json, String> {
    parse_with_limit(s, MAX_JSON_BYTES)
}

/// Rejects input over `max_bytes` without reading it, and anything but whitespace after the value:
/// accepting trailing data lets implementations read one body differently.
pub fn parse_with_limit(s: &str, max_bytes: usize) -> Result<Json, String> {
    if s.len() > max_bytes {
        return Err("JSON input is too large".into());
    }
    let mut p = P {
        s: s.as_bytes(),
        i: 0,
    };
    let value = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err("Trailing data after JSON".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_object_array() {
        let j = parse(r#"{"domains":[["a.com",5],["b.net",3]],"n":42}"#).unwrap();
        assert_eq!(j.get("n").unwrap().as_num(), Some(42.0));
        let d = j.get("domains").unwrap().as_array().unwrap();
        assert_eq!(d[0].as_array().unwrap()[0].as_str(), Some("a.com"));
        assert_eq!(d[1].as_array().unwrap()[1].as_num(), Some(3.0));
    }

    #[test]
    fn to_text_round_trips_through_parse() {
        let source = r#"{"a":[1,2.5,-3,true,false,null],"b":{"c":"x\"y\n\u0001"},"d":[]}"#;
        let value = parse(source).unwrap();
        assert_eq!(parse(&value.to_text()).unwrap(), value);
        assert_eq!(Json::Num(f64::NAN).to_text(), "null");
    }

    #[test]
    fn escape_quotes() {
        assert_eq!(escape("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn rejects_truncated_and_invalid_unicode_escapes_without_panicking() {
        for input in [
            r#""\u"#,
            r#""\u12"#,
            r#""\ud800"#,
            r#""\ud800\u0041"#,
            r#""\udc00"#,
        ] {
            assert!(parse(input).is_err(), "accepted invalid input: {input:?}");
        }
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap().as_str(), Some("😀"));
    }

    #[test]
    fn preserves_utf8_and_rejects_trailing_data() {
        assert_eq!(parse(r#""한글""#).unwrap().as_str(), Some("한글"));
        assert!(parse("null true").is_err());
    }

    #[test]
    /// Without the depth bound the stack overflows.
    fn rejects_excessive_depth_and_duplicate_keys() {
        let nested = format!(
            "{}null{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert!(parse(&nested).is_err());
        assert!(parse(r#"{"same":1,"same":2}"#).is_err());
    }

    #[test]
    fn numbers_follow_json_grammar_and_integer_conversion_is_exact() {
        for input in ["01", "-", "1.", "1e", "1e+", "+1", "1e400"] {
            assert!(parse(input).is_err(), "accepted invalid number: {input}");
        }
        assert_eq!(parse("53").unwrap().as_u64(), Some(53));
        assert_eq!(parse("53.0").unwrap().as_u64(), Some(53));
        assert_eq!(parse("53.9").unwrap().as_u64(), None);
        assert_eq!(parse("-1").unwrap().as_u64(), None);
        assert_eq!(parse("9007199254740992").unwrap().as_u64(), None);
    }
}
