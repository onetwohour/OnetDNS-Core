/*!
 * @brief JSON 파서와 직렬화기.
 *
 * @details 제어 API, etcd 클라이언트, 대시보드 데이터가 쓴다. 신뢰할 수 없는 입력을 받으므로
 *          크기·깊이·항목 수에 모두 상한이 걸려 있다. 상한이 없으면 짧은 입력 하나로
 *          재귀 깊이를 무한정 늘리거나 메모리를 고갈시킬 수 있다.
 */

/**
 * @brief JSON 값.
 * @note 객체를 맵이 아니라 Vec으로 담아 키 순서를 보존한다. 순서가 바뀌면 서명 대상
 *       본문이나 사람이 읽는 출력이 매번 달라진다. 중복 키는 파싱 단계에서 거부한다.
 */
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum Json {
    /** @brief 없음. */
    Null,
    /** @brief 참거짓. */
    Bool(bool),
    /** @brief 수. */
    Num(f64),
    /** @brief 문자열. */
    Str(String),
    /** @brief 배열. */
    Arr(Vec<Json>),
    /** @brief 객체. 적힌 순서를 지킨다. */
    Obj(Vec<(String, Json)>),
}

impl Json {
    /** @brief 객체에서 키를 찾는다. 객체가 아니면 None. */
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /** @brief 배열 원소를 빌린다. 배열이 아니면 None. */
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    /** @brief 문자열 값을 빌린다. */
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    /** @brief 수 값을 얻는다. */
    pub fn as_num(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    /**
     * @brief 정확히 표현 가능한 음이 아닌 정수로 변환한다.
     * @details JSON 수는 f64라 2^53을 넘으면 정수를 정확히 담지 못한다. 그 위를 그대로
     *          변환하면 조용히 값이 어긋나므로, 안전 범위 밖·소수·비유한값은 전부 거부한다.
     */
    pub fn as_u64(&self) -> Option<u64> {
        /** @brief 실수로 정확히 담을 수 있는 정수 상한. 넘으면 되읽을 때 값이 달라진다. */
        const MAX_SAFE_JSON_INTEGER: f64 = 9_007_199_254_740_991.0;
        let number = self.as_num()?;
        (number.is_finite()
            && number >= 0.0
            && number.fract() == 0.0
            && number <= MAX_SAFE_JSON_INTEGER)
            .then_some(number as u64)
    }
    /** @brief 불 값을 얻는다. */
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /**
     * @brief JSON 텍스트로 적는다. parse 로 다시 읽으면 같은 값이 된다.
     * @note 유한하지 않은 수는 JSON 에 없으므로 null 로 적는다.
     */
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write_text(&mut out);
        out
    }

    /** @brief to_text 의 본체. 버퍼 하나에 이어 쓴다. */
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

/**
 * @brief 문자열을 따옴표까지 포함한 JSON 리터럴로 만든다.
 * @warning 제어문자를 \uXXXX로 바꾼다. 빠뜨리면 외부 입력이 JSON 구조를 깨뜨린다.
 */
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

/** @brief 파서 커서. 바이트 단위로 훑고 필요한 곳에서만 UTF-8을 해석한다. */
struct P<'a> {
    /** @brief 읽고 있는 글. */
    s: &'a [u8],
    /** @brief 지금 위치. */
    i: usize,
}

/** @brief 입력 크기 상한. 이보다 큰 본문은 파싱을 시작하지도 않는다. */
const MAX_JSON_BYTES: usize = 1024 * 1024;

/**
 * @brief 중첩 깊이 상한.
 * @warning 파서가 재귀라 이 상한이 곧 스택 넘침 방어다. [[[[... 몇 킬로바이트면 상한
 *          없이는 스택을 넘긴다.
 */
const MAX_JSON_DEPTH: usize = 128;

/** @brief 배열·객체 하나가 가질 수 있는 항목 수 상한. */
const MAX_JSON_ITEMS: usize = 100_000;

impl<'a> P<'a> {
    /** @brief 공백을 건너뛴다. */
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    /**
     * @brief 첫 바이트로 종류를 정해 값 하나를 읽는다.
     * @param depth 현재 중첩 깊이. 상한을 넘으면 재귀하지 않고 오류를 낸다.
     */
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
    /** @brief true/false/null 키워드를 정확히 대조해 읽는다. */
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
    /**
     * @brief 따옴표 문자열을 읽으며 이스케이프를 푼다.
     *
     * @details 서러게이트 쌍을 온전히 검사한다. 단독 high/low 서러게이트를 통과시키면
     *          유효하지 않은 스칼라값이 되어 이후 처리에서 문자열이 깨진다.
     * @note 이스케이프되지 않은 제어문자는 거부한다(RFC 8259).
     */
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
    /** @brief \u 뒤의 4자리 16진수를 읽는다. 정확히 4자리가 아니면 오류다. */
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
    /**
     * @brief 수를 읽는다. 문법은 RFC 8259 그대로다.
     * @details 선행 0, 소수점만 있고 자릿수가 없는 형태, 지수부가 빈 형태를 모두 거부한다.
     * @note 무한대·NaN이 되는 값은 거부한다. JSON으로 다시 쓸 수 없어 왕복이 깨진다.
     */
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
    /** @brief 배열을 읽는다. 항목 수 상한을 넘으면 중단한다. */
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
    /**
     * @brief 객체를 읽는다.
     * @warning 중복 키는 거부한다. 마지막 값으로 덮어쓰면, 같은 본문을 다르게 해석하는
     *          구현들 사이에서 어느 값이 유효한지가 갈려 설정 주입의 경로가 된다.
     */
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

/** @brief 기본 크기 상한으로 JSON을 파싱한다. */
pub fn parse(s: &str) -> Result<Json, String> {
    parse_with_limit(s, MAX_JSON_BYTES)
}

/**
 * @brief 크기 상한을 지정해 JSON을 파싱한다.
 * @param max_bytes 입력 상한. 넘으면 한 바이트도 읽지 않고 거부한다.
 * @return 값 뒤에 공백 아닌 것이 남아 있으면 오류다. 뒤쪽 쓰레기를 허용하면 한 본문이
 *         구현마다 다르게 읽힌다.
 */
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
/** @brief 읽기와 적기, 그리고 어긋난 입력이 패닉 없이 거부되는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 객체와 배열이 읽히는지. */
    fn parse_object_array() {
        let j = parse(r#"{"domains":[["a.com",5],["b.net",3]],"n":42}"#).unwrap();
        assert_eq!(j.get("n").unwrap().as_num(), Some(42.0));
        let d = j.get("domains").unwrap().as_array().unwrap();
        assert_eq!(d[0].as_array().unwrap()[0].as_str(), Some("a.com"));
        assert_eq!(d[1].as_array().unwrap()[1].as_num(), Some(3.0));
    }

    #[test]
    /** @brief 적은 텍스트를 다시 읽으면 같은 값이 되는지. */
    fn to_text_round_trips_through_parse() {
        let source = r#"{"a":[1,2.5,-3,true,false,null],"b":{"c":"x\"y\n\u0001"},"d":[]}"#;
        let value = parse(source).unwrap();
        assert_eq!(parse(&value.to_text()).unwrap(), value);
        assert_eq!(Json::Num(f64::NAN).to_text(), "null");
    }

    #[test]
    /** @brief 따옴표가 감싸지는지. */
    fn escape_quotes() {
        assert_eq!(escape("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    /** @brief 잘린 문자 표기를 패닉 없이 거부하는지. */
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
    /** @brief 글자가 보존되고 뒤에 남는 바이트를 거부하는지. */
    fn preserves_utf8_and_rejects_trailing_data() {
        assert_eq!(parse(r#""한글""#).unwrap().as_str(), Some("한글"));
        assert!(parse("null true").is_err());
    }

    #[test]
    /** @brief 너무 깊은 중첩과 겹친 이름을 거부하는지. 깊이를 안 막으면 스택이 넘친다. */
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
    /** @brief 수 표기가 규격을 따르고 정수 변환이 정확한지. */
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
