/*!
 * @brief 정규식 엔진.
 *
 * @details 백트래킹이 아니라 스레드 집합을 함께 진행시키는 방식이다. 그래서 입력 길이에
 *          선형인 시간이 보장된다.
 * @warning 이 엔진은 운영자가 쓴 규칙을 실행한다. 백트래킹 엔진이었다면 규칙 하나가
 *          지수 시간을 쓰는 상황이 가능했다. 명령 수와 중첩 깊이에도 상한이 있다.
 * @note 바이트 단위로 다룬다. 도메인 이름이 대상이라 그것으로 충분하다.
 */

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 패턴이 잘못됐을 때의 오류. */
pub struct Error(pub String);

impl std::fmt::Display for Error {
    /** @brief 사람이 읽을 문구. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Regex error: {}", self.0)
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone)]
/** @brief 파싱한 패턴의 트리. */
enum Ast {
    /** @brief 빈 것. 아무것도 안 먹는다. */
    Empty,
    /** @brief 이 바이트 하나. */
    Literal(u8),
    /** @brief 아무 글자 하나. */
    AnyChar { dotall: bool },

    /** @brief 이 문자 클래스에 드는 문자 하나. */
    Class {
        /** @brief 이 클래스에 들지 않는 문자를 고르는지. */
        negated: bool,
        /** @brief 클래스에 든 문자 범위들. */
        ranges: Vec<(u8, u8)>,
    },
    /** @brief 차례로 이어진다. */
    Concat(Vec<Ast>),
    /** @brief 여럿 중 하나. */
    Alt(Vec<Ast>),
    /** @brief 정해진 횟수만큼 되풀이한다. */
    Repeat {
        /** @brief 되풀이할 것. */
        node: Box<Ast>,
        /** @brief 적어도 이만큼. */
        min: u32,
        /** @brief 많아야 이만큼. 없으면 끝이 없다. */
        max: Option<u32>,
    },
    /** @brief 글 또는 줄의 시작. */
    StartAnchor { multiline: bool },
    /** @brief 글 또는 줄의 끝. */
    EndAnchor { multiline: bool },
    /** @brief 단어 경계. */
    WordBoundary(bool),
}

/** @brief 반복 횟수 상한. 큰 값을 그대로 펼치면 명령 수가 폭증한다. */
const MAX_REPEAT: u32 = 1000;

/** @brief 만들 수 있는 명령 수 상한. 규칙 하나가 메모리를 다 쓰지 못하게 한다. */
const MAX_INSTS: usize = 200_000;

/** @brief 파싱 중첩 깊이 상한. 깊게 감싼 패턴에서 스택이 넘치는 것을 막는다. */
const MAX_PARSE_DEPTH: usize = 200;

#[derive(Clone, Copy)]
/** @brief 지금 유효한 플래그. 괄호 안에서 바꿨다가 나오면 되돌아간다. */
struct Flags {
    /** @brief 대소문자를 가리지 않는다. */
    ci: bool,
    /** @brief 아무 글자에 줄바꿈도 넣는다. */
    dotall: bool,
    /** @brief 줄마다 시작과 끝을 본다. */
    multiline: bool,
    /** @brief 빈칸과 주석을 무시한다. */
    extended: bool,
}

/** @brief 패턴 문자열을 읽어 트리로 만드는 파서. */
struct Parser<'a> {
    /** @brief 읽고 있는 글. */
    s: &'a [u8],
    /** @brief 지금 위치. */
    pos: usize,
    /** @brief 괄호가 겹친 깊이. 상한이 없으면 스택이 넘친다. */
    depth: usize,
    /** @brief 대소문자를 가리지 않는다. */
    ci: bool,
    /** @brief 아무 글자에 줄바꿈도 넣는다. */
    dotall: bool,
    /** @brief 줄마다 시작과 끝을 본다. */
    multiline: bool,
    /** @brief 빈칸과 주석을 무시한다. */
    extended: bool,
}

impl<'a> Parser<'a> {
    /** @brief 패턴으로 파서를 만든다. */
    fn new(s: &'a [u8]) -> Self {
        Parser {
            s,
            pos: 0,
            depth: 0,
            ci: false,
            dotall: false,
            multiline: false,
            extended: false,
        }
    }

    /** @brief 지금 플래그. */
    fn flags(&self) -> Flags {
        Flags {
            ci: self.ci,
            dotall: self.dotall,
            multiline: self.multiline,
            extended: self.extended,
        }
    }

    /** @brief 플래그를 되돌린다. 괄호를 빠져나올 때 부른다. */
    fn restore(&mut self, f: Flags) {
        self.ci = f.ci;
        self.dotall = f.dotall;
        self.multiline = f.multiline;
        self.extended = f.extended;
    }

    /** @brief 확장 모드에서 공백과 주석을 건너뛴다. */
    fn skip_x_ws(&mut self) {
        if !self.extended {
            return;
        }
        while let Some(c) = self.peek() {
            if c == b'#' {
                while let Some(c) = self.bump() {
                    if c == b'\n' {
                        break;
                    }
                }
            } else if c.is_ascii_whitespace() {
                self.bump();
            } else {
                break;
            }
        }
    }

    /** @brief 다음 바이트를 보되 소비하지 않는다. */
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    /** @brief 다음 바이트를 소비한다. */
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    /** @brief 기대한 바이트면 소비한다. */
    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /** @brief 세로줄로 나뉜 선택지를 읽는다. */
    fn parse_alt(&mut self) -> Result<Ast, Error> {
        let mut branches = vec![self.parse_concat()?];
        while self.eat(b'|') {
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            branches
                .pop()
                .ok_or_else(|| Error("Empty alternative".to_string()))
        } else {
            Ok(Ast::Alt(branches))
        }
    }

    /** @brief 이어 붙인 조각들을 읽는다. */
    fn parse_concat(&mut self) -> Result<Ast, Error> {
        let mut parts = vec![];
        loop {
            self.skip_x_ws();
            match self.peek() {
                None | Some(b'|') | Some(b')') => break,
                _ => {}
            }
            parts.push(self.parse_repeat()?);
        }
        match parts.len() {
            0 => Ok(Ast::Empty),
            1 => parts
                .pop()
                .ok_or_else(|| Error("Empty concatenation".to_string())),
            _ => Ok(Ast::Concat(parts)),
        }
    }

    /** @brief 반복 표시가 붙은 조각을 읽는다. */
    fn parse_repeat(&mut self) -> Result<Ast, Error> {
        let atom = self.parse_atom()?;
        self.skip_x_ws();
        let (min, max) = match self.peek() {
            Some(b'*') => {
                self.bump();
                (0, None)
            }
            Some(b'+') => {
                self.bump();
                (1, None)
            }
            Some(b'?') => {
                self.bump();
                (0, Some(1))
            }
            Some(b'{') => match self.try_parse_bounds()? {
                Some(mm) => mm,
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };

        self.eat(b'?');
        Ok(Ast::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    /** @brief 중괄호 반복 범위를 읽어 본다. 형식이 아니면 되돌린다. */
    fn try_parse_bounds(&mut self) -> Result<Option<(u32, Option<u32>)>, Error> {
        let start = self.pos;
        self.bump();
        let min = match self.parse_uint() {
            Some(n) => n,
            None => {
                self.pos = start;
                return Ok(None);
            }
        };
        let max = if self.eat(b',') {
            if self.peek() == Some(b'}') {
                None
            } else {
                match self.parse_uint() {
                    Some(m) => Some(m),
                    None => {
                        self.pos = start;
                        return Ok(None);
                    }
                }
            }
        } else {
            Some(min)
        };
        if !self.eat(b'}') {
            self.pos = start;
            return Ok(None);
        }
        if min > MAX_REPEAT || max.map(|m| m > MAX_REPEAT).unwrap_or(false) {
            return Err(Error("Regex repetition count is too large".into()));
        }
        if let Some(m) = max {
            if m < min {
                return Err(Error("Repetition range is reversed".into()));
            }
        }
        Ok(Some((min, max)))
    }

    /** @brief 부호 없는 정수를 읽는다. */
    fn parse_uint(&mut self) -> Option<u32> {
        let start = self.pos;
        let mut n: u32 = 0;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                n = n.saturating_mul(10).saturating_add((c - b'0') as u32);
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            None
        } else {
            Some(n)
        }
    }

    /** @brief 가장 작은 단위 하나를 읽는다. */
    fn parse_atom(&mut self) -> Result<Ast, Error> {
        match self.peek() {
            None => Ok(Ast::Empty),
            Some(b'(') => self.parse_group(),
            Some(b'[') => self.parse_class(),
            Some(b'.') => {
                self.bump();
                Ok(Ast::AnyChar {
                    dotall: self.dotall,
                })
            }
            Some(b'^') => {
                self.bump();
                Ok(Ast::StartAnchor {
                    multiline: self.multiline,
                })
            }
            Some(b'$') => {
                self.bump();
                Ok(Ast::EndAnchor {
                    multiline: self.multiline,
                })
            }
            Some(b'\\') => self.parse_escape(),
            Some(b'*') | Some(b'+') | Some(b'?') => {
                Err(Error("Quantifier has nothing to repeat".into()))
            }
            Some(c) => {
                self.bump();
                Ok(Ast::Literal(self.fold(c)))
            }
        }
    }

    /** @brief 괄호로 묶인 조각을 읽는다. 깊이 상한을 여기서 검사한다. */
    fn parse_group(&mut self) -> Result<Ast, Error> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(Error("Regex nesting is too deep".into()));
        }
        let r = self.parse_group_inner();
        self.depth -= 1;
        r
    }

    /** @brief 괄호 안을 읽는다. 플래그 지정 괄호도 여기서 갈린다. */
    fn parse_group_inner(&mut self) -> Result<Ast, Error> {
        self.bump();
        if self.eat(b'?') {
            match self.peek() {
                Some(b':') => {
                    self.bump();
                }
                Some(c) if c == b'-' || is_flag_char(c) => match self.parse_flag_group()? {
                    None => return Ok(Ast::Empty),
                    Some(saved) => {
                        let inner = self.parse_alt()?;
                        if !self.eat(b')') {
                            return Err(Error("Missing closing parenthesis".into()));
                        }
                        self.restore(saved);
                        return Ok(inner);
                    }
                },
                _ => return Err(Error("Unsupported (?...) group".into())),
            }
        }
        let inner = self.parse_alt()?;
        if !self.eat(b')') {
            return Err(Error("Missing closing parenthesis".into()));
        }
        Ok(inner)
    }

    /** @brief 플래그 하나를 켜거나 끈다. */
    fn set_flag(&mut self, c: u8, on: bool) {
        match c {
            b'i' => self.ci = on,
            b's' => self.dotall = on,
            b'm' => self.multiline = on,
            b'x' => self.extended = on,
            _ => {}
        }
    }

    /** @brief 플래그만 바꾸는 괄호를 읽는다. */
    fn parse_flag_group(&mut self) -> Result<Option<Flags>, Error> {
        let saved = self.flags();
        let mut negate = false;
        loop {
            match self.peek() {
                Some(b'-') if !negate => {
                    self.bump();
                    negate = true;
                }
                Some(c) if is_flag_char(c) => {
                    self.bump();
                    self.set_flag(c, !negate);
                }
                Some(b':') => {
                    self.bump();
                    return Ok(Some(saved));
                }
                Some(b')') => {
                    self.bump();
                    return Ok(None);
                }
                _ => return Err(Error("Unsupported group flag".into())),
            }
        }
    }

    /** @brief 대괄호 문자 집합을 읽는다. */
    fn parse_class(&mut self) -> Result<Ast, Error> {
        self.bump();
        let negated = self.eat(b'^');
        let mut ranges: Vec<(u8, u8)> = vec![];

        let mut first = true;
        loop {
            match self.peek() {
                None => return Err(Error("Unclosed character class".into())),
                Some(b']') if !first => {
                    self.bump();
                    break;
                }
                _ => {}
            }
            first = false;
            let lo = self.class_atom(&mut ranges)?;
            let Some(lo) = lo else { continue };

            if self.peek() == Some(b'-')
                && self.s.get(self.pos + 1) != Some(&b']')
                && self.s.get(self.pos + 1).is_some()
            {
                self.bump();
                let hi = self.class_atom(&mut ranges)?;
                match hi {
                    Some(hi) if hi >= lo => self.push_class_range(&mut ranges, lo, hi),
                    Some(_) => return Err(Error("Character class range is reversed".into())),
                    None => {
                        self.push_class_range(&mut ranges, lo, lo);
                    }
                }
            } else {
                self.push_class_range(&mut ranges, lo, lo);
            }
        }
        if ranges.is_empty() {
            return Err(Error("Empty character class".into()));
        }
        Ok(Ast::Class { negated, ranges })
    }

    /** @brief 문자 범위를 집합에 넣는다. 대소문자 무시면 양쪽을 다 넣는다. */
    fn push_class_range(&self, ranges: &mut Vec<(u8, u8)>, lo: u8, hi: u8) {
        ranges.push((lo, hi));
        if self.ci {
            let ua = lo.max(b'A');
            let ub = hi.min(b'Z');
            if ua <= ub {
                ranges.push((ua + 0x20, ub + 0x20));
            }
            let la = lo.max(b'a');
            let lb = hi.min(b'z');
            if la <= lb {
                ranges.push((la - 0x20, lb - 0x20));
            }
        }
    }

    /** @brief 문자 집합 안의 항목 하나를 읽는다. */
    fn class_atom(&mut self, ranges: &mut Vec<(u8, u8)>) -> Result<Option<u8>, Error> {
        match self.bump() {
            None => Err(Error("Unclosed character class".into())),
            Some(b'\\') => {
                let e = self.bump().ok_or_else(|| Error("Invalid escape".into()))?;
                match e {
                    b'd' => {
                        ranges.push((b'0', b'9'));
                        Ok(None)
                    }
                    b'w' => {
                        ranges.extend_from_slice(&WORD_RANGES);
                        Ok(None)
                    }
                    b's' => {
                        ranges.extend_from_slice(&SPACE_RANGES);
                        Ok(None)
                    }
                    b'D' => {
                        ranges.extend(complement_ranges(&[(b'0', b'9')]));
                        Ok(None)
                    }
                    b'W' => {
                        ranges.extend(complement_ranges(&WORD_RANGES));
                        Ok(None)
                    }
                    b'S' => {
                        ranges.extend(complement_ranges(&SPACE_RANGES));
                        Ok(None)
                    }
                    b'n' => Ok(Some(b'\n')),
                    b't' => Ok(Some(b'\t')),
                    b'r' => Ok(Some(b'\r')),
                    b'f' => Ok(Some(0x0C)),
                    b'v' => Ok(Some(0x0B)),
                    b'0' => Ok(Some(0)),
                    b'b' => Ok(Some(0x08)),
                    other => Ok(Some(other)),
                }
            }
            Some(c) => Ok(Some(c)),
        }
    }

    /** @brief 역슬래시 이스케이프를 읽는다. */
    fn parse_escape(&mut self) -> Result<Ast, Error> {
        self.bump();
        let e = self
            .bump()
            .ok_or_else(|| Error("Trailing backslash in pattern".into()))?;
        Ok(match e {
            b'd' => class_from(&[(b'0', b'9')], false),
            b'D' => class_from(&[(b'0', b'9')], true),
            b'w' => class_from(&WORD_RANGES, false),
            b'W' => class_from(&WORD_RANGES, true),
            b's' => class_from(&SPACE_RANGES, false),
            b'S' => class_from(&SPACE_RANGES, true),
            b'b' => Ast::WordBoundary(true),
            b'B' => Ast::WordBoundary(false),
            b'n' => Ast::Literal(b'\n'),
            b't' => Ast::Literal(b'\t'),
            b'r' => Ast::Literal(b'\r'),
            b'f' => Ast::Literal(0x0C),
            b'v' => Ast::Literal(0x0B),
            b'0' => Ast::Literal(0),

            other => Ast::Literal(self.fold(other)),
        })
    }

    /** @brief 대소문자 무시일 때 바이트를 소문자로 바꾼다. */
    fn fold(&self, b: u8) -> u8 {
        if self.ci {
            b.to_ascii_lowercase()
        } else {
            b
        }
    }
}

/** @brief 단어 문자 범위. */
const WORD_RANGES: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'a', b'z'), (b'_', b'_')];
/** @brief 공백 문자 범위. */
const SPACE_RANGES: [(u8, u8); 2] = [(b'\t', b'\r'), (b' ', b' ')];

/** @brief 이 문자가 플래그 이름인지. */
fn is_flag_char(c: u8) -> bool {
    matches!(c, b'i' | b's' | b'm' | b'x')
}

/** @brief 범위 집합의 여집합. 부정 문자 집합에 쓴다. */
fn complement_ranges(ranges: &[(u8, u8)]) -> Vec<(u8, u8)> {
    let mut sorted: Vec<(u8, u8)> = ranges.to_vec();
    sorted.sort_by_key(|r| r.0);
    let mut out = Vec::new();
    let mut next: u16 = 0;
    for (lo, hi) in sorted {
        let (lo, hi) = (lo as u16, hi as u16);
        if lo > next {
            out.push((next as u8, (lo - 1) as u8));
        }
        if hi + 1 > next {
            next = hi + 1;
        }
    }
    if next <= 255 {
        out.push((next as u8, 255));
    }
    out
}

/** @brief 범위 집합에서 트리 노드를 만든다. */
fn class_from(ranges: &[(u8, u8)], negated: bool) -> Ast {
    Ast::Class {
        negated,
        ranges: ranges.to_vec(),
    }
}

#[derive(Debug, Clone)]
/** @brief 실행할 명령 하나. */
enum Inst {
    /** @brief 이 바이트와 맞는지 본다. */
    Byte(u8),
    /** @brief 아무 글자 하나를 먹는다. */
    Any { dotall: bool },
    /** @brief 이 문자 클래스와 맞는지 본다. */
    Class {
        /** @brief 이 클래스에 들지 않는 문자와 맞는지. */
        negated: bool,
        /** @brief 클래스에 든 문자 범위들. */
        ranges: Vec<(u8, u8)>,
    },
    /** @brief 여기까지 오면 맞은 것이다. */
    Match,
    /** @brief 이곳으로 건너뛴다. */
    Jmp(usize),
    /** @brief 두 분기로 나뉜다. */
    Split(usize, usize),
    /** @brief 시작 위치인지 본다. */
    Start { multiline: bool },
    /** @brief 끝 곳인지 본다. */
    End { multiline: bool },
    /** @brief 단어 경계인지 본다. */
    WordBoundary(bool),
}

/** @brief 트리를 명령 목록으로 바꾸는 것. */
struct Compiler {
    /** @brief 만가지고 있는 명령들. */
    insts: Vec<Inst>,
}

impl Compiler {
    /** @brief 명령 하나를 낸다. 상한을 넘으면 실패다. */
    fn emit(&mut self, i: Inst) -> Result<usize, Error> {
        if self.insts.len() >= MAX_INSTS {
            return Err(Error("Regex is too large".into()));
        }
        self.insts.push(i);
        Ok(self.insts.len() - 1)
    }

    /** @brief 트리 노드 하나를 명령으로 바꾼다. */
    fn compile(&mut self, ast: &Ast) -> Result<(), Error> {
        match ast {
            Ast::Empty => {}
            Ast::Literal(b) => {
                self.emit(Inst::Byte(*b))?;
            }
            Ast::AnyChar { dotall } => {
                self.emit(Inst::Any { dotall: *dotall })?;
            }
            Ast::Class { negated, ranges } => {
                self.emit(Inst::Class {
                    negated: *negated,
                    ranges: ranges.clone(),
                })?;
            }
            Ast::StartAnchor { multiline } => {
                self.emit(Inst::Start {
                    multiline: *multiline,
                })?;
            }
            Ast::EndAnchor { multiline } => {
                self.emit(Inst::End {
                    multiline: *multiline,
                })?;
            }
            Ast::WordBoundary(w) => {
                self.emit(Inst::WordBoundary(*w))?;
            }
            Ast::Concat(parts) => {
                for p in parts {
                    self.compile(p)?;
                }
            }
            Ast::Alt(branches) => {
                let mut jmps = vec![];
                let n = branches.len();
                for (i, b) in branches.iter().enumerate() {
                    if i + 1 < n {
                        let split = self.emit(Inst::Split(0, 0))?;
                        let l1 = self.insts.len();
                        self.compile(b)?;
                        let j = self.emit(Inst::Jmp(0))?;
                        jmps.push(j);
                        let l2 = self.insts.len();
                        self.insts[split] = Inst::Split(l1, l2);
                    } else {
                        self.compile(b)?;
                    }
                }
                let end = self.insts.len();
                for j in jmps {
                    self.insts[j] = Inst::Jmp(end);
                }
            }
            Ast::Repeat { node, min, max } => self.compile_repeat(node, *min, *max)?,
        }
        Ok(())
    }

    /**
     * @brief 반복을 명령으로 펼친다.
     * @note 최소 횟수만큼은 그대로 복사하고 나머지를 선택 분기로 만든다. 반복 상한이
     *       없으면 이 펼치기가 명령 수를 폭증시킨다.
     */
    fn compile_repeat(&mut self, node: &Ast, min: u32, max: Option<u32>) -> Result<(), Error> {
        for _ in 0..min {
            self.compile(node)?;
        }
        match max {
            None => {
                let l1 = self.emit(Inst::Split(0, 0))?;
                let body = self.insts.len();
                self.compile(node)?;
                self.emit(Inst::Jmp(l1))?;
                let exit = self.insts.len();
                self.insts[l1] = Inst::Split(body, exit);
            }
            Some(m) => {
                let optional = m.saturating_sub(min);
                let mut splits = vec![];
                for _ in 0..optional {
                    let s = self.emit(Inst::Split(0, 0))?;
                    splits.push(s);
                    let body = self.insts.len();
                    self.insts[s] = Inst::Split(body, 0);
                    self.compile(node)?;
                }
                let end = self.insts.len();
                for s in splits {
                    if let Inst::Split(a, _) = self.insts[s] {
                        self.insts[s] = Inst::Split(a, end);
                    }
                }
            }
        }
        Ok(())
    }
}

/**
 * @brief 스레드 집합. 넣기와 확인이 상수 시간이고 비우기도 상수 시간이다.
 * @details 매 입력 바이트마다 비우므로, 비우는 비용이 크기에 비례하면 안 된다.
 */
struct SparseSet {
    /** @brief 위치마다 마지막으로 넣은 세대. */
    gen: Vec<u32>,
    /** @brief 지금 세대. 비울 때 이것만 올린다. */
    cur: u32,
    /** @brief 지금 들어 있는 곳들. */
    dense: Vec<usize>,
}

impl SparseSet {
    /** @brief 빈 집합. */
    fn new() -> Self {
        SparseSet {
            gen: Vec::new(),
            cur: 0,
            dense: Vec::new(),
        }
    }

    /** @brief 이만큼의 명령을 담을 수 있게 한다. */
    fn ensure(&mut self, n: usize) {
        if self.gen.len() < n {
            self.gen.resize(n, 0);
        }
    }
    /** @brief 비운다. 세대 번호만 올려 상수 시간이다. */
    fn clear(&mut self) {
        self.cur = self.cur.wrapping_add(1);
        if self.cur == 0 {
            for g in &mut self.gen {
                *g = 0;
            }
            self.cur = 1;
        }
        self.dense.clear();
    }
    /** @brief 이 명령이 집합에 있는지. */
    fn contains(&self, pc: usize) -> bool {
        self.gen[pc] == self.cur
    }
    /** @brief 명령을 집합에 넣는다. */
    fn insert(&mut self, pc: usize) {
        self.gen[pc] = self.cur;
        self.dense.push(pc);
    }
}

/** @brief 실행마다 재사용하는 작업 공간. 매번 할당하지 않는다. */
struct Scratch {
    /** @brief 이번 글자에서 볼 분기들. */
    clist: SparseSet,
    /** @brief 다음 글자에서 볼 분기들. */
    nlist: SparseSet,
    /** @brief 분기를 펼칠 때 쓰는 곳. */
    stack: Vec<usize>,
}

thread_local! {
    /** @brief 이 스레드가 재사용하는 작업 공간. 판정마다 새로 잡지 않으려는 것이다. */
    static SCRATCH: std::cell::RefCell<Scratch> = std::cell::RefCell::new(Scratch {
        clist: SparseSet::new(),
        nlist: SparseSet::new(),
        stack: Vec::new(),
    });
}

/** @brief 단어 문자인지. */
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/** @brief 이 위치가 단어 경계인지. */
fn word_boundary(input: &[u8], pos: usize) -> bool {
    let before = pos > 0 && is_word(input[pos - 1]);
    let after = pos < input.len() && is_word(input[pos]);
    before != after
}

#[derive(Debug)]
/** @brief 컴파일된 프로그램. */
struct Prog {
    /** @brief 실행할 명령들. */
    insts: Vec<Inst>,
    /** @brief 시작 위치에 묶여 있는지. 그러면 앞으로 밀며 다시 보지 않는다. */
    start_anchored: bool,
}

impl Prog {
    /**
     * @brief 스레드를 집합에 넣고 분기를 따라 펼친다.
     * @note 이미 있는 명령은 다시 넣지 않는다. 그것이 선형 시간을 보장하는 근거다.
     */
    fn add_thread(
        &self,
        list: &mut SparseSet,
        pc: usize,
        pos: usize,
        input: &[u8],
        stack: &mut Vec<usize>,
    ) {
        stack.clear();
        stack.push(pc);
        while let Some(pc) = stack.pop() {
            if list.contains(pc) {
                continue;
            }
            list.insert(pc);
            match &self.insts[pc] {
                Inst::Jmp(t) => stack.push(*t),
                Inst::Split(a, b) => {
                    stack.push(*b);
                    stack.push(*a);
                }
                Inst::Start { multiline }
                    if pos == 0 || (*multiline && pos > 0 && input[pos - 1] == b'\n') =>
                {
                    stack.push(pc + 1);
                }
                Inst::End { multiline }
                    if pos == input.len() || (*multiline && input.get(pos) == Some(&b'\n')) =>
                {
                    stack.push(pc + 1);
                }
                Inst::WordBoundary(want) if word_boundary(input, pos) == *want => {
                    stack.push(pc + 1);
                }

                _ => {}
            }
        }
    }

    /** @brief 이 입력에 맞는지. */
    fn is_match(&self, input: &[u8]) -> bool {
        SCRATCH.with(|s| {
            let mut s = s.borrow_mut();
            let Scratch {
                clist,
                nlist,
                stack,
            } = &mut *s;
            self.run(input, clist, nlist, stack)
        })
    }

    /**
     * @brief 입력을 한 바이트씩 진행시키며 맞는지 본다.
     * @details 모든 후보를 동시에 진행시킨다. 되돌아가지 않으므로 시간이 입력 길이에 선형이다.
     */
    fn run(
        &self,
        input: &[u8],
        clist: &mut SparseSet,
        nlist: &mut SparseSet,
        stack: &mut Vec<usize>,
    ) -> bool {
        let n = self.insts.len();
        clist.ensure(n);
        nlist.ensure(n);

        clist.clear();
        for pos in 0..=input.len() {
            if pos == 0 || !self.start_anchored {
                self.add_thread(clist, 0, pos, input, stack);
            }

            let byte = input.get(pos).copied();
            nlist.clear();

            let mut i = 0;
            while i < clist.dense.len() {
                let pc = clist.dense[i];
                i += 1;
                match &self.insts[pc] {
                    Inst::Match => return true,
                    Inst::Byte(b) if byte == Some(*b) => {
                        self.add_thread(nlist, pc + 1, pos + 1, input, stack);
                    }
                    Inst::Any { dotall } => {
                        if let Some(b) = byte {
                            if *dotall || b != b'\n' {
                                self.add_thread(nlist, pc + 1, pos + 1, input, stack);
                            }
                        }
                    }
                    Inst::Class { negated, ranges } => {
                        if let Some(b) = byte {
                            let inside = ranges.iter().any(|(lo, hi)| b >= *lo && b <= *hi);
                            if inside != *negated {
                                self.add_thread(nlist, pc + 1, pos + 1, input, stack);
                            }
                        }
                    }
                    _ => {}
                }
            }
            std::mem::swap(clist, nlist);
        }
        false
    }
}

/** @brief 패턴을 트리로 만든다. */
fn parse_pattern(pattern: &str) -> Result<Ast, Error> {
    let mut parser = Parser::new(pattern.as_bytes());
    let ast = parser.parse_alt()?;
    if parser.pos != parser.s.len() {
        return Err(Error("Unexpected character".into()));
    }
    Ok(ast)
}

/** @brief 트리를 프로그램으로 만든다. */
fn compile_ast(ast: &Ast) -> Result<Prog, Error> {
    let mut c = Compiler { insts: Vec::new() };
    c.compile(ast)?;
    c.emit(Inst::Match)?;
    Ok(Prog {
        insts: c.insts,
        start_anchored: is_start_anchored(ast),
    })
}

/** @brief 패턴이 시작에 고정돼 있는지. 그러면 위치를 옮겨 가며 시도하지 않아도 된다. */
fn is_start_anchored(ast: &Ast) -> bool {
    match ast {
        Ast::StartAnchor { multiline: false } => true,
        Ast::Concat(parts) => parts
            .iter()
            .find(|part| !matches!(part, Ast::Empty))
            .map(is_start_anchored)
            .unwrap_or(false),
        Ast::Alt(branches) => !branches.is_empty() && branches.iter().all(is_start_anchored),
        _ => false,
    }
}

/** @brief 패턴 문자열을 바로 프로그램으로 만든다. */
fn compile_pattern(pattern: &str) -> Result<Prog, Error> {
    compile_ast(&parse_pattern(pattern)?)
}

#[derive(Debug)]
/** @brief 컴파일된 정규식 하나. */
pub struct Regex {
    /** @brief 이 정규식의 명령들. */
    prog: Prog,
}

impl Regex {
    /** @brief 패턴을 컴파일한다. 형식이 어긋나거나 상한을 넘으면 오류다. */
    pub fn new(pattern: &str) -> Result<Regex, Error> {
        Ok(Regex {
            prog: compile_pattern(pattern)?,
        })
    }

    /** @brief 이 문자열에 맞는지. */
    pub fn is_match(&self, text: &str) -> bool {
        self.prog.is_match(text.as_bytes())
    }
}

#[derive(Debug)]
/** @brief 여러 패턴을 묶은 것. 하나라도 맞으면 맞는 것으로 본다. */
pub struct RegexSet {
    /** @brief 묶어 놓은 정규식들의 명령. 하나도 없으면 없다. */
    prog: Option<Prog>,
}

impl RegexSet {
    /** @brief 패턴들을 한꺼번에 컴파일한다. 하나라도 잘못되면 전체가 실패다. */
    pub fn new<I, S>(patterns: I) -> Result<RegexSet, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut asts = vec![];
        for p in patterns {
            asts.push(parse_pattern(p.as_ref())?);
        }
        let prog = match asts.len() {
            0 => None,
            1 => Some(compile_ast(
                &asts
                    .pop()
                    .ok_or_else(|| Error("Empty regex set".to_string()))?,
            )?),
            _ => Some(compile_ast(&Ast::Alt(asts))?),
        };
        Ok(RegexSet { prog })
    }

    /** @brief 어느 하나라도 맞는지. */
    pub fn is_match(&self, text: &str) -> bool {
        match &self.prog {
            Some(p) => p.is_match(text.as_bytes()),
            None => false,
        }
    }
}

#[cfg(test)]
/** @brief 문법 요소별 동작, 플래그, 그리고 지수 시간이 걸리지 않는지. */
mod tests {
    use super::*;

    /** @brief 패턴과 문자열이 맞는지 간단히 확인한다. */
    fn m(pat: &str, hay: &str) -> bool {
        Regex::new(pat).unwrap().is_match(hay)
    }

    #[test]
    /** @brief 고정되지 않은 문자열이 어디서든 맞는지. */
    fn literal_unanchored() {
        assert!(m("ads", "x.ads.example.com"));
        assert!(m("ads", "ads"));
        assert!(!m("ads", "ad.example.com"));
    }

    #[test]
    /** @brief 시작과 끝 고정이 동작하는지. */
    fn anchors() {
        assert!(m("^ads", "ads.example.com"));
        assert!(!m("^ads", "x.ads.example.com"));
        assert!(m("com$", "example.com"));
        assert!(!m("com$", "com.example"));
        assert!(m("^example\\.com$", "example.com"));
        assert!(!m("^example\\.com$", "www.example.com"));
    }

    #[test]
    /** @brief 임의 문자와 이스케이프. */
    fn dot_and_escape() {
        assert!(m("a.c", "abc"));
        assert!(m("a.c", "axc"));
        assert!(!m("a\\.c", "abc"));
        assert!(m("a\\.c", "a.c"));
    }

    #[test]
    /** @brief 선택지와 괄호. */
    fn alternation_and_groups() {
        assert!(m("ads|trackers", "foo.trackers.net"));
        assert!(m("(ads|trk)\\.", "trk.example.com"));
        assert!(m("(?:ads|trk)\\.net", "trk.net"));
        assert!(!m("(ads|trk)\\.", "safe.example.com"));
    }

    #[test]
    /** @brief 반복 표시들. */
    fn quantifiers() {
        assert!(m("a+", "baaa"));
        assert!(m("ab*c", "ac"));
        assert!(m("ab*c", "abbbc"));
        assert!(m("ab?c", "ac"));
        assert!(m("ab?c", "abc"));
        assert!(!m("ab?c", "abbc"));
    }

    #[test]
    /** @brief 중괄호 반복 범위. */
    fn bounded_repeat() {
        assert!(m("^a{3}$", "aaa"));
        assert!(!m("^a{3}$", "aa"));
        assert!(m("^a{2,4}$", "aaa"));
        assert!(!m("^a{2,4}$", "a"));
        assert!(!m("^a{2,4}$", "aaaaa"));
        assert!(m("^a{2,}$", "aaaaa"));
        assert!(!m("^a{2,}$", "a"));
    }

    #[test]
    /** @brief 문자 집합. */
    fn char_classes() {
        assert!(m("[0-9]+", "host123"));
        assert!(m("^[a-z]+$", "abc"));
        assert!(!m("^[a-z]+$", "abc1"));
        assert!(m("[^.]+", "abc"));
        assert!(m("\\d{3}", "ad987.net"));
        assert!(m("[a-z0-9-]+\\.example", "my-host1.example"));
    }

    #[test]
    /** @brief 단어 문자와 경계. */
    fn word_class_and_boundary() {
        assert!(m("\\w+", "abc_123"));
        assert!(m("\\bads\\b", "the ads here"));
        assert!(!m("\\bads\\b", "downloads here"));
    }

    #[test]
    /** @brief 대소문자 무시 플래그. */
    fn case_insensitive_flag() {
        assert!(m("(?i)ADS", "ads.example.com"));
        assert!(m("(?i)Tracker", "x.tracker.net"));
    }

    #[test]
    /** @brief 괄호 안에서만 적용되는 플래그. */
    fn scoped_flag_group() {
        assert!(m("(?i:ADS)\\.net", "ads.net"));
        assert!(m("foo(?i:BAR)baz", "foobarbaz"));
        assert!(!m("(?i:ADS)X", "adsx"));
        assert!(m("(?i:ADS)X", "adsX"));
    }

    #[test]
    /** @brief 플래그 끄기. */
    fn negated_flag() {
        assert!(m("(?i)A(?-i:B)", "aB"));
        assert!(!m("(?i)A(?-i:B)", "ab"));
    }

    #[test]
    /** @brief 임의 문자가 개행까지 포함하는 플래그. */
    fn dotall_flag() {
        assert!(!m("a.b", "a\nb"));
        assert!(m("(?s)a.b", "a\nb"));
        assert!(m("(?s:a.b)", "a\nb"));
    }

    #[test]
    /** @brief 여러 줄 모드에서 고정 표시가 줄 단위로 걸리는지. */
    fn multiline_flag() {
        assert!(!m("^bar$", "foo\nbar\nbaz"));
        assert!(m("(?m)^bar$", "foo\nbar\nbaz"));
        assert!(m("(?m)^foo$", "foo\nbar"));
    }

    #[test]
    /** @brief 확장 모드에서 공백과 주석이 무시되는지. */
    fn extended_flag() {
        assert!(m("(?x) a b c # comment\n", "abc"));
        assert!(m("(?x:a b c)", "abc"));
        assert!(m("(?x)a \\ b", "a b"));
    }

    #[test]
    /** @brief 부정 문자 집합 안의 이스케이프. */
    fn negated_class_escapes() {
        assert!(m("^[\\D]+$", "abc-xyz"));
        assert!(!m("^[\\D]+$", "ab9"));
        assert!(m("[\\W]", "a!b"));
        assert!(!m("^[\\W]+$", "abc"));
        assert!(m("^[\\S]+$", "nowhitespace"));
        assert!(!m("[\\S]", "   "));
        assert!(m("[\\d\\D]", "x"));
    }

    #[test]
    /** @brief 플래그를 여럿 함께 켠 경우. */
    fn combined_flags() {
        assert!(m("(?is)A.B", "a\nb"));
        assert!(m("(?ims)^A.B$", "x\na\nb\ny"));
    }

    #[test]
    /** @brief 실제 차단 규칙에 쓰이는 형태의 패턴들. */
    fn realistic_domain_patterns() {
        assert!(m("^(.+\\.)?doubleclick\\.net$", "ad.doubleclick.net"));
        assert!(m("^(.+\\.)?doubleclick\\.net$", "doubleclick.net"));
        assert!(!m(
            "^(.+\\.)?doubleclick\\.net$",
            "notdoubleclick.net.evil.com"
        ));
        assert!(m("analytics?", "google-analytics.com"));
    }

    #[test]
    /** @brief 형식이 어긋난 패턴이 오류가 되는지. */
    fn invalid_patterns_error() {
        assert!(Regex::new("(unclosed").is_err());
        assert!(Regex::new("[unclosed").is_err());
        assert!(Regex::new("*nostart").is_err());
        assert!(Regex::new("a{2,1}").is_err());
        assert!(Regex::new("extra)paren").is_err());
    }

    #[test]
    /** @brief 정규식 집합에서 하나라도 맞으면 맞는 것으로 보는지. */
    fn regex_set_any_match() {
        let set = RegexSet::new(["ads", "^trk", "tracker$"]).unwrap();
        assert!(set.is_match("x.ads.com"));
        assert!(set.is_match("trk.example.com"));
        assert!(set.is_match("foo.tracker"));
        assert!(!set.is_match("safe.example.com"));
    }

    #[test]
    /** @brief 시작 고정 패턴이 중간에서 맞지 않는지. */
    fn anchored_programs_start_only_at_the_beginning() {
        let anchored = Regex::new("^(ads|tracker)[0-9]+\\.").unwrap();
        assert!(anchored.prog.start_anchored);
        assert!(anchored.is_match("ads12.example"));
        assert!(!anchored.is_match("x.ads12.example"));

        let set = RegexSet::new(["^ads", "^tracker"]).unwrap();
        assert!(set.prog.as_ref().unwrap().start_anchored);
        assert!(set.is_match("tracker.example"));
        assert!(!set.is_match("x.tracker.example"));

        let mixed = RegexSet::new(["^ads", "tracker"]).unwrap();
        assert!(!mixed.prog.as_ref().unwrap().start_anchored);
        assert!(mixed.is_match("x.tracker.example"));

        let multiline = Regex::new("(?m)^ads").unwrap();
        assert!(!multiline.prog.start_anchored);
        assert!(multiline.is_match("safe\nads"));
    }

    #[test]
    /** @brief 정규식 집합 안에 잘못된 패턴이 있으면 전체가 실패하는지. */
    fn regex_set_new_fails_on_bad_pattern() {
        assert!(RegexSet::new(["good", "(bad"]).is_err());
    }

    #[test]
    /** @brief 백트래킹 엔진이라면 지수 시간이 걸릴 패턴이 여기서는 빨리 끝나는지. */
    fn no_redos_blowup() {
        let re = Regex::new("(a+)+$").unwrap();
        let hay = "a".repeat(40) + "!";
        assert!(!re.is_match(&hay));
    }

    #[test]
    /** @brief 깊게 감싼 패턴이 스택 넘침이 아니라 오류로 끝나는지. */
    fn deeply_nested_groups_error_not_overflow() {
        let pat = "(".repeat(100_000);
        assert!(Regex::new(&pat).is_err());
        let balanced = "(".repeat(50_000) + &")".repeat(50_000);
        assert!(Regex::new(&balanced).is_err());

        let ok = "(".repeat(50) + "a" + &")".repeat(50);
        assert!(Regex::new(&ok).is_ok());
    }

    #[test]
    /** @brief 빈 패턴이 무엇에나 맞는지. */
    fn empty_pattern_matches() {
        assert!(m("", "anything"));
        assert!(m("", ""));
    }
}
