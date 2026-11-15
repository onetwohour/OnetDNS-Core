//! Regex engine that advances a set of threads together instead of backtracking, so time is linear
//! in the input length. Rules come from operators and lists; with a backtracking engine one rule
//! could take exponential time. Instruction count and nesting depth are capped too.
//!
//! Works on bytes, which is enough for domain names.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Regex error: {}", self.0)
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone)]
enum Ast {
    Empty,
    Literal(u8),
    AnyChar {
        dotall: bool,
    },

    Class {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
    Concat(Vec<Ast>),
    Alt(Vec<Ast>),
    Repeat {
        node: Box<Ast>,
        min: u32,
        max: Option<u32>,
    },
    StartAnchor {
        multiline: bool,
    },
    EndAnchor {
        multiline: bool,
    },
    WordBoundary(bool),
}

/// Expanding a large count as is would blow up the instruction count.
const MAX_REPEAT: u32 = 1000;

/// So one rule cannot use up memory.
const MAX_INSTS: usize = 200_000;

/// Deeply nested patterns would otherwise overflow the stack.
const MAX_PARSE_DEPTH: usize = 200;

#[derive(Clone, Copy)]
/// Restored on leaving the group that changed them.
struct Flags {
    ci: bool,
    dotall: bool,
    multiline: bool,
    extended: bool,
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    depth: usize,
    ci: bool,
    dotall: bool,
    multiline: bool,
    extended: bool,
}

impl<'a> Parser<'a> {
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

    fn flags(&self) -> Flags {
        Flags {
            ci: self.ci,
            dotall: self.dotall,
            multiline: self.multiline,
            extended: self.extended,
        }
    }

    fn restore(&mut self, f: Flags) {
        self.ci = f.ci;
        self.dotall = f.dotall;
        self.multiline = f.multiline;
        self.extended = f.extended;
    }

    /// In extended mode.
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

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

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

    /// Rewinds when it is not a bound.
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

    /// Checks the depth limit.
    fn parse_group(&mut self) -> Result<Ast, Error> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(Error("Regex nesting is too deep".into()));
        }
        let r = self.parse_group_inner();
        self.depth -= 1;
        r
    }

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

    fn set_flag(&mut self, c: u8, on: bool) {
        match c {
            b'i' => self.ci = on,
            b's' => self.dotall = on,
            b'm' => self.multiline = on,
            b'x' => self.extended = on,
            _ => {}
        }
    }

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

    /// Under case-insensitivity both cases go in.
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

    fn fold(&self, b: u8) -> u8 {
        if self.ci {
            b.to_ascii_lowercase()
        } else {
            b
        }
    }
}

const WORD_RANGES: [(u8, u8); 4] = [(b'0', b'9'), (b'A', b'Z'), (b'a', b'z'), (b'_', b'_')];
const SPACE_RANGES: [(u8, u8); 2] = [(b'\t', b'\r'), (b' ', b' ')];

fn is_flag_char(c: u8) -> bool {
    matches!(c, b'i' | b's' | b'm' | b'x')
}

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

fn class_from(ranges: &[(u8, u8)], negated: bool) -> Ast {
    Ast::Class {
        negated,
        ranges: ranges.to_vec(),
    }
}

#[derive(Debug, Clone)]
enum Inst {
    Byte(u8),
    Any {
        dotall: bool,
    },
    Class {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
    Match,
    Jmp(usize),
    Split(usize, usize),
    Start {
        multiline: bool,
    },
    End {
        multiline: bool,
    },
    WordBoundary(bool),
}

struct Compiler {
    insts: Vec<Inst>,
}

impl Compiler {
    fn emit(&mut self, i: Inst) -> Result<usize, Error> {
        if self.insts.len() >= MAX_INSTS {
            return Err(Error("Regex is too large".into()));
        }
        self.insts.push(i);
        Ok(self.insts.len() - 1)
    }

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

    /// Copies the node `min` times, then makes the rest optional branches. Without the repeat limit
    /// this expansion would blow up the instruction count.
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

/// Thread set with constant-time insert, lookup, and clear. It is cleared for every input byte, so
/// clearing must not cost its size.
struct SparseSet {
    gen: Vec<u32>,
    /// Clearing only bumps this.
    cur: u32,
    dense: Vec<usize>,
}

impl SparseSet {
    fn new() -> Self {
        SparseSet {
            gen: Vec::new(),
            cur: 0,
            dense: Vec::new(),
        }
    }

    fn ensure(&mut self, n: usize) {
        if self.gen.len() < n {
            self.gen.resize(n, 0);
        }
    }
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
    fn contains(&self, pc: usize) -> bool {
        self.gen[pc] == self.cur
    }
    fn insert(&mut self, pc: usize) {
        self.gen[pc] = self.cur;
        self.dense.push(pc);
    }
}

/// Reused across runs, so matching does not allocate.
struct Scratch {
    clist: SparseSet,
    nlist: SparseSet,
    stack: Vec<usize>,
}

thread_local! {
    static SCRATCH: std::cell::RefCell<Scratch> = std::cell::RefCell::new(Scratch {
        clist: SparseSet::new(),
        nlist: SparseSet::new(),
        stack: Vec::new(),
    });
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn word_boundary(input: &[u8], pos: usize) -> bool {
    let before = pos > 0 && is_word(input[pos - 1]);
    let after = pos < input.len() && is_word(input[pos]);
    before != after
}

#[derive(Debug)]
struct Prog {
    insts: Vec<Inst>,
    /// Then the run does not retry from later positions.
    start_anchored: bool,
}

impl Prog {
    /// An instruction already in the set is not added again, which is what keeps time linear.
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

    /// Advances every candidate together one byte at a time and never backtracks.
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

fn parse_pattern(pattern: &str) -> Result<Ast, Error> {
    let mut parser = Parser::new(pattern.as_bytes());
    let ast = parser.parse_alt()?;
    if parser.pos != parser.s.len() {
        return Err(Error("Unexpected character".into()));
    }
    Ok(ast)
}

fn compile_ast(ast: &Ast) -> Result<Prog, Error> {
    let mut c = Compiler { insts: Vec::new() };
    c.compile(ast)?;
    c.emit(Inst::Match)?;
    Ok(Prog {
        insts: c.insts,
        start_anchored: is_start_anchored(ast),
    })
}

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

fn compile_pattern(pattern: &str) -> Result<Prog, Error> {
    compile_ast(&parse_pattern(pattern)?)
}

#[derive(Debug)]
pub struct Regex {
    prog: Prog,
}

impl Regex {
    /// Fails on bad syntax or past the limits.
    pub fn new(pattern: &str) -> Result<Regex, Error> {
        Ok(Regex {
            prog: compile_pattern(pattern)?,
        })
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.prog.is_match(text.as_bytes())
    }
}

#[derive(Debug)]
/// Matches when any pattern matches.
pub struct RegexSet {
    prog: Option<Prog>,
}

impl RegexSet {
    /// One bad pattern fails the whole set.
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

    pub fn is_match(&self, text: &str) -> bool {
        match &self.prog {
            Some(p) => p.is_match(text.as_bytes()),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pat: &str, hay: &str) -> bool {
        Regex::new(pat).unwrap().is_match(hay)
    }

    #[test]
    fn literal_unanchored() {
        assert!(m("ads", "x.ads.example.com"));
        assert!(m("ads", "ads"));
        assert!(!m("ads", "ad.example.com"));
    }

    #[test]
    fn anchors() {
        assert!(m("^ads", "ads.example.com"));
        assert!(!m("^ads", "x.ads.example.com"));
        assert!(m("com$", "example.com"));
        assert!(!m("com$", "com.example"));
        assert!(m("^example\\.com$", "example.com"));
        assert!(!m("^example\\.com$", "www.example.com"));
    }

    #[test]
    fn dot_and_escape() {
        assert!(m("a.c", "abc"));
        assert!(m("a.c", "axc"));
        assert!(!m("a\\.c", "abc"));
        assert!(m("a\\.c", "a.c"));
    }

    #[test]
    fn alternation_and_groups() {
        assert!(m("ads|trackers", "foo.trackers.net"));
        assert!(m("(ads|trk)\\.", "trk.example.com"));
        assert!(m("(?:ads|trk)\\.net", "trk.net"));
        assert!(!m("(ads|trk)\\.", "safe.example.com"));
    }

    #[test]
    fn quantifiers() {
        assert!(m("a+", "baaa"));
        assert!(m("ab*c", "ac"));
        assert!(m("ab*c", "abbbc"));
        assert!(m("ab?c", "ac"));
        assert!(m("ab?c", "abc"));
        assert!(!m("ab?c", "abbc"));
    }

    #[test]
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
    fn char_classes() {
        assert!(m("[0-9]+", "host123"));
        assert!(m("^[a-z]+$", "abc"));
        assert!(!m("^[a-z]+$", "abc1"));
        assert!(m("[^.]+", "abc"));
        assert!(m("\\d{3}", "ad987.net"));
        assert!(m("[a-z0-9-]+\\.example", "my-host1.example"));
    }

    #[test]
    fn word_class_and_boundary() {
        assert!(m("\\w+", "abc_123"));
        assert!(m("\\bads\\b", "the ads here"));
        assert!(!m("\\bads\\b", "downloads here"));
    }

    #[test]
    fn case_insensitive_flag() {
        assert!(m("(?i)ADS", "ads.example.com"));
        assert!(m("(?i)Tracker", "x.tracker.net"));
    }

    #[test]
    fn scoped_flag_group() {
        assert!(m("(?i:ADS)\\.net", "ads.net"));
        assert!(m("foo(?i:BAR)baz", "foobarbaz"));
        assert!(!m("(?i:ADS)X", "adsx"));
        assert!(m("(?i:ADS)X", "adsX"));
    }

    #[test]
    fn negated_flag() {
        assert!(m("(?i)A(?-i:B)", "aB"));
        assert!(!m("(?i)A(?-i:B)", "ab"));
    }

    #[test]
    fn dotall_flag() {
        assert!(!m("a.b", "a\nb"));
        assert!(m("(?s)a.b", "a\nb"));
        assert!(m("(?s:a.b)", "a\nb"));
    }

    #[test]
    fn multiline_flag() {
        assert!(!m("^bar$", "foo\nbar\nbaz"));
        assert!(m("(?m)^bar$", "foo\nbar\nbaz"));
        assert!(m("(?m)^foo$", "foo\nbar"));
    }

    #[test]
    fn extended_flag() {
        assert!(m("(?x) a b c # comment\n", "abc"));
        assert!(m("(?x:a b c)", "abc"));
        assert!(m("(?x)a \\ b", "a b"));
    }

    #[test]
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
    fn combined_flags() {
        assert!(m("(?is)A.B", "a\nb"));
        assert!(m("(?ims)^A.B$", "x\na\nb\ny"));
    }

    #[test]
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
    fn invalid_patterns_error() {
        assert!(Regex::new("(unclosed").is_err());
        assert!(Regex::new("[unclosed").is_err());
        assert!(Regex::new("*nostart").is_err());
        assert!(Regex::new("a{2,1}").is_err());
        assert!(Regex::new("extra)paren").is_err());
    }

    #[test]
    fn regex_set_any_match() {
        let set = RegexSet::new(["ads", "^trk", "tracker$"]).unwrap();
        assert!(set.is_match("x.ads.com"));
        assert!(set.is_match("trk.example.com"));
        assert!(set.is_match("foo.tracker"));
        assert!(!set.is_match("safe.example.com"));
    }

    #[test]
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
    fn regex_set_new_fails_on_bad_pattern() {
        assert!(RegexSet::new(["good", "(bad"]).is_err());
    }

    #[test]
    /// A pattern that takes exponential time in a backtracking engine.
    fn no_redos_blowup() {
        let re = Regex::new("(a+)+$").unwrap();
        let hay = "a".repeat(40) + "!";
        assert!(!re.is_match(&hay));
    }

    #[test]
    fn deeply_nested_groups_error_not_overflow() {
        let pat = "(".repeat(100_000);
        assert!(Regex::new(&pat).is_err());
        let balanced = "(".repeat(50_000) + &")".repeat(50_000);
        assert!(Regex::new(&balanced).is_err());

        let ok = "(".repeat(50) + "a" + &")".repeat(50);
        assert!(Regex::new(&ok).is_ok());
    }

    #[test]
    fn empty_pattern_matches() {
        assert!(m("", "anything"));
        assert!(m("", ""));
    }
}
