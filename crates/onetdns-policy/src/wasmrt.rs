/*!
 * @brief WASM 인터프리터.
 *
 * @details 정책 플러그인을 격리해 실행하려고 만들었다. JIT이 아니라 트리 순회 방식이라
 *          실행 가능 메모리를 만들지 않는다. 신뢰할 수 없는 코드를 돌리는 데 그 편이 안전하다.
 * @warning 전체가 신뢰할 수 없는 입력을 다룬다. 파싱 단계의 모든 상한은 방어 장치이며,
 *          느슨하게 풀면 짧은 모듈 하나로 메모리나 스택을 고갈시킬 수 있다.
 */

use std::collections::HashMap;

/** @brief WASM 선형 메모리 한 페이지의 크기. 명세가 정한 값이다. */
const PAGE: usize = 65536;

/** @brief 모듈 바이트열 크기 상한. */
const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;

/** @brief 함수 형식 개수 상한. */
const MAX_TYPES: u32 = 16_384;

/** @brief 함수 개수 상한. */
const MAX_FUNCTIONS: u32 = 65_536;

/** @brief 함수 하나의 매개변수 개수 상한. */
const MAX_PARAMS: u32 = 1_024;

/** @brief 자체 실행기가 지원하는 함수 반환값 개수. */
const MAX_RESULTS: u32 = 1;

/** @brief 테이블 원소 수 상한. */
const MAX_TABLE_ELEMS: u32 = 65_536;

/** @brief 전역 변수 개수 상한. */
const MAX_GLOBALS: u32 = 65_536;

/** @brief 데이터 세그먼트 총 바이트 상한. */
const MAX_DATA_BYTES: usize = 16 * 1024 * 1024;

/** @brief 데이터 세그먼트 개수 상한. 빈 조각으로 파서 시간을 늘리지 못하게 한다. */
const MAX_DATA_SEGMENTS: u32 = 4_096;

/** @brief 내보내기 항목 수 상한. 이름 HashMap의 호스트 메모리를 묶는다. */
const MAX_EXPORTS: u32 = 4_096;

/** @brief 모듈 전체의 디코딩된 명령 수 상한. 작은 opcode의 enum 팽창을 묶는다. */
const MAX_DECODED_INSTRUCTIONS: usize = 262_144;

/**
 * @brief 호출 깊이 상한.
 * @warning 인터프리터가 재귀라 이 값이 곧 호스트 스택 넘침 방어다. 게스트의 무한 재귀가
 *          연료보다 먼저 스택을 밀어내는 것을 막는다.
 */
const MAX_CALL_DEPTH: usize = 128;

/** @brief 함수 하나의 지역 변수 개수 상한. */
const MAX_LOCALS_PER_FUNCTION: usize = 1_024;

/** @brief 함수 프레임 하나의 실행 값 스택 상한. */
const MAX_VALUE_STACK: usize = 4_096;

/** @brief 함수 프레임 하나의 중첩 제어 라벨 상한. */
const MAX_LABEL_STACK: usize = 1_024;

/** @brief WASM 값. */
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /** @brief 32비트 정수. */
    I32(i32),
    /** @brief 64비트 정수. */
    I64(i64),
    /** @brief 32비트 실수. */
    F32(f32),
    /** @brief 64비트 실수. */
    F64(f64),
}

impl Value {
    /** @brief 이 값의 WASM 형식. 로드·호출 경계의 형식 검증에 쓴다. */
    fn value_type(self) -> ValType {
        match self {
            Value::I32(_) => ValType::I32,
            Value::I64(_) => ValType::I64,
            Value::F32(_) => ValType::F32,
            Value::F64(_) => ValType::F64,
        }
    }

    /** @brief i32로 꺼낸다. 다른 형식이면 오류다. */
    fn as_i32(self) -> Result<i32, String> {
        match self {
            Value::I32(v) => Ok(v),
            _ => Err("Invalid WASM value type; expected a 32-bit integer".into()),
        }
    }
    /** @brief i64로 꺼낸다. 다른 형식이면 오류다. */
    fn as_i64(self) -> Result<i64, String> {
        match self {
            Value::I64(v) => Ok(v),
            _ => Err("Invalid WASM value type; expected a 64-bit integer".into()),
        }
    }
}

/** @brief WASM 값 형식. ABI 검사에서 함수 서명을 대조하는 데 쓴다. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    /** @brief 32비트 정수. */
    I32,
    /** @brief 64비트 정수. */
    I64,
    /** @brief 32비트 실수. */
    F32,
    /** @brief 64비트 실수. */
    F64,
}

/** @brief 형식 바이트를 해석한다. 참조 형식 등 지원하지 않는 값은 거부한다. */
fn val_type(b: u8) -> Result<ValType, String> {
    match b {
        0x7f => Ok(ValType::I32),
        0x7e => Ok(ValType::I64),
        0x7d => Ok(ValType::F32),
        0x7c => Ok(ValType::F64),
        other => Err(format!("Unknown valtype 0x{other:02x}")),
    }
}

/** @brief 형식의 0값. 지역 변수 초기화에 쓴다. */
fn default_val(t: ValType) -> Value {
    match t {
        ValType::I32 => Value::I32(0),
        ValType::I64 => Value::I64(0),
        ValType::F32 => Value::F32(0.0),
        ValType::F64 => Value::F64(0.0),
    }
}

/** @brief 함수 서명. */
#[derive(Debug)]
struct FuncType {
    /** @brief 받는 값들의 형. */
    params: Vec<ValType>,
    /** @brief 돌려주는 값들의 형. */
    results: Vec<ValType>,
}

/**
 * @brief 디코딩된 명령.
 * @details 블록·루프·분기의 목표 위치를 파싱 시점에 미리 풀어 둔다. 실행 중에 매번
 *          짝을 찾아 훑으면 중첩이 깊은 코드에서 비용이 급격히 커진다.
 */
#[derive(Debug, Clone)]
enum Instr {
    /** @brief 여기 닿으면 덫에 걸린다. */
    Unreachable,
    /** @brief 아무것도 하지 않는다. */
    Nop,
    /** @brief 블록을 연다. */
    Block { arity: u32, end: usize },
    /** @brief 반복할 블록(loop)을 연다. */
    Loop { arity: u32, end: usize },
    /** @brief 조건이 참일 때의 블록. */
    If {
        /** @brief 이 블록이 남길 값의 수. */
        arity: u32,
        /** @brief 거짓일 때 뛸 곳. */
        else_: usize,
        /** @brief 이 블록이 끝나는 위치. */
        end: usize,
    },
    /** @brief 거짓일 때의 블록. */
    Else { end: usize },
    /** @brief 블록을 닫는다. */
    End,
    /** @brief 이만큼 바깥 블록으로 빠져나간다. */
    Br(u32),
    /** @brief 조건이 참이면 빠져나간다. */
    BrIf(u32),
    /** @brief 테이블에서 골라 빠져나간다. */
    BrTable(Vec<u32>, u32),
    /** @brief 함수에서 돌아간다. */
    Return,
    /** @brief 함수를 부른다. */
    Call(u32),
    /** @brief 테이블을 거쳐 함수를 부른다. */
    CallIndirect(u32),
    /** @brief 값 하나를 버린다. */
    Drop,
    /** @brief 조건에 따라 둘 중 하나를 고른다. */
    Select,
    /** @brief 지역 변수를 읽는다. */
    LocalGet(u32),
    /** @brief 지역 변수에 쓴다. */
    LocalSet(u32),
    /** @brief 지역 변수에 쓰면서 값도 남긴다. */
    LocalTee(u32),
    /** @brief 전역 변수를 읽는다. */
    GlobalGet(u32),
    /** @brief 전역 변수에 쓴다. */
    GlobalSet(u32),
    /** @brief 메모리에서 읽는다. */
    Load { op: u8, offset: u32 },
    /** @brief 메모리에 쓴다. */
    Store { op: u8, offset: u32 },
    /** @brief 메모리 크기를 묻는다. */
    MemSize,
    /** @brief 메모리를 늘린다. */
    MemGrow,
    /** @brief 32비트 정수 상수. */
    I32Const(i32),
    /** @brief 64비트 정수 상수. */
    I64Const(i64),
    /** @brief 32비트 실수 상수. */
    F32Const(f32),
    /** @brief 64비트 실수 상수. */
    F64Const(f64),
    /** @brief 값 계산 명령. 번호가 어느 연산인지 구분한다. */
    Num(u8),
}

/** @brief 모듈 바이트열을 훑는 커서. */
struct Reader<'a> {
    /** @brief 읽어 들일 바이트. */
    b: &'a [u8],
    /** @brief 지금 위치. */
    pos: usize,
}

impl<'a> Reader<'a> {
    /** @brief 커서를 만든다. */
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    /** @brief 끝까지 읽었는지. */
    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
    /** @brief 1바이트를 읽는다. */
    fn byte(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.pos).ok_or("EOF")?;
        self.pos += 1;
        Ok(v)
    }
    /** @brief n바이트를 빌린다. 범위를 넘으면 오류다. */
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or("WASM byte range overflowed")?;
        let s = self.b.get(self.pos..end).ok_or("EOF")?;
        self.pos = end;
        Ok(s)
    }
    /**
     * @brief LEB128 부호 없는 32비트를 읽는다.
     * @warning 시프트 폭을 제한한다. 0x80이 계속 이어지는 입력이 무한 루프가 되지 않게 막는다.
     */
    fn u32(&mut self) -> Result<u32, String> {
        let mut r = 0u32;
        let mut shift = 0;
        loop {
            let b = self.byte()?;
            r |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                return Ok(r);
            }
            shift += 7;
            if shift >= 35 {
                return Err("LEB128 u32 value is out of range".into());
            }
        }
    }
    /** @brief LEB128 부호 있는 32비트를 읽는다. */
    fn i32(&mut self) -> Result<i32, String> {
        Ok(self.i64()? as i32)
    }
    /** @brief LEB128 부호 있는 64비트를 읽는다. 마지막 바이트의 부호 비트를 확장한다. */
    fn i64(&mut self) -> Result<i64, String> {
        let mut r = 0i64;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            r |= ((b & 0x7f) as i64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && (b & 0x40) != 0 {
                    r |= -1i64 << shift;
                }
                return Ok(r);
            }
            if shift >= 70 {
                return Err("LEB128 i64 value is out of range".into());
            }
        }
    }
    /** @brief 32비트 실수 하나를 읽는다. */
    fn f32(&mut self) -> Result<f32, String> {
        let b = self.bytes(4)?;
        Ok(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /** @brief 64비트 실수 하나를 읽는다. */
    fn f64(&mut self) -> Result<f64, String> {
        let b = self.bytes(8)?;
        Ok(f64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    /** @brief 길이 접두사가 붙은 UTF-8 이름을 읽는다. */
    fn name(&mut self) -> Result<String, String> {
        let n = self.u32()? as usize;
        let s = self.bytes(n)?;
        String::from_utf8(s.to_vec()).map_err(|_| "Non-UTF-8 name".into())
    }
}

/** @brief 디코딩된 함수: 서명 인덱스, 지역 변수 형식, 명령열. */
struct Func {
    /** @brief 이 함수의 형. */
    type_idx: u32,
    /** @brief 지역 변수들의 형. */
    locals: Vec<ValType>,
    /** @brief 이 함수의 명령들. */
    body: Vec<Instr>,
}

/** @brief 내보내기 종류. */
#[derive(Clone, Copy)]
enum ExportKind {
    /** @brief 함수. */
    Func,
    /** @brief 메모리. */
    Memory,
    /** @brief 전역 변수. */
    Global,
    /** @brief 함수 테이블. */
    Table,
}

/**
 * @brief 파싱된 WASM 모듈. 인스턴스와 달리 불변이며 여러 호출이 공유한다.
 * @details 모듈을 한 번만 파싱해 두는 것이 호출당 비용을 결정한다. 인스턴스는 메모리와
 *          전역만 새로 잡는다.
 */
pub struct Module {
    /** @brief 이 플러그인에 쓰인 함수 형들. */
    types: Vec<FuncType>,
    /** @brief 이 플러그인이 담은 함수들. */
    funcs: Vec<Func>,
    /** @brief 함수마다의 형 번호. */
    func_types: Vec<u32>,
    /** @brief 밖에 내놓은 이름들. */
    exports: HashMap<String, (ExportKind, u32)>,
    /** @brief 처음 잡을 메모리 쪽 수. */
    mem_min: u32,
    /** @brief 늘릴 수 있는 최대 쪽 수. */
    mem_max: Option<u32>,
    /** @brief 모듈 안에 선형 메모리 0번이 실제로 정의됐는지. */
    memory_defined: bool,
    /** @brief 전역 변수들의 형, 고칠 수 있는지, 처음 값. */
    globals: Vec<(ValType, bool, Value)>,
    /** @brief 올리자마자 부를 함수. */
    start: Option<u32>,
    /** @brief 테이블을 거쳐 부를 함수들. */
    table: Vec<Option<u32>>,
    /** @brief 모듈 안에 함수 테이블 0번이 실제로 정의됐는지. */
    table_defined: bool,
    /** @brief 메모리에 미리 채워 둘 자료. */
    data: Vec<(u32, Vec<u8>)>,
}

impl Module {
    /** @brief 이 이름의 내보내기가 있는지. 종류는 보지 않는다. */
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.contains_key(name)
    }

    /** @brief 이 이름으로 메모리 0번을 내보내는지. 호스트가 문맥을 쓸 대상이다. */
    pub fn has_memory_export(&self, name: &str) -> bool {
        self.memory_defined && matches!(self.exports.get(name), Some((ExportKind::Memory, 0)))
    }

    /**
     * @brief 내보낸 함수의 서명을 돌려준다.
     * @details 로드 시점 ABI 검사가 이걸 쓴다. 함수 인덱스는 가져오기 개수를 뺀 뒤 지역
     *          정의 배열을 가리킨다. 이 보정을 빼먹으면 엉뚱한 함수의 서명을 본다.
     * @return 함수가 아니거나 인덱스가 범위를 벗어나면 None.
     */
    pub fn func_export_signature(&self, name: &str) -> Option<(&[ValType], &[ValType])> {
        let idx = match self.exports.get(name)? {
            (ExportKind::Func, idx) => *idx,
            _ => return None,
        };
        let func = self.funcs.get(idx as usize)?;
        let ftype = self.types.get(func.type_idx as usize)?;
        Some((&ftype.params, &ftype.results))
    }

    /**
     * @brief WASM 바이너리를 파싱한다.
     * @details 매직과 버전을 먼저 확인하고 섹션을 순서대로 읽는다. 각 섹션은 자기 개수
     *          상한을 검사한다. 개수를 그대로 믿고 미리 할당하면 몇 바이트짜리 모듈이
     *          거대한 벡터를 만든다.
     * @return 신뢰할 수 없는 입력이므로 어떤 형태로 깨져 있어도 패닉하지 않고 오류를 돌려준다.
     */
    pub fn parse(bytes: &[u8]) -> Result<Module, String> {
        if bytes.len() > MAX_MODULE_BYTES {
            return Err("WASM module is too large".into());
        }
        let mut r = Reader::new(bytes);
        if r.bytes(4)? != b"\0asm" {
            return Err("WASM magic does not match".into());
        }
        if r.bytes(4)? != [1, 0, 0, 0] {
            return Err("WASM version != 1".into());
        }
        let mut m = Module {
            types: Vec::new(),
            funcs: Vec::new(),
            func_types: Vec::new(),
            exports: HashMap::new(),
            mem_min: 0,
            mem_max: None,
            memory_defined: false,
            globals: Vec::new(),
            start: None,
            table: Vec::new(),
            table_defined: false,
            data: Vec::new(),
        };
        let mut code_bodies: Vec<&[u8]> = Vec::new();
        let mut last_standard_section = 0u8;
        while !r.done() {
            let id = r.byte()?;
            let size = usize::try_from(r.u32()?).map_err(|_| "Section size overflowed")?;
            let payload = r.bytes(size)?;
            if id == 0 {
                continue;
            }
            if !(1..=11).contains(&id) {
                return Err(format!("Unsupported WASM section ID {id}"));
            }
            if id <= last_standard_section {
                return Err("WASM standard section is duplicated or out of order".into());
            }
            last_standard_section = id;
            let mut s = Reader::new(payload);
            match id {
                1 => m.parse_types(&mut s)?,
                2 => m.parse_imports(&mut s)?,
                3 => {
                    let n = s.u32()?;
                    if n > MAX_FUNCTIONS {
                        return Err("Too many functions".into());
                    }
                    for _ in 0..n {
                        m.func_types.push(s.u32()?);
                    }
                }
                4 => m.parse_tables(&mut s)?,
                5 => m.parse_memory(&mut s)?,
                6 => m.parse_globals(&mut s)?,
                7 => m.parse_exports(&mut s)?,
                8 => m.start = Some(s.u32()?),
                9 => m.parse_elements(&mut s)?,
                10 => {
                    let n = s.u32()?;
                    if n > MAX_FUNCTIONS {
                        return Err("Too many WASM code bodies".into());
                    }
                    for _ in 0..n {
                        let csize =
                            usize::try_from(s.u32()?).map_err(|_| "Code size overflowed")?;
                        code_bodies.push(s.bytes(csize)?);
                    }
                }
                11 => m.parse_data(&mut s)?,
                _ => unreachable!("Standard section range was checked above"),
            }
            if !s.done() {
                return Err(format!("WASM section {id} has unparsed trailing bytes"));
            }
        }

        if code_bodies.len() != m.func_types.len() {
            return Err("code and function section counts do not match".into());
        }
        let mut decoded_instructions = 0usize;
        for (i, body) in code_bodies.iter().enumerate() {
            let type_idx = m.func_types[i];
            let ft = m
                .types
                .get(type_idx as usize)
                .ok_or("WASM function references a type that does not exist")?;
            let nparams = ft.params.len();
            let instruction_budget = MAX_DECODED_INSTRUCTIONS
                .checked_sub(decoded_instructions)
                .ok_or("Too many decoded WASM instructions")?;
            let (locals, instrs) = decode_function(body, nparams, instruction_budget)?;
            decoded_instructions = decoded_instructions
                .checked_add(instrs.len())
                .ok_or("WASM instruction count overflowed")?;
            if decoded_instructions > MAX_DECODED_INSTRUCTIONS {
                return Err("Too many decoded WASM instructions".into());
            }
            m.funcs.push(Func {
                type_idx,
                locals,
                body: instrs,
            });
        }
        m.validate_semantics()?;
        Ok(m)
    }

    /** @brief 디코딩된 인덱스와 정의가 런타임이 지원하는 모듈 의미에 맞는지 검사한다. */
    fn validate_semantics(&self) -> Result<(), String> {
        for (kind, idx) in self.exports.values() {
            let valid = match kind {
                ExportKind::Func => (*idx as usize) < self.funcs.len(),
                ExportKind::Table => *idx == 0 && self.table_defined,
                ExportKind::Memory => *idx == 0 && self.memory_defined,
                ExportKind::Global => (*idx as usize) < self.globals.len(),
            };
            if !valid {
                return Err("WASM export references a definition that does not exist".into());
            }
        }

        if let Some(start) = self.start {
            let func = self
                .funcs
                .get(start as usize)
                .ok_or("WASM start function index is out of range")?;
            let ty = self
                .types
                .get(func.type_idx as usize)
                .ok_or("WASM start function type index is out of range")?;
            if !ty.params.is_empty() || !ty.results.is_empty() {
                return Err(
                    "WASM start function must take no parameters and return nothing".into(),
                );
            }
        }

        for function in self.table.iter().flatten() {
            if (*function as usize) >= self.funcs.len() {
                return Err("WASM table references a function that does not exist".into());
            }
        }

        for func in &self.funcs {
            let params = self
                .types
                .get(func.type_idx as usize)
                .ok_or("WASM function type index is out of range")?
                .params
                .len();
            let local_count = params
                .checked_add(func.locals.len())
                .ok_or("WASM local index range overflowed")?;
            for instr in &func.body {
                match instr {
                    Instr::Call(idx) if (*idx as usize) >= self.funcs.len() => {
                        return Err("WASM call function index is out of range".into());
                    }
                    Instr::CallIndirect(type_idx) => {
                        if !self.table_defined {
                            return Err("WASM call_indirect needs a table".into());
                        }
                        if (*type_idx as usize) >= self.types.len() {
                            return Err("WASM call_indirect type index is out of range".into());
                        }
                    }
                    Instr::LocalGet(idx) | Instr::LocalSet(idx) | Instr::LocalTee(idx)
                        if (*idx as usize) >= local_count =>
                    {
                        return Err("WASM local index is out of range".into());
                    }
                    Instr::GlobalGet(idx) if (*idx as usize) >= self.globals.len() => {
                        return Err("WASM global index is out of range".into());
                    }
                    Instr::GlobalSet(idx) => match self.globals.get(*idx as usize) {
                        Some((_, true, _)) => {}
                        Some((_, false, _)) => {
                            return Err("Cannot modify an immutable WASM global".into());
                        }
                        None => {
                            return Err("WASM global index is out of range".into());
                        }
                    },
                    Instr::Load { .. } | Instr::Store { .. } | Instr::MemSize | Instr::MemGrow
                        if !self.memory_defined =>
                    {
                        return Err("WASM memory instruction needs a memory".into());
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /** @brief 타입 섹션. 함수 서명 목록이다. */
    fn parse_types(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n > MAX_TYPES {
            return Err("Too many types".into());
        }
        for _ in 0..n {
            if s.byte()? != 0x60 {
                return Err("Invalid functype".into());
            }
            let np = s.u32()?;
            if np > MAX_PARAMS {
                return Err("Too many function parameters".into());
            }
            let mut params = Vec::with_capacity(np as usize);
            for _ in 0..np {
                params.push(val_type(s.byte()?)?);
            }
            let nr = s.u32()?;
            if nr > MAX_RESULTS {
                return Err("Functions support at most one result".into());
            }
            let mut results = Vec::with_capacity(nr as usize);
            for _ in 0..nr {
                results.push(val_type(s.byte()?)?);
            }
            self.types.push(FuncType { params, results });
        }
        Ok(())
    }

    /**
     * @brief 가져오기 섹션.
     * @note 호스트 기능을 하나도 노출하지 않으므로 빈 섹션 외에는 전부 거부한다.
     */
    fn parse_imports(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n != 0 {
            return Err("WASM imports are not supported".into());
        }
        Ok(())
    }

    /** @brief 테이블 섹션. call_indirect의 대상 표다. */
    fn parse_tables(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n > 1 {
            return Err("Only one table is supported".into());
        }
        for _ in 0..n {
            if s.byte()? != 0x70 {
                return Err("WASM table element type must be funcref".into());
            }
            let (min, max) = read_limits(s)?;
            if min > MAX_TABLE_ELEMS || max.is_some_and(|value| value > MAX_TABLE_ELEMS) {
                return Err("WASM table is too large".into());
            }
            self.table = vec![None; min as usize];
            self.table_defined = true;
        }
        Ok(())
    }

    /** @brief 메모리 섹션. 선형 메모리 하나만 허용한다. */
    fn parse_memory(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n > 1 {
            return Err("Only one memory is supported".into());
        }
        if n > 0 {
            let (min, max) = read_limits(s)?;
            if max.is_some_and(|value| value < min) {
                return Err("WASM maximum memory is smaller than the minimum".into());
            }
            self.mem_min = min;
            self.mem_max = max;
            self.memory_defined = true;
        }
        Ok(())
    }

    /** @brief 전역 섹션. 형식·가변성·초기값을 읽는다. */
    fn parse_globals(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n > MAX_GLOBALS {
            return Err("Too many globals".into());
        }
        for _ in 0..n {
            let vt = val_type(s.byte()?)?;
            let mutable = match s.byte()? {
                0 => false,
                1 => true,
                _ => return Err("Invalid WASM global mutability".into()),
            };
            let v = eval_const_expr(s, vt)?;
            self.globals.push((vt, mutable, v));
        }
        Ok(())
    }

    /** @brief 내보내기 섹션. 호스트가 부를 수 있는 이름 테이블을 만든다. */
    fn parse_exports(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n > MAX_EXPORTS {
            return Err("Too many exports".into());
        }
        for _ in 0..n {
            let name = s.name()?;
            let kind = s.byte()?;
            let idx = s.u32()?;
            let k = match kind {
                0x00 => ExportKind::Func,
                0x01 => ExportKind::Table,
                0x02 => ExportKind::Memory,
                0x03 => ExportKind::Global,
                _ => return Err("Unknown export kind".into()),
            };
            if self.exports.insert(name, (k, idx)).is_some() {
                return Err("Duplicate WASM export name".into());
            }
        }
        Ok(())
    }

    /** @brief 원소 섹션. 테이블 항목을 함수 인덱스로 채운다. */
    fn parse_elements(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n > MAX_TABLE_ELEMS {
            return Err("Too many element segments".into());
        }
        if n != 0 && !self.table_defined {
            return Err("WASM element segment needs a table".into());
        }
        for _ in 0..n {
            let flags = s.u32()?;
            if flags != 0 {
                return Err("Unsupported element segment form".into());
            }
            let offset = eval_const_expr(s, ValType::I32)?.as_i32()?;
            if offset < 0 {
                return Err("WASM element segment offset is negative".into());
            }
            let off = offset as usize;
            let cnt = usize::try_from(s.u32()?).map_err(|_| "Element count overflowed")?;
            let end = off.checked_add(cnt).ok_or("Element range overflowed")?;
            if end > self.table.len() {
                return Err("Element segment exceeds the table".into());
            }
            for slot in &mut self.table[off..end] {
                *slot = Some(s.u32()?);
            }
        }
        Ok(())
    }

    /**
     * @brief 데이터 섹션. 인스턴스 생성 시 메모리에 로드할 조각이다.
     * @note 누적 바이트 상한을 검사한다. 세그먼트를 잘게 쪼개 상한을 우회하지 못하게 한다.
     */
    fn parse_data(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n > MAX_DATA_SEGMENTS {
            return Err("Too many data segments".into());
        }
        if n != 0 && !self.memory_defined {
            return Err("WASM data segment needs a memory".into());
        }
        let mut total = self
            .data
            .iter()
            .map(|(_, bytes)| bytes.len())
            .sum::<usize>();
        for _ in 0..n {
            let flags = s.u32()?;
            if flags != 0 {
                return Err("Unsupported data segment form".into());
            }
            let offset = eval_const_expr(s, ValType::I32)?.as_i32()?;
            if offset < 0 {
                return Err("WASM data segment offset is negative".into());
            }
            let len = usize::try_from(s.u32()?).map_err(|_| "Data length overflowed")?;
            total = total.checked_add(len).ok_or("Total data size overflowed")?;
            if total > MAX_DATA_BYTES {
                return Err("Data segments are too large in total".into());
            }
            let bytes = s.bytes(len)?.to_vec();
            self.data.push((offset as u32, bytes));
        }
        Ok(())
    }
}

/** @brief 메모리·테이블의 최소/최대 한계를 읽는다. */
fn read_limits(s: &mut Reader) -> Result<(u32, Option<u32>), String> {
    let flag = s.byte()?;
    if flag > 1 {
        return Err("Invalid WASM limits flag".into());
    }
    let min = s.u32()?;
    let max = if flag == 1 { Some(s.u32()?) } else { None };
    if max.is_some_and(|value| value < min) {
        return Err("WASM maximum limit is smaller than the minimum".into());
    }
    Ok((min, max))
}

/**
 * @brief 상수 식을 평가한다. 전역 초기값과 세그먼트 오프셋에 쓴다.
 * @note 리터럴만 받는다. 다른 전역을 참조하는 형태는 거부한다. 초기화 순서에 의존하는
 *       모듈을 받아들이지 않는 편이 단순하고 안전하다.
 */
fn eval_const_expr(s: &mut Reader, expected: ValType) -> Result<Value, String> {
    let op = s.byte()?;
    let v = match op {
        0x41 => Value::I32(s.i32()?),
        0x42 => Value::I64(s.i64()?),
        0x43 => Value::F32(s.f32()?),
        0x44 => Value::F64(s.f64()?),
        0x23 => {
            let _g = s.u32()?;
            return Err("Global-reference const expr is not supported".into());
        }
        other => return Err(format!("Const expr opcode 0x{other:02x} is not supported")),
    };
    if s.byte()? != 0x0b {
        return Err("Const expr is missing its end".into());
    }
    if v.value_type() != expected {
        return Err("WASM const expr result type does not match its declaration".into());
    }
    Ok(v)
}

/**
 * @brief 블록 타입에서 결과 개수를 읽는다.
 * @note 다중값 블록과 타입 인덱스 블록은 지원하지 않는다. 플러그인 ABI가 요구하지 않고,
 *       지원하지 않는 형태를 조용히 통과시키면 실행 중에 스택이 어긋난다.
 */
fn blocktype_arity(s: &mut Reader) -> Result<u32, String> {
    let b = s.byte()?;
    match b {
        0x40 => Ok(0),
        0x7c..=0x7f => Ok(1),
        _ => Err("Multi-value and type-index block types are not supported".into()),
    }
}

/**
 * @brief 함수 본문을 명령열로 디코딩한다.
 * @details 제어 명령의 짝(end/else) 위치를 여기서 찾아 명령 안에 고정해 둔다. 실행 중에
 *          짝을 찾아 훑지 않아도 되므로 중첩이 깊어도 분기 비용이 일정하다.
 * @param nparams 매개변수 개수. 지역 변수 총량 상한 검사에 함께 들어간다.
 * @param instruction_budget 이 함수가 디코딩할 수 있는 남은 모듈 명령 수.
 */
fn decode_function(
    body: &[u8],
    nparams: usize,
    instruction_budget: usize,
) -> Result<(Vec<ValType>, Vec<Instr>), String> {
    let mut s = Reader::new(body);
    let nlocal_decl = s.u32()?;
    if nlocal_decl as usize > MAX_LOCALS_PER_FUNCTION {
        return Err("Too many WASM local declarations".into());
    }
    let mut locals = Vec::new();
    for _ in 0..nlocal_decl {
        let count = usize::try_from(s.u32()?).map_err(|_| "WASM local count overflowed")?;
        let vt = val_type(s.byte()?)?;
        let total = locals
            .len()
            .checked_add(count)
            .ok_or("WASM local count overflowed")?;
        if total > MAX_LOCALS_PER_FUNCTION
            || total.saturating_add(nparams) > MAX_LOCALS_PER_FUNCTION
        {
            return Err("Too many function locals".into());
        }
        locals.resize(total, vt);
    }
    let mut instrs: Vec<Instr> = Vec::new();

    let mut ctrl: Vec<(usize, u8)> = Vec::new();
    let mut function_ended = false;
    while !s.done() {
        let op = s.byte()?;
        match op {
            0x00 => instrs.push(Instr::Unreachable),
            0x01 => instrs.push(Instr::Nop),
            0x02 => {
                let arity = blocktype_arity(&mut s)?;
                ctrl.push((instrs.len(), 0));
                instrs.push(Instr::Block { arity, end: 0 });
            }
            0x03 => {
                let arity = blocktype_arity(&mut s)?;
                ctrl.push((instrs.len(), 1));
                instrs.push(Instr::Loop { arity, end: 0 });
            }
            0x04 => {
                let arity = blocktype_arity(&mut s)?;
                ctrl.push((instrs.len(), 2));
                instrs.push(Instr::If {
                    arity,
                    else_: 0,
                    end: 0,
                });
            }
            0x05 => {
                let (if_idx, kind) = ctrl.last_mut().ok_or("else without if")?;
                if *kind != 2 {
                    return Err("WASM else has no matching if block".into());
                }
                *kind = 3;
                let if_idx = *if_idx;
                let here = instrs.len();
                if let Instr::If { else_, .. } = &mut instrs[if_idx] {
                    *else_ = here;
                }
                instrs.push(Instr::Else { end: 0 });
            }
            0x0b => {
                if let Some((idx, kind)) = ctrl.pop() {
                    let here = instrs.len();
                    match kind {
                        0 => {
                            if let Instr::Block { end, .. } = &mut instrs[idx] {
                                *end = here;
                            }
                        }
                        1 => {
                            if let Instr::Loop { end, .. } = &mut instrs[idx] {
                                *end = here;
                            }
                        }
                        2 | 3 => {
                            if let Instr::If { else_, end, .. } = &mut instrs[idx] {
                                *end = here;

                                if *else_ == 0 {
                                    *else_ = here;
                                }
                            }

                            for instr in instrs[idx + 1..here].iter_mut() {
                                if let Instr::Else { end } = instr {
                                    if *end == 0 {
                                        *end = here;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    instrs.push(Instr::End);
                } else {
                    instrs.push(Instr::End);
                    function_ended = true;
                    break;
                }
            }
            0x0c => instrs.push(Instr::Br(s.u32()?)),
            0x0d => instrs.push(Instr::BrIf(s.u32()?)),
            0x0e => {
                let cnt = s.u32()? as usize;

                /** @brief 분기 테이블에 담을 수 있는 대상 수. 없으면 짧은 플러그인으로 메모리를 잡게 만든다. */
                const MAX_BR_TABLE_TARGETS: usize = 65_536;
                if cnt > MAX_BR_TABLE_TARGETS {
                    return Err("WASM br_table has too many targets".into());
                }
                let mut targets = Vec::with_capacity(cnt);
                for _ in 0..cnt {
                    targets.push(s.u32()?);
                }
                let default = s.u32()?;
                instrs.push(Instr::BrTable(targets, default));
            }
            0x0f => instrs.push(Instr::Return),
            0x10 => instrs.push(Instr::Call(s.u32()?)),
            0x11 => {
                let t = s.u32()?;
                if s.byte()? != 0 {
                    return Err("WASM call_indirect table index must be 0".into());
                }
                instrs.push(Instr::CallIndirect(t));
            }
            0x1a => instrs.push(Instr::Drop),
            0x1b => instrs.push(Instr::Select),
            0x1c => {
                let n = s.u32()?;
                if n != 1 {
                    return Err("WASM typed select needs exactly one result type".into());
                }
                let _ = val_type(s.byte()?)?;
                instrs.push(Instr::Select);
            }
            0x20 => instrs.push(Instr::LocalGet(s.u32()?)),
            0x21 => instrs.push(Instr::LocalSet(s.u32()?)),
            0x22 => instrs.push(Instr::LocalTee(s.u32()?)),
            0x23 => instrs.push(Instr::GlobalGet(s.u32()?)),
            0x24 => instrs.push(Instr::GlobalSet(s.u32()?)),
            0x28..=0x35 => {
                let _align = s.u32()?;
                let offset = s.u32()?;
                instrs.push(Instr::Load { op, offset });
            }
            0x36..=0x3e => {
                let _align = s.u32()?;
                let offset = s.u32()?;
                instrs.push(Instr::Store { op, offset });
            }
            0x3f => {
                if s.byte()? != 0 {
                    return Err("WASM memory.size memory index must be 0".into());
                }
                instrs.push(Instr::MemSize);
            }
            0x40 => {
                if s.byte()? != 0 {
                    return Err("WASM memory.grow memory index must be 0".into());
                }
                instrs.push(Instr::MemGrow);
            }
            0x41 => instrs.push(Instr::I32Const(s.i32()?)),
            0x42 => instrs.push(Instr::I64Const(s.i64()?)),
            0x43 => instrs.push(Instr::F32Const(s.f32()?)),
            0x44 => instrs.push(Instr::F64Const(s.f64()?)),
            0x45..=0x5a | 0x67..=0x8a | 0xa7 | 0xac..=0xad | 0xc0..=0xc4 => {
                instrs.push(Instr::Num(op));
            }
            0x45..=0xc4 => {
                return Err(format!("Unsupported numeric opcode 0x{op:02x}"));
            }

            other => return Err(format!("Unsupported opcode 0x{other:02x}")),
        }
        if instrs.len() > instruction_budget {
            return Err("Too many decoded WASM instructions".into());
        }
    }
    if instrs.len() > instruction_budget {
        return Err("Too many decoded WASM instructions".into());
    }
    if !function_ended {
        return Err("WASM function body has no final end".into());
    }
    if !s.done() {
        return Err("WASM function has data after the final end".into());
    }
    Ok((locals, instrs))
}

/**
 * @brief 실행 중인 인스턴스: 모듈 하나에 대한 가변 상태.
 * @invariant fuel은 명령마다 줄고 0이 되면 트랩이다. call_depth는 상한을 넘지 않는다.
 */
pub struct Instance<'m> {
    /** @brief 돌리고 있는 플러그인. */
    module: &'m Module,
    /** @brief 이 실행의 메모리. */
    memory: Vec<u8>,
    /** @brief 메모리를 늘릴 수 있는 한계. */
    mem_max_bytes: usize,
    /** @brief 전역 변수 값들. */
    globals: Vec<Value>,
    /** @brief 남은 연료. 0이 되면 덫에 걸린다. */
    fuel: u64,
    /** @brief 겹쳐 부른 깊이. 상한이 없으면 스택이 넘친다. */
    call_depth: usize,
}

/** @brief 호출 프레임. 지역 변수와 실행 중인 함수. */
struct Frame {
    /** @brief 이 호출의 지역 변수들. */
    locals: Vec<Value>,
    /** @brief 부른 함수 번호. */
    func_idx: u32,
}

/**
 * @brief 제어 흐름 라벨.
 * @details height는 이 라벨에 들어올 때의 값 스택 높이다. 분기할 때 스택을 그 높이로
 *          되돌려야 블록이 남긴 값이 새지 않는다. 루프는 목표가 자기 시작점이라 따로 구분한다.
 */
struct Label {
    /** @brief 이 라벨로 분기할 때 보존할 값의 수. */
    arity: u32,
    /** @brief 정상적으로 end에 닿았을 때 이 블록이 남길 값의 수. */
    end_arity: u32,
    /** @brief 이 블록에 들어올 때의 값 스택 높이. */
    height: usize,
    /** @brief 여기서 빠져나갈 곳. */
    target: usize,
    /** @brief 반복하는 블록(loop)인지. 그러면 처음으로 돌아간다. */
    is_loop: bool,
}

/**
 * @brief 인스턴스에서 회수한 재사용 가능 상태.
 * @details 메모리와 전역 벡터의 할당만 재사용한다. 내용은 인스턴스를 만들 때 전부
 *          초기화되므로 이전 호출의 값이 다음 호출로 새지 않는다.
 */
#[derive(Default)]
pub struct InstanceState {
    /** @brief 다시 쓰려고 남겨 둔 메모리. */
    memory: Vec<u8>,
    /** @brief 다시 쓰려고 남겨 둔 전역 변수들. */
    globals: Vec<Value>,
}

impl InstanceState {
    /** @brief 보관 중인 메모리 용량. 너무 크면 풀에 되돌리지 않고 버린다. */
    pub fn memory_capacity(&self) -> usize {
        self.memory.capacity()
    }
}

impl<'m> Instance<'m> {
    /** @brief 상태를 새로 잡아 인스턴스를 만든다. */
    #[cfg(test)]
    pub fn instantiate(
        module: &'m Module,
        fuel: u64,
        mem_max_bytes: usize,
    ) -> Result<Self, String> {
        Self::instantiate_with(module, fuel, mem_max_bytes, InstanceState::default())
    }

    /**
     * @brief 재사용 상태 위에 인스턴스를 만든다.
     * @details 메모리를 0으로 되돌린 뒤 데이터 세그먼트를 로드하고 전역을 초기값으로
     *          되돌린다. 재사용해도 이전 호출의 흔적이 남지 않는 근거다.
     * @param mem_max_bytes 메모리 상한. 초기 크기가 이를 넘으면 인스턴스를 만들지 않는다.
     */
    pub fn instantiate_with(
        module: &'m Module,
        fuel: u64,
        mem_max_bytes: usize,
        state: InstanceState,
    ) -> Result<Self, String> {
        let mem_bytes = usize::try_from(module.mem_min)
            .ok()
            .and_then(|pages| pages.checked_mul(PAGE))
            .ok_or("Initial memory size overflowed")?;
        if mem_bytes > mem_max_bytes {
            return Err("WASM initial memory is too large".into());
        }
        let InstanceState {
            mut memory,
            mut globals,
        } = state;
        memory.clear();
        memory.resize(mem_bytes, 0);
        for (off, bytes) in &module.data {
            let off = *off as usize;
            if off
                .checked_add(bytes.len())
                .is_none_or(|end| end > memory.len())
            {
                return Err("Data segment exceeds memory".into());
            }
            memory[off..off + bytes.len()].copy_from_slice(bytes);
        }
        globals.clear();
        globals.extend(module.globals.iter().map(|(_, _, v)| *v));
        let mut inst = Instance {
            module,
            memory,
            mem_max_bytes,
            globals,
            fuel,
            call_depth: 0,
        };
        if let Some(start) = module.start {
            inst.invoke(start, Vec::new())?;
        }
        Ok(inst)
    }

    /** @brief 인스턴스를 해체해 재사용할 할당을 꺼낸다. */
    pub fn into_state(self) -> InstanceState {
        InstanceState {
            memory: self.memory,
            globals: self.globals,
        }
    }

    /**
     * @brief 게스트 메모리에 쓴다.
     * @warning 주소는 게스트가 준 값이라 신뢰할 수 없다. 덧셈부터 넘침을 검사하고 범위를
     *          확인한다. 검사를 빠뜨리면 게스트가 호스트 메모리를 건드릴 수 있다.
     */
    pub fn write_mem(&mut self, addr: usize, data: &[u8]) -> Result<(), String> {
        let end = addr.checked_add(data.len()).ok_or("Address overflowed")?;
        if end > self.memory.len() {
            return Err("Memory write out of bounds".into());
        }
        self.memory[addr..end].copy_from_slice(data);
        Ok(())
    }

    /** @brief 게스트 메모리를 읽는다. 범위 검사는 write_mem과 같다. */
    pub fn read_mem(&self, addr: usize, len: usize) -> Result<&[u8], String> {
        let end = addr
            .checked_add(len)
            .ok_or("Memory read address overflowed")?;
        self.memory
            .get(addr..end)
            .ok_or("Memory read out of bounds".into())
    }

    /** @brief 내보낸 함수의 인덱스. 함수가 아니면 None. */
    pub fn export_func(&self, name: &str) -> Option<u32> {
        match self.module.exports.get(name) {
            Some((ExportKind::Func, idx)) => Some(*idx),
            _ => None,
        }
    }

    /** @brief 남은 연료. 0이면 예산 소진으로 트랩한 것이다. */
    pub fn fuel_remaining(&self) -> u64 {
        self.fuel
    }

    /** @brief 내보낸 함수를 이름으로 호출한다. */
    pub fn call_export(&mut self, name: &str, args: Vec<Value>) -> Result<Vec<Value>, String> {
        let idx = self
            .export_func(name)
            .ok_or(format!("Exported function '{name}' not found"))?;
        self.invoke(idx, args)
    }

    /**
     * @brief 인덱스로 함수를 찾는다.
     * @note import는 로드 단계에서 거부하므로 인덱스는 곧 지역 함수 배열의 인덱스다.
     */
    fn func(&self, idx: u32) -> Result<&'m Func, String> {
        self.module
            .funcs
            .get(idx as usize)
            .ok_or("WASM function index is out of range".into())
    }

    /** @brief 함수 인덱스의 서명을 찾는다. */
    fn ftype(&self, idx: u32) -> Result<&'m FuncType, String> {
        let f = self.func(idx)?;
        self.module
            .types
            .get(f.type_idx as usize)
            .ok_or("WASM type index is out of range".into())
    }

    /**
     * @brief 함수를 호출한다. 프레임을 만들고 지역 변수를 0으로 채운다.
     * @warning 깊이 상한을 먼저 확인한다. 인터프리터가 재귀라 이 검사가 호스트 스택
     *          넘침을 막는 유일한 장치다.
     */
    fn invoke(&mut self, idx: u32, args: Vec<Value>) -> Result<Vec<Value>, String> {
        if self.call_depth >= MAX_CALL_DEPTH {
            return Err("WASM call depth limit exceeded".into());
        }
        let result_type = {
            let ft = self.ftype(idx)?;
            if args.len() != ft.params.len() {
                return Err("Argument count does not match".into());
            }
            if args
                .iter()
                .zip(&ft.params)
                .any(|(value, expected)| value.value_type() != *expected)
            {
                return Err("WASM function argument types do not match its declaration".into());
            }
            ft.results.first().copied()
        };
        let f = self.func(idx)?;
        let mut locals = args;
        for lt in &f.locals {
            locals.push(default_val(*lt));
        }
        let frame = Frame {
            locals,
            func_idx: idx,
        };
        self.call_depth += 1;
        let result = self.run(frame, result_type);
        self.call_depth -= 1;
        result
    }

    /**
     * @brief 함수 본문을 실행한다.
     * @details 값 스택과 라벨 스택을 따로 둔다. 라벨은 블록 진입 시의 스택 높이를 가지고
     *          있어, 분기할 때 그 높이로 되돌려 블록이 남긴 값이 새지 않게 한다.
     * @note 명령마다 연료를 확인한다. 어느 명령에서 시작하든 예산을 넘길 수 없다.
     */
    fn run(
        &mut self,
        mut frame: Frame,
        result_type: Option<ValType>,
    ) -> Result<Vec<Value>, String> {
        let body: &[Instr] = &self.func(frame.func_idx)?.body;
        let mut stack: Vec<Value> = Vec::new();
        let result_arity = u32::from(result_type.is_some());
        let mut labels: Vec<Label> = vec![Label {
            arity: result_arity,
            end_arity: result_arity,
            height: 0,
            target: body.len(),
            is_loop: false,
        }];
        let mut pc = 0usize;

        loop {
            if stack.len() > MAX_VALUE_STACK || labels.len() > MAX_LABEL_STACK {
                return Err(if stack.len() > MAX_VALUE_STACK {
                    "WASM value stack limit exceeded"
                } else {
                    "WASM control stack limit exceeded"
                }
                .into());
            }
            if pc >= body.len() {
                break;
            }
            if self.fuel == 0 {
                return Err("Out of fuel".into());
            }
            self.fuel -= 1;
            let instr = &body[pc];
            match instr {
                Instr::Unreachable => return Err("unreachable".into()),
                Instr::Nop => {}
                Instr::Block { arity, end } => {
                    labels.push(Label {
                        arity: *arity,
                        end_arity: *arity,
                        height: stack.len(),
                        target: *end,
                        is_loop: false,
                    });
                }
                Instr::Loop { arity, .. } => {
                    labels.push(Label {
                        arity: 0,
                        end_arity: *arity,
                        height: stack.len(),
                        target: pc,
                        is_loop: true,
                    });
                }
                Instr::If { arity, else_, end } => {
                    let cond = stack.pop().ok_or("Stack underflow")?.as_i32()?;
                    labels.push(Label {
                        arity: *arity,
                        end_arity: *arity,
                        height: stack.len(),
                        target: *end,
                        is_loop: false,
                    });
                    if cond == 0 {
                        pc = if *else_ == *end { *end } else { *else_ + 1 };
                        continue;
                    }
                }
                Instr::Else { end } => {
                    pc = *end;
                    continue;
                }
                Instr::End => {
                    let label = labels
                        .pop()
                        .ok_or("WASM end has no matching control label")?;
                    let expected = label
                        .height
                        .checked_add(label.end_arity as usize)
                        .ok_or("WASM control stack height overflowed")?;
                    if stack.len() != expected {
                        return Err(
                            "WASM block result stack height does not match its declaration".into(),
                        );
                    }
                    if labels.is_empty() {
                        break;
                    }
                }
                Instr::Br(d) => {
                    pc = self.do_branch(*d, &mut stack, &mut labels)?;
                    continue;
                }
                Instr::BrIf(d) => {
                    let cond = stack.pop().ok_or("Stack underflow")?.as_i32()?;
                    if cond != 0 {
                        pc = self.do_branch(*d, &mut stack, &mut labels)?;
                        continue;
                    }
                }
                Instr::BrTable(targets, default) => {
                    let i = stack.pop().ok_or("Stack underflow")?.as_i32()? as usize;
                    let d = *targets.get(i).unwrap_or(default);
                    pc = self.do_branch(d, &mut stack, &mut labels)?;
                    continue;
                }
                Instr::Return => {
                    if let Some(expected) = result_type {
                        let value = stack.pop().ok_or("Stack underflow")?;
                        if value.value_type() != expected {
                            return Err(
                                "WASM function return types do not match its declaration".into()
                            );
                        }
                        return Ok(vec![value]);
                    }
                    return Ok(Vec::new());
                }
                Instr::Call(callee) => {
                    let param_count = self.ftype(*callee)?.params.len();
                    let mut args = Vec::with_capacity(param_count);
                    for _ in 0..param_count {
                        args.push(stack.pop().ok_or("Stack underflow")?);
                    }
                    args.reverse();
                    let res = self.invoke(*callee, args)?;
                    stack.extend(res);
                }
                Instr::CallIndirect(type_idx) => {
                    let ti = stack.pop().ok_or("Stack underflow")?.as_i32()? as usize;
                    let callee = self
                        .module
                        .table
                        .get(ti)
                        .copied()
                        .flatten()
                        .ok_or("Invalid table index")?;
                    let param_count = {
                        let cft = self.ftype(callee)?;
                        let expected = self
                            .module
                            .types
                            .get(*type_idx as usize)
                            .ok_or("Invalid call_indirect type index")?;
                        if cft.params != expected.params || cft.results != expected.results {
                            return Err("call_indirect type does not match".into());
                        }
                        cft.params.len()
                    };
                    let mut args = Vec::with_capacity(param_count);
                    for _ in 0..param_count {
                        args.push(stack.pop().ok_or("Stack underflow")?);
                    }
                    args.reverse();
                    let res = self.invoke(callee, args)?;
                    stack.extend(res);
                }
                Instr::Drop => {
                    stack.pop().ok_or("Stack underflow")?;
                }
                Instr::Select => {
                    let c = stack.pop().ok_or("Stack underflow")?.as_i32()?;
                    let b = stack.pop().ok_or("Stack underflow")?;
                    let a = stack.pop().ok_or("Stack underflow")?;
                    if a.value_type() != b.value_type() {
                        return Err("WASM select operand types do not match".into());
                    }
                    stack.push(if c != 0 { a } else { b });
                }
                Instr::LocalGet(i) => {
                    stack.push(*frame.locals.get(*i as usize).ok_or("local index")?);
                }
                Instr::LocalSet(i) => {
                    let v = stack.pop().ok_or("Stack underflow")?;
                    let slot = frame.locals.get_mut(*i as usize).ok_or("local index")?;
                    if slot.value_type() != v.value_type() {
                        return Err("WASM local.set value type does not match".into());
                    }
                    *slot = v;
                }
                Instr::LocalTee(i) => {
                    let v = *stack.last().ok_or("Stack underflow")?;
                    let slot = frame.locals.get_mut(*i as usize).ok_or("local index")?;
                    if slot.value_type() != v.value_type() {
                        return Err("WASM local.tee value type does not match".into());
                    }
                    *slot = v;
                }
                Instr::GlobalGet(i) => {
                    stack.push(*self.globals.get(*i as usize).ok_or("global index")?);
                }
                Instr::GlobalSet(i) => {
                    let v = stack.pop().ok_or("Stack underflow")?;
                    let slot = self.globals.get_mut(*i as usize).ok_or("global index")?;
                    if slot.value_type() != v.value_type() {
                        return Err("WASM global.set value type does not match".into());
                    }
                    *slot = v;
                }
                Instr::Load { op, offset } => {
                    let addr = stack.pop().ok_or("Stack underflow")?.as_i32()? as usize;
                    let effective = addr
                        .checked_add(*offset as usize)
                        .ok_or("WASM load effective address overflowed")?;
                    let v = self.exec_load(*op, effective)?;
                    stack.push(v);
                }
                Instr::Store { op, offset } => {
                    let v = stack.pop().ok_or("Stack underflow")?;
                    let addr = stack.pop().ok_or("Stack underflow")?.as_i32()? as usize;
                    let effective = addr
                        .checked_add(*offset as usize)
                        .ok_or("WASM store effective address overflowed")?;
                    self.exec_store(*op, effective, v)?;
                }
                Instr::MemSize => {
                    stack.push(Value::I32((self.memory.len() / PAGE) as i32));
                }
                Instr::MemGrow => {
                    let signed_delta = stack.pop().ok_or("Stack underflow")?.as_i32()?;
                    let old = self.memory.len() / PAGE;
                    let next_pages = usize::try_from(signed_delta)
                        .ok()
                        .and_then(|delta| old.checked_add(delta));
                    let newbytes = next_pages.and_then(|pages| pages.checked_mul(PAGE));
                    if newbytes.is_none_or(|bytes| bytes > self.mem_max_bytes)
                        || next_pages.is_some_and(|pages| {
                            self.module.mem_max.is_some_and(|mx| pages > mx as usize)
                        })
                    {
                        stack.push(Value::I32(-1));
                    } else {
                        self.memory
                            .resize(newbytes.expect("Validated memory size"), 0);
                        stack.push(Value::I32(old as i32));
                    }
                }
                Instr::I32Const(v) => stack.push(Value::I32(*v)),
                Instr::I64Const(v) => stack.push(Value::I64(*v)),
                Instr::F32Const(v) => stack.push(Value::F32(*v)),
                Instr::F64Const(v) => stack.push(Value::F64(*v)),
                Instr::Num(op) => exec_num(*op, &mut stack)?,
            }
            pc += 1;
        }

        let arity = usize::from(result_type.is_some());
        if stack.len() != arity {
            return Err("WASM function return stack height does not match its declaration".into());
        }
        let out = stack.split_off(stack.len() - arity);
        if let (Some(value), Some(expected)) = (out.first(), result_type) {
            if value.value_type() != expected {
                return Err("WASM function return types do not match its declaration".into());
            }
        }
        Ok(out)
    }

    /**
     * @brief 라벨 depth만큼 바깥으로 분기한다.
     * @details 라벨 arity만큼의 값을 떼어 두고 스택을 그 라벨의 높이로 자른 뒤 되돌려
     *          놓는다. 이 절차가 없으면 블록 안에서 쌓은 중간값이 바깥으로 새어 나간다.
     * @note 루프 라벨은 자기 자신을 남긴다. 다시 돌아올 목표이기 때문이다.
     * @return 이어서 실행할 명령 위치.
     */
    fn do_branch(
        &self,
        depth: u32,
        stack: &mut Vec<Value>,
        labels: &mut Vec<Label>,
    ) -> Result<usize, String> {
        let n = labels.len();
        let idx = n
            .checked_sub(1 + depth as usize)
            .ok_or("WASM branch depth exceeds the current block depth")?;
        let label = &labels[idx];
        let arity = label.arity as usize;
        let height = label.height;
        let target = label.target;
        let is_loop = label.is_loop;

        let required = height
            .checked_add(arity)
            .ok_or("WASM branch stack height overflowed")?;
        if stack.len() < required {
            return Err("Stack underflow on branch".into());
        }
        let kept = stack.split_off(stack.len() - arity);
        stack.truncate(height);
        stack.extend(kept);
        if is_loop {
            labels.truncate(idx + 1);
            Ok(target + 1)
        } else {
            labels.truncate(idx);
            Ok(target + 1)
        }
    }

    /**
     * @brief 메모리 로드 명령을 실행한다.
     * @warning 주소는 게스트가 계산한 값이다. 폭마다 넘침과 범위를 확인해 트랩으로 돌린다.
     *          여기서 검사를 놓치면 게스트가 호스트 메모리를 읽는다.
     */
    fn exec_load(&self, op: u8, addr: usize) -> Result<Value, String> {
        let rd = |n: usize| -> Result<&[u8], String> {
            let end = addr.checked_add(n).ok_or("Address overflowed")?;
            self.memory
                .get(addr..end)
                .ok_or("Load out of bounds".into())
        };
        Ok(match op {
            0x28 => {
                let b = rd(4)?;
                Value::I32(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            0x29 => {
                let b = rd(8)?;
                Value::I64(i64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            0x2a => {
                let b = rd(4)?;
                Value::F32(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            0x2b => {
                let b = rd(8)?;
                Value::F64(f64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            0x2c => Value::I32(rd(1)?[0] as i8 as i32),
            0x2d => Value::I32(rd(1)?[0] as i32),
            0x2e => {
                let b = rd(2)?;
                Value::I32(i16::from_le_bytes([b[0], b[1]]) as i32)
            }
            0x2f => {
                let b = rd(2)?;
                Value::I32(u16::from_le_bytes([b[0], b[1]]) as i32)
            }
            0x30 => Value::I64(rd(1)?[0] as i8 as i64),
            0x31 => Value::I64(rd(1)?[0] as i64),
            0x32 => {
                let b = rd(2)?;
                Value::I64(i16::from_le_bytes([b[0], b[1]]) as i64)
            }
            0x33 => {
                let b = rd(2)?;
                Value::I64(u16::from_le_bytes([b[0], b[1]]) as i64)
            }
            0x34 => {
                let b = rd(4)?;
                Value::I64(i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64)
            }
            0x35 => {
                let b = rd(4)?;
                Value::I64(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64)
            }
            _ => return Err(format!("Unsupported memory load opcode 0x{op:02x}")),
        })
    }

    /** @brief 메모리 저장 명령을 실행한다. 범위 검사는 로드와 같다. */
    fn exec_store(&mut self, op: u8, addr: usize, v: Value) -> Result<(), String> {
        let wr = |mem: &mut Vec<u8>, bytes: &[u8]| -> Result<(), String> {
            let end = addr.checked_add(bytes.len()).ok_or("Address overflowed")?;
            if end > mem.len() {
                return Err("Store out of bounds".into());
            }
            mem[addr..end].copy_from_slice(bytes);
            Ok(())
        };
        match op {
            0x36 => wr(&mut self.memory, &v.as_i32()?.to_le_bytes())?,
            0x37 => wr(&mut self.memory, &v.as_i64()?.to_le_bytes())?,
            0x38 => {
                let f = match v {
                    Value::F32(x) => x,
                    _ => return Err("Expected an f32 value".into()),
                };
                wr(&mut self.memory, &f.to_le_bytes())?
            }
            0x39 => {
                let f = match v {
                    Value::F64(x) => x,
                    _ => return Err("Expected an f64 value".into()),
                };
                wr(&mut self.memory, &f.to_le_bytes())?
            }
            0x3a => wr(&mut self.memory, &[(v.as_i32()? as u8)])?,
            0x3b => wr(&mut self.memory, &(v.as_i32()? as u16).to_le_bytes())?,
            0x3c => wr(&mut self.memory, &[(v.as_i64()? as u8)])?,
            0x3d => wr(&mut self.memory, &(v.as_i64()? as u16).to_le_bytes())?,
            0x3e => wr(&mut self.memory, &(v.as_i64()? as u32).to_le_bytes())?,
            _ => return Err(format!("Unsupported memory store opcode 0x{op:02x}")),
        }
        Ok(())
    }
}

/** @brief 스택에서 i32를 꺼낸다. 비었거나 형식이 다르면 트랩이다. */
fn pop_i32(s: &mut Vec<Value>) -> Result<i32, String> {
    s.pop()
        .ok_or("Stack underflow".into())
        .and_then(Value::as_i32)
}
/** @brief 스택에서 i64를 꺼낸다. */
fn pop_i64(s: &mut Vec<Value>) -> Result<i64, String> {
    s.pop()
        .ok_or("Stack underflow".into())
        .and_then(Value::as_i64)
}

/**
 * @brief 수치 연산 명령을 실행한다.
 * @note 0으로 나누기와 i32::MIN / -1 같은 넘침은 명세대로 트랩이다. Rust의 기본 나눗셈을
 *       그대로 쓰면 그 자리에서 패닉하므로 반드시 먼저 걸러야 한다.
 */
fn exec_num(op: u8, s: &mut Vec<Value>) -> Result<(), String> {
    macro_rules! i32_un {
        ($f:expr) => {{
            let a = pop_i32(s)?;
            s.push(Value::I32($f(a)));
        }};
    }
    macro_rules! i32_bin {
        ($f:expr) => {{
            let b = pop_i32(s)?;
            let a = pop_i32(s)?;
            s.push(Value::I32($f(a, b)));
        }};
    }
    macro_rules! i32_cmp {
        ($f:expr) => {{
            let b = pop_i32(s)?;
            let a = pop_i32(s)?;
            s.push(Value::I32(if $f(a, b) { 1 } else { 0 }));
        }};
    }
    macro_rules! i64_bin {
        ($f:expr) => {{
            let b = pop_i64(s)?;
            let a = pop_i64(s)?;
            s.push(Value::I64($f(a, b)));
        }};
    }
    macro_rules! i64_cmp {
        ($f:expr) => {{
            let b = pop_i64(s)?;
            let a = pop_i64(s)?;
            s.push(Value::I32(if $f(a, b) { 1 } else { 0 }));
        }};
    }
    match op {
        0x45 => {
            let a = pop_i32(s)?;
            s.push(Value::I32(if a == 0 { 1 } else { 0 }));
        }
        0x46 => i32_cmp!(|a, b| a == b),
        0x47 => i32_cmp!(|a, b| a != b),
        0x48 => i32_cmp!(|a, b| a < b),
        0x49 => i32_cmp!(|a: i32, b: i32| (a as u32) < (b as u32)),
        0x4a => i32_cmp!(|a, b| a > b),
        0x4b => i32_cmp!(|a: i32, b: i32| (a as u32) > (b as u32)),
        0x4c => i32_cmp!(|a, b| a <= b),
        0x4d => i32_cmp!(|a: i32, b: i32| (a as u32) <= (b as u32)),
        0x4e => i32_cmp!(|a, b| a >= b),
        0x4f => i32_cmp!(|a: i32, b: i32| (a as u32) >= (b as u32)),

        0x50 => {
            let a = pop_i64(s)?;
            s.push(Value::I32(if a == 0 { 1 } else { 0 }));
        }
        0x51 => i64_cmp!(|a, b| a == b),
        0x52 => i64_cmp!(|a, b| a != b),
        0x53 => i64_cmp!(|a, b| a < b),
        0x54 => i64_cmp!(|a: i64, b: i64| (a as u64) < (b as u64)),
        0x55 => i64_cmp!(|a, b| a > b),
        0x56 => i64_cmp!(|a: i64, b: i64| (a as u64) > (b as u64)),
        0x57 => i64_cmp!(|a, b| a <= b),
        0x58 => i64_cmp!(|a: i64, b: i64| (a as u64) <= (b as u64)),
        0x59 => i64_cmp!(|a, b| a >= b),
        0x5a => i64_cmp!(|a: i64, b: i64| (a as u64) >= (b as u64)),

        0x67 => i32_un!(|a: i32| a.leading_zeros() as i32),
        0x68 => i32_un!(|a: i32| a.trailing_zeros() as i32),
        0x69 => i32_un!(|a: i32| a.count_ones() as i32),
        0x6a => i32_bin!(|a: i32, b: i32| a.wrapping_add(b)),
        0x6b => i32_bin!(|a: i32, b: i32| a.wrapping_sub(b)),
        0x6c => i32_bin!(|a: i32, b: i32| a.wrapping_mul(b)),
        0x6d => {
            let b = pop_i32(s)?;
            let a = pop_i32(s)?;
            if b == 0 {
                return Err("i32.div_s division by zero".into());
            }
            if a == i32::MIN && b == -1 {
                return Err("i32.div_s overflow".into());
            }
            s.push(Value::I32(a / b));
        }
        0x6e => {
            let b = pop_i32(s)?;
            let a = pop_i32(s)?;
            if b == 0 {
                return Err("i32.div_u division by zero".into());
            }
            s.push(Value::I32(((a as u32) / (b as u32)) as i32));
        }
        0x6f => {
            let b = pop_i32(s)?;
            let a = pop_i32(s)?;
            if b == 0 {
                return Err("i32.rem_s division by zero".into());
            }
            s.push(Value::I32(a.wrapping_rem(b)));
        }
        0x70 => {
            let b = pop_i32(s)?;
            let a = pop_i32(s)?;
            if b == 0 {
                return Err("i32.rem_u division by zero".into());
            }
            s.push(Value::I32(((a as u32) % (b as u32)) as i32));
        }
        0x71 => i32_bin!(|a: i32, b: i32| a & b),
        0x72 => i32_bin!(|a: i32, b: i32| a | b),
        0x73 => i32_bin!(|a: i32, b: i32| a ^ b),
        0x74 => i32_bin!(|a: i32, b: i32| a.wrapping_shl(b as u32)),
        0x75 => i32_bin!(|a: i32, b: i32| a.wrapping_shr(b as u32)),
        0x76 => i32_bin!(|a: i32, b: i32| ((a as u32).wrapping_shr(b as u32)) as i32),
        0x77 => i32_bin!(|a: i32, b: i32| a.rotate_left((b as u32) & 31)),
        0x78 => i32_bin!(|a: i32, b: i32| a.rotate_right((b as u32) & 31)),

        0x79 => {
            let a = pop_i64(s)?;
            s.push(Value::I64(a.leading_zeros() as i64));
        }
        0x7a => {
            let a = pop_i64(s)?;
            s.push(Value::I64(a.trailing_zeros() as i64));
        }
        0x7b => {
            let a = pop_i64(s)?;
            s.push(Value::I64(a.count_ones() as i64));
        }
        0x7c => i64_bin!(|a: i64, b: i64| a.wrapping_add(b)),
        0x7d => i64_bin!(|a: i64, b: i64| a.wrapping_sub(b)),
        0x7e => i64_bin!(|a: i64, b: i64| a.wrapping_mul(b)),
        0x7f => {
            let b = pop_i64(s)?;
            let a = pop_i64(s)?;
            if b == 0 {
                return Err("i64.div_s division by zero".into());
            }
            if a == i64::MIN && b == -1 {
                return Err("i64.div_s overflow".into());
            }
            s.push(Value::I64(a / b));
        }
        0x80 => {
            let b = pop_i64(s)?;
            let a = pop_i64(s)?;
            if b == 0 {
                return Err("i64.div_u division by zero".into());
            }
            s.push(Value::I64(((a as u64) / (b as u64)) as i64));
        }
        0x81 => {
            let b = pop_i64(s)?;
            let a = pop_i64(s)?;
            if b == 0 {
                return Err("i64.rem_s division by zero".into());
            }
            s.push(Value::I64(a.wrapping_rem(b)));
        }
        0x82 => {
            let b = pop_i64(s)?;
            let a = pop_i64(s)?;
            if b == 0 {
                return Err("i64.rem_u division by zero".into());
            }
            s.push(Value::I64(((a as u64) % (b as u64)) as i64));
        }
        0x83 => i64_bin!(|a: i64, b: i64| a & b),
        0x84 => i64_bin!(|a: i64, b: i64| a | b),
        0x85 => i64_bin!(|a: i64, b: i64| a ^ b),
        0x86 => i64_bin!(|a: i64, b: i64| a.wrapping_shl(b as u32)),
        0x87 => i64_bin!(|a: i64, b: i64| a.wrapping_shr(b as u32)),
        0x88 => i64_bin!(|a: i64, b: i64| ((a as u64).wrapping_shr(b as u32)) as i64),
        0x89 => i64_bin!(|a: i64, b: i64| a.rotate_left((b as u32) & 63)),
        0x8a => i64_bin!(|a: i64, b: i64| a.rotate_right((b as u32) & 63)),

        0xa7 => {
            let a = pop_i64(s)?;
            s.push(Value::I32(a as i32));
        }
        0xac => {
            let a = pop_i32(s)?;
            s.push(Value::I64(a as i64));
        }
        0xad => {
            let a = pop_i32(s)?;
            s.push(Value::I64((a as u32) as i64));
        }

        0xc0 => i32_un!(|a: i32| (a as i8) as i32),
        0xc1 => i32_un!(|a: i32| (a as i16) as i32),
        0xc2 => {
            let a = pop_i64(s)?;
            s.push(Value::I64((a as i8) as i64));
        }
        0xc3 => {
            let a = pop_i64(s)?;
            s.push(Value::I64((a as i16) as i64));
        }
        0xc4 => {
            let a = pop_i64(s)?;
            s.push(Value::I64((a as i32) as i64));
        }
        other => return Err(format!("Unsupported numeric opcode 0x{other:02x}")),
    }
    Ok(())
}

#[cfg(test)]
/** @brief 계산과 분기, 연료 상한, 그리고 잘못된 주소 접근이 패닉이 아닌 덫이 되는지. */
mod tests {
    use super::*;

    /** @brief 테스트용 unsigned LEB128을 붙인다. */
    fn push_u32_leb(out: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    /** @brief NOP 명령 수를 정확히 정한 최소 모듈. */
    fn nop_module(instructions: usize) -> Vec<u8> {
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        module.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        module.extend_from_slice(&[3, 2, 1, 0]);

        let mut body = Vec::with_capacity(instructions + 2);
        body.push(0);
        body.resize(instructions + 1, 0x01);
        body.push(0x0b);
        let mut code = vec![1];
        push_u32_leb(&mut code, body.len() as u32);
        code.extend_from_slice(&body);
        module.push(10);
        push_u32_leb(&mut module, code.len() as u32);
        module.extend_from_slice(&code);
        module
    }

    /** @brief 이 플러그인을 돌려 결과를 받는다. */
    fn run_eval(wat: &str, args: &[Value]) -> Result<Vec<Value>, String> {
        let wasm = wat::parse_str(wat).unwrap();
        let m = Module::parse(&wasm)?;
        let mut inst = Instance::instantiate(&m, 1_000_000, 16 * 1024 * 1024)?;
        inst.call_export("f", args.to_vec())
    }

    #[test]
    /** @brief 표준 섹션 중복·알 수 없는 ID·남은 payload를 조용히 받지 않는지. */
    fn malformed_section_envelopes_are_rejected() {
        let header = b"\0asm\x01\0\0\0";
        let mut duplicate = header.to_vec();
        duplicate.extend_from_slice(&[1, 1, 0, 1, 1, 0]);
        assert!(Module::parse(&duplicate).is_err(), "중복 type section");

        let mut trailing = header.to_vec();
        trailing.extend_from_slice(&[1, 2, 0, 0]);
        assert!(
            Module::parse(&trailing).is_err(),
            "type section trailing byte"
        );

        let mut unknown = header.to_vec();
        unknown.extend_from_slice(&[12, 0]);
        assert!(Module::parse(&unknown).is_err(), "지원하지 않는 section ID");

        let mut trailing_function = header.to_vec();
        trailing_function.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        trailing_function.extend_from_slice(&[3, 2, 1, 0]);
        trailing_function.extend_from_slice(&[10, 5, 1, 3, 0, 0x0b, 0x01]);
        assert!(
            Module::parse(&trailing_function).is_err(),
            "함수 end 뒤 trailing opcode"
        );

        let mut missing_function_end = header.to_vec();
        missing_function_end.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        missing_function_end.extend_from_slice(&[3, 2, 1, 0]);
        missing_function_end.extend_from_slice(&[10, 4, 1, 2, 0, 0x01]);
        assert!(
            Module::parse(&missing_function_end).is_err(),
            "함수 바깥 end 누락"
        );

        let mut duplicate_else = header.to_vec();
        duplicate_else.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        duplicate_else.extend_from_slice(&[3, 2, 1, 0]);
        duplicate_else
            .extend_from_slice(&[10, 11, 1, 9, 0, 0x41, 1, 0x04, 0x40, 0x05, 0x05, 0x0b, 0x0b]);
        assert!(
            Module::parse(&duplicate_else).is_err(),
            "if 하나에 else 두 개"
        );
    }

    #[test]
    /** @brief export/start/예약 필드가 존재하는 정의와 정확히 맞아야 하는지. */
    fn malformed_module_semantics_are_rejected_on_load() {
        let header = b"\0asm\x01\0\0\0";

        let mut duplicate_export = header.to_vec();
        duplicate_export.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        duplicate_export.extend_from_slice(&[3, 2, 1, 0]);
        duplicate_export.extend_from_slice(&[7, 9, 2, 1, b'x', 0, 0, 1, b'x', 0, 0]);
        duplicate_export.extend_from_slice(&[10, 4, 1, 2, 0, 0x0b]);
        assert!(
            Module::parse(&duplicate_export).is_err(),
            "중복 export 이름"
        );

        let mut invalid_function_export = header.to_vec();
        invalid_function_export.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        invalid_function_export.extend_from_slice(&[3, 2, 1, 0]);
        invalid_function_export.extend_from_slice(&[7, 5, 1, 1, b'x', 0, 1]);
        invalid_function_export.extend_from_slice(&[10, 4, 1, 2, 0, 0x0b]);
        assert!(
            Module::parse(&invalid_function_export).is_err(),
            "존재하지 않는 함수 export"
        );

        let mut missing_memory = header.to_vec();
        missing_memory.extend_from_slice(&[7, 10, 1, 6, b'm', b'e', b'm', b'o', b'r', b'y', 2, 0]);
        assert!(
            Module::parse(&missing_memory).is_err(),
            "정의되지 않은 memory export"
        );

        let mut invalid_start_signature = header.to_vec();
        invalid_start_signature.extend_from_slice(&[1, 5, 1, 0x60, 0, 1, 0x7f]);
        invalid_start_signature.extend_from_slice(&[3, 2, 1, 0]);
        invalid_start_signature.extend_from_slice(&[8, 1, 0]);
        invalid_start_signature.extend_from_slice(&[10, 6, 1, 4, 0, 0x41, 0, 0x0b]);
        assert!(
            Module::parse(&invalid_start_signature).is_err(),
            "start는 인자와 반환값이 없어야 함"
        );

        let mut invalid_memory_immediate = header.to_vec();
        invalid_memory_immediate.extend_from_slice(&[1, 5, 1, 0x60, 0, 1, 0x7f]);
        invalid_memory_immediate.extend_from_slice(&[3, 2, 1, 0]);
        invalid_memory_immediate.extend_from_slice(&[5, 3, 1, 0, 1]);
        invalid_memory_immediate.extend_from_slice(&[10, 6, 1, 4, 0, 0x3f, 1, 0x0b]);
        assert!(
            Module::parse(&invalid_memory_immediate).is_err(),
            "memory.size 예약 immediate"
        );

        let mut invalid_global_mutability = header.to_vec();
        invalid_global_mutability.extend_from_slice(&[6, 6, 1, 0x7f, 2, 0x41, 0, 0x0b]);
        assert!(
            Module::parse(&invalid_global_mutability).is_err(),
            "global mutability는 0 또는 1"
        );

        let multi_result = wat::parse_str(
            r#"(module (func (export "f") (result i32 i32)
                (i32.const 1) (i32.const 2)))"#,
        )
        .unwrap();
        assert!(
            Module::parse(&multi_result).is_err(),
            "지원하지 않는 다중 반환"
        );

        let unsupported_float = wat::parse_str(
            r#"(module (func (export "f") (result f32)
                (f32.add (f32.const 1) (f32.const 2))))"#,
        )
        .unwrap();
        assert!(
            Module::parse(&unsupported_float).is_err(),
            "실행할 수 없는 숫자 opcode는 로드 시 거부"
        );
    }

    #[test]
    /** @brief 한 바이트 명령이 디코딩 뒤 큰 enum 벡터로 팽창하지 못하는지. */
    fn decoded_instruction_count_is_bounded() {
        assert!(Module::parse(&nop_module(MAX_DECODED_INSTRUCTIONS - 1)).is_ok());
        assert!(Module::parse(&nop_module(MAX_DECODED_INSTRUCTIONS)).is_err());
    }

    #[test]
    /** @brief 실행할 수 없는 import를 호환 명목으로 로드하지 않는지. */
    fn imports_are_rejected() {
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        let mut payload = Vec::new();
        push_u32_leb(&mut payload, 1);
        module.push(2);
        push_u32_leb(&mut module, payload.len() as u32);
        module.extend_from_slice(&payload);
        assert!(Module::parse(&module).is_err());
    }

    #[test]
    /** @brief 선형 메모리 밖의 호스트 값 스택도 요청 단위 상한을 갖는지. */
    fn execution_value_stack_is_bounded() {
        let mut wat = String::from("(module (func (export \"f\") (result i32) ");
        for _ in 0..4_097 {
            wat.push_str("i32.const 0 ");
        }
        for _ in 0..4_097 {
            wat.push_str("drop ");
        }
        wat.push_str("i32.const 1))");
        assert!(run_eval(&wat, &[]).is_err());
    }

    #[test]
    /** @brief 재귀 호출마다 복제되는 local 벡터가 함수 하나에서 과대해지지 않는지. */
    fn function_local_count_is_tightly_bounded() {
        let mut wat = String::from("(module (func (export \"f\") (result i32) (local");
        for _ in 0..1_025 {
            wat.push_str(" i32");
        }
        wat.push_str(") i32.const 0))");
        let wasm = wat::parse_str(&wat).unwrap();
        assert!(Module::parse(&wasm).is_err());
    }

    #[test]
    /** @brief 사칙연산과 비교. */
    fn arithmetic_and_compare() {
        let wat = r#"(module (func (export "f") (param i32 i32) (result i32)
            (i32.add (local.get 0) (i32.mul (local.get 1) (i32.const 3)))))"#;
        assert_eq!(
            run_eval(wat, &[Value::I32(10), Value::I32(4)]).unwrap(),
            vec![Value::I32(22)]
        );
    }

    #[test]
    /** @brief 분기와 반복. */
    fn if_else_and_loop_sum() {
        let wat = r#"(module (func (export "f") (param $n i32) (result i32)
            (local $i i32) (local $acc i32)
            (block $done
              (loop $l
                (br_if $done (i32.gt_s (local.get $i) (local.get $n)))
                (local.set $acc (i32.add (local.get $acc) (local.get $i)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $l)))
            (local.get $acc)))"#;
        assert_eq!(
            run_eval(wat, &[Value::I32(10)]).unwrap(),
            vec![Value::I32(55)]
        );
    }

    #[test]
    /** @brief loop의 분기 arity와 정상 종료 result arity를 따로 보존하는지. */
    fn loop_result_arity_is_checked_at_end() {
        let wat = r#"(module (func (export "f") (result i32)
            (loop (result i32) (i32.const 7))))"#;
        assert_eq!(run_eval(wat, &[]).unwrap(), vec![Value::I32(7)]);
    }

    #[test]
    /** @brief 메모리 읽고 쓰기와 전역 값. */
    fn memory_store_load_and_globals() {
        let wat = r#"(module (memory (export "memory") 1)
            (global $g (mut i32) (i32.const 100))
            (func (export "f") (param i32) (result i32)
              (i32.store8 (global.get $g) (local.get 0))
              (global.set $g (i32.add (global.get $g) (i32.const 1)))
              (i32.load8_u (i32.const 100))))"#;
        assert_eq!(
            run_eval(wat, &[Value::I32(77)]).unwrap(),
            vec![Value::I32(77)]
        );
    }

    #[test]
    /** @brief 연료가 떨어지면 덫에 걸리는지. */
    fn fuel_exhaustion_traps() {
        let wat = r#"(module (func (export "f") (result i32)
            (loop $l (br $l)) (i32.const 1)))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let m = Module::parse(&wasm).unwrap();
        let mut inst = Instance::instantiate(&m, 10_000, 1024 * 1024).unwrap();
        assert!(inst.call_export("f", vec![]).is_err());
    }

    #[test]
    /** @brief 범위를 넘는 주소 접근이 패닉이 아니라 덫이 되는지. 패닉하면 질의 하나가 이 서버를 흔든다. */
    fn load_at_overflowing_address_traps_not_panics() {
        let wat = r#"(module (memory 1) (func (export "f") (result i32)
            (i32.load (i32.const -1))))"#;
        assert!(run_eval(wat, &[]).is_err());
    }

    #[test]
    /** @brief 테이블을 거친 호출. */
    fn call_indirect_dispatch() {
        let wat = r#"(module
            (table 2 funcref) (elem (i32.const 0) $a $b)
            (type $t (func (result i32)))
            (func $a (result i32) (i32.const 11))
            (func $b (result i32) (i32.const 22))
            (func (export "f") (param i32) (result i32)
              (call_indirect (type $t) (local.get 0))))"#;
        assert_eq!(
            run_eval(wat, &[Value::I32(1)]).unwrap(),
            vec![Value::I32(22)]
        );
        assert_eq!(
            run_eval(wat, &[Value::I32(0)]).unwrap(),
            vec![Value::I32(11)]
        );
    }

    #[test]
    /** @brief call_indirect가 매개변수 개수만 같은 다른 형식의 함수를 실행하지 않는지. */
    fn call_indirect_requires_the_exact_function_type() {
        let wat = r#"(module
            (type $expected (func (param i32) (result i32)))
            (type $actual (func (param f32) (result i64)))
            (table 1 funcref)
            (elem (i32.const 0) $callee)
            (func $callee (type $actual) (i64.const 7))
            (func (export "f") (param i32) (result i32)
              (call_indirect (type $expected) (local.get 0) (i32.const 0))))"#;
        assert!(run_eval(wat, &[Value::I32(1)]).is_err());
    }

    #[test]
    /** @brief signed division의 유일한 표현 범위 넘침이 값 반환이 아니라 trap인지. */
    fn signed_division_overflow_traps() {
        let i32_wat = r#"(module (func (export "f") (result i32)
            (i32.div_s (i32.const -2147483648) (i32.const -1))))"#;
        let i64_wat = r#"(module (func (export "f") (result i64)
            (i64.div_s (i64.const -9223372036854775808) (i64.const -1))))"#;
        assert!(run_eval(i32_wat, &[]).is_err());
        assert!(run_eval(i64_wat, &[]).is_err());
    }

    #[test]
    /** @brief 첫 바이트가 다르면 거부하는지. */
    fn bad_magic_rejected() {
        assert!(Module::parse(b"not wasm at all").is_err());
    }
}
