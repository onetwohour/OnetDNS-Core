//! WASM interpreter for policy plugins. It walks decoded instructions instead of compiling them, so
//! it never creates executable memory, which is safer for untrusted code.
//!
//! Everything here handles untrusted input. Every parse-time limit is a defense; loosening one lets
//! a short module exhaust memory or stack.

use std::collections::HashMap;

const PAGE: usize = 65536;

const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;

const MAX_TYPES: u32 = 16_384;

const MAX_FUNCTIONS: u32 = 65_536;

const MAX_PARAMS: u32 = 1_024;

/// The interpreter supports at most one result.
const MAX_RESULTS: u32 = 1;

const MAX_TABLE_ELEMS: u32 = 65_536;

const MAX_GLOBALS: u32 = 65_536;

const MAX_DATA_BYTES: usize = 16 * 1024 * 1024;

/// Stops empty segments from stretching parse time.
const MAX_DATA_SEGMENTS: u32 = 4_096;

/// Bounds host memory for the export name map.
const MAX_EXPORTS: u32 = 4_096;

/// One-byte opcodes decode into much larger enum values, so the decoded total is capped.
const MAX_DECODED_INSTRUCTIONS: usize = 262_144;

/// The interpreter recurses, so this is the host stack overflow defense: unbounded guest recursion
/// would overflow the stack before fuel runs out.
const MAX_CALL_DEPTH: usize = 128;

const MAX_LOCALS_PER_FUNCTION: usize = 1_024;

const MAX_VALUE_STACK: usize = 4_096;

const MAX_LABEL_STACK: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl Value {
    fn value_type(self) -> ValType {
        match self {
            Value::I32(_) => ValType::I32,
            Value::I64(_) => ValType::I64,
            Value::F32(_) => ValType::F32,
            Value::F64(_) => ValType::F64,
        }
    }

    fn as_i32(self) -> Result<i32, String> {
        match self {
            Value::I32(v) => Ok(v),
            _ => Err("Invalid WASM value type; expected a 32-bit integer".into()),
        }
    }
    fn as_i64(self) -> Result<i64, String> {
        match self {
            Value::I64(v) => Ok(v),
            _ => Err("Invalid WASM value type; expected a 64-bit integer".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
}

/// Unsupported types, such as reference types, are rejected.
fn val_type(b: u8) -> Result<ValType, String> {
    match b {
        0x7f => Ok(ValType::I32),
        0x7e => Ok(ValType::I64),
        0x7d => Ok(ValType::F32),
        0x7c => Ok(ValType::F64),
        other => Err(format!("Unknown valtype 0x{other:02x}")),
    }
}

fn default_val(t: ValType) -> Value {
    match t {
        ValType::I32 => Value::I32(0),
        ValType::I64 => Value::I64(0),
        ValType::F32 => Value::F32(0.0),
        ValType::F64 => Value::F64(0.0),
    }
}

#[derive(Debug)]
struct FuncType {
    params: Vec<ValType>,
    results: Vec<ValType>,
}

/// Block, loop, and branch targets are resolved at parse time; searching for the matching end at
/// run time gets expensive in deeply nested code.
#[derive(Debug, Clone)]
enum Instr {
    Unreachable,
    Nop,
    Block {
        arity: u32,
        end: usize,
    },
    Loop {
        arity: u32,
        end: usize,
    },
    If {
        arity: u32,
        else_: usize,
        end: usize,
    },
    Else {
        end: usize,
    },
    End,
    Br(u32),
    BrIf(u32),
    BrTable(Vec<u32>, u32),
    Return,
    Call(u32),
    CallIndirect(u32),
    Drop,
    Select,
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    Load {
        op: u8,
        offset: u32,
    },
    Store {
        op: u8,
        offset: u32,
    },
    MemSize,
    MemGrow,
    I32Const(i32),
    I64Const(i64),
    F32Const(f32),
    F64Const(f64),
    /// Numeric instruction; the opcode selects the operation.
    Num(u8),
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
    fn byte(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.pos).ok_or("EOF")?;
        self.pos += 1;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or("WASM byte range overflowed")?;
        let s = self.b.get(self.pos..end).ok_or("EOF")?;
        self.pos = end;
        Ok(s)
    }
    /// Unsigned LEB128. The shift width is bounded, so an endless run of 0x80 bytes cannot loop
    /// forever.
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
    /// Signed LEB128.
    fn i32(&mut self) -> Result<i32, String> {
        Ok(self.i64()? as i32)
    }
    /// Signed LEB128, sign-extended from the last byte.
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
    fn f32(&mut self) -> Result<f32, String> {
        let b = self.bytes(4)?;
        Ok(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn f64(&mut self) -> Result<f64, String> {
        let b = self.bytes(8)?;
        Ok(f64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    /// Length-prefixed UTF-8 name.
    fn name(&mut self) -> Result<String, String> {
        let n = self.u32()? as usize;
        let s = self.bytes(n)?;
        String::from_utf8(s.to_vec()).map_err(|_| "Non-UTF-8 name".into())
    }
}

struct Func {
    type_idx: u32,
    locals: Vec<ValType>,
    body: Vec<Instr>,
}

#[derive(Clone, Copy)]
enum ExportKind {
    Func,
    Memory,
    Global,
    Table,
}

/// Parsed module: immutable and shared by all calls. Parsing once keeps per-call cost low; an
/// instance only allocates memory and globals.
pub struct Module {
    types: Vec<FuncType>,
    funcs: Vec<Func>,
    func_types: Vec<u32>,
    exports: HashMap<String, (ExportKind, u32)>,
    /// Initial size, in pages.
    mem_min: u32,
    /// Maximum size, in pages.
    mem_max: Option<u32>,
    /// Whether the module defines memory 0.
    memory_defined: bool,
    /// Type, mutability, and initial value of each global.
    globals: Vec<(ValType, bool, Value)>,
    /// Function run at instantiation.
    start: Option<u32>,
    table: Vec<Option<u32>>,
    /// Whether the module defines table 0.
    table_defined: bool,
    /// Segments copied into memory at instantiation.
    data: Vec<(u32, Vec<u8>)>,
}

impl Module {
    /// Ignores the export kind.
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.contains_key(name)
    }

    /// Whether `name` exports memory 0, which the host writes the context into.
    pub fn has_memory_export(&self, name: &str) -> bool {
        self.memory_defined && matches!(self.exports.get(name), Some((ExportKind::Memory, 0)))
    }

    /// Signature of an exported function, for the load-time ABI check.
    pub fn func_export_signature(&self, name: &str) -> Option<(&[ValType], &[ValType])> {
        let idx = match self.exports.get(name)? {
            (ExportKind::Func, idx) => *idx,
            _ => return None,
        };
        let func = self.funcs.get(idx as usize)?;
        let ftype = self.types.get(func.type_idx as usize)?;
        Some((&ftype.params, &ftype.results))
    }

    /// Checks magic and version, then reads sections in order, each checking its own count cap;
    /// trusting a count and preallocating would let a module of a few bytes build a huge vector.
    /// Any malformed module returns an error, never a panic.
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

    /// Checks that decoded indexes and definitions match the module semantics the runtime supports.
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

    /// No host functions are exposed, so anything but an empty section is rejected.
    fn parse_imports(&mut self, s: &mut Reader) -> Result<(), String> {
        let n = s.u32()?;
        if n != 0 {
            return Err("WASM imports are not supported".into());
        }
        Ok(())
    }

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

    /// Only one linear memory.
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

    /// Caps the total bytes, so splitting segments cannot get around the limit.
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

/// Constant expressions for global initializers and segment offsets. Only literals: a reference to
/// another global is refused, which keeps modules from depending on initialization order.
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

/// Multi-value and type-index blocks are not supported: the plugin ABI does not need them, and
/// letting an unsupported form through would misalign the stack at run time.
fn blocktype_arity(s: &mut Reader) -> Result<u32, String> {
    let b = s.byte()?;
    match b {
        0x40 => Ok(0),
        0x7c..=0x7f => Ok(1),
        _ => Err("Multi-value and type-index block types are not supported".into()),
    }
}

/// Resolves the matching end and else of each control instruction here and stores them in the
/// instruction, so branch cost stays constant however deep the nesting. `nparams` counts toward the
/// local limit; `instruction_budget` is what remains of the module's decoded instruction cap.
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

                /// Without it, a short plugin could allocate a huge table.
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

/// Mutable state for one module. `fuel` drops with every instruction and traps at 0; `call_depth`
/// stays within `MAX_CALL_DEPTH`.
pub struct Instance<'m> {
    module: &'m Module,
    memory: Vec<u8>,
    mem_max_bytes: usize,
    globals: Vec<Value>,
    fuel: u64,
    call_depth: usize,
}

struct Frame {
    locals: Vec<Value>,
    func_idx: u32,
}

/// `height` is the value stack height on entering the block. A branch cuts the stack back to it, so
/// values the block pushed do not leak. A loop's target is its own start, hence `is_loop`.
struct Label {
    /// Values kept when branching to this label.
    arity: u32,
    /// Values the block leaves when it reaches end normally.
    end_arity: u32,
    height: usize,
    target: usize,
    is_loop: bool,
}

/// Allocations reclaimed from an instance; only the memory and globals buffers are reused. Their
/// contents are reset when an instance is built, so values from one call never reach the next.
#[derive(Default)]
pub struct InstanceState {
    memory: Vec<u8>,
    globals: Vec<Value>,
}

impl InstanceState {
    /// A state that grew too large is dropped instead of pooled.
    pub fn memory_capacity(&self) -> usize {
        self.memory.capacity()
    }
}

impl<'m> Instance<'m> {
    #[cfg(test)]
    pub fn instantiate(
        module: &'m Module,
        fuel: u64,
        mem_max_bytes: usize,
    ) -> Result<Self, String> {
        Self::instantiate_with(module, fuel, mem_max_bytes, InstanceState::default())
    }

    /// Builds an instance on a reused state: memory is zeroed, data segments loaded, and globals
    /// reset, so reuse leaves no trace of earlier calls. Fails if the initial memory exceeds
    /// `mem_max_bytes`.
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

    pub fn into_state(self) -> InstanceState {
        InstanceState {
            memory: self.memory,
            globals: self.globals,
        }
    }

    /// The address comes from the guest and is untrusted: the addition is checked for overflow
    /// before the range.
    pub fn write_mem(&mut self, addr: usize, data: &[u8]) -> Result<(), String> {
        let end = addr.checked_add(data.len()).ok_or("Address overflowed")?;
        if end > self.memory.len() {
            return Err("Memory write out of bounds".into());
        }
        self.memory[addr..end].copy_from_slice(data);
        Ok(())
    }

    /// Same range checks as `write_mem`.
    pub fn read_mem(&self, addr: usize, len: usize) -> Result<&[u8], String> {
        let end = addr
            .checked_add(len)
            .ok_or("Memory read address overflowed")?;
        self.memory
            .get(addr..end)
            .ok_or("Memory read out of bounds".into())
    }

    pub fn export_func(&self, name: &str) -> Option<u32> {
        match self.module.exports.get(name) {
            Some((ExportKind::Func, idx)) => Some(*idx),
            _ => None,
        }
    }

    /// 0 means the call trapped on an exhausted budget.
    pub fn fuel_remaining(&self) -> u64 {
        self.fuel
    }

    pub fn call_export(&mut self, name: &str, args: Vec<Value>) -> Result<Vec<Value>, String> {
        let idx = self
            .export_func(name)
            .ok_or(format!("Exported function '{name}' not found"))?;
        self.invoke(idx, args)
    }

    /// Imports are refused at load, so a function index is an index into the local functions.
    fn func(&self, idx: u32) -> Result<&'m Func, String> {
        self.module
            .funcs
            .get(idx as usize)
            .ok_or("WASM function index is out of range".into())
    }

    fn ftype(&self, idx: u32) -> Result<&'m FuncType, String> {
        let f = self.func(idx)?;
        self.module
            .types
            .get(f.type_idx as usize)
            .ok_or("WASM type index is out of range".into())
    }

    /// Checks the depth limit first: the interpreter recurses, so this is the only guard against
    /// host stack overflow.
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

    /// Value and label stacks are separate. A label keeps the stack height at block entry, and a
    /// branch cuts back to it so the block's values do not leak. Fuel is checked on every
    /// instruction, so no starting point can exceed the budget.
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

    /// Branches out `depth` labels: sets aside the label's arity values, cuts the stack to the
    /// label's height, then puts them back; without that, intermediate values from inside the block
    /// leak out. A loop label stays, since the branch returns to it. Returns the next instruction
    /// index.
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

    /// The address is computed by the guest. Every width checks overflow and range and traps; a
    /// missed check would let the guest read host memory.
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

    /// Same range checks as `exec_load`.
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

/// Traps when the stack is empty or the type differs.
fn pop_i32(s: &mut Vec<Value>) -> Result<i32, String> {
    s.pop()
        .ok_or("Stack underflow".into())
        .and_then(Value::as_i32)
}
fn pop_i64(s: &mut Vec<Value>) -> Result<i64, String> {
    s.pop()
        .ok_or("Stack underflow".into())
        .and_then(Value::as_i64)
}

/// Division by zero and overflow such as i32::MIN / -1 trap as the spec requires. Rust's plain
/// division panics there, so they are filtered first.
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
mod tests {
    use super::*;

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

    /// Minimal module with exactly `instructions` NOPs.
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

    fn run_eval(wat: &str, args: &[Value]) -> Result<Vec<Value>, String> {
        let wasm = wat::parse_str(wat).unwrap();
        let m = Module::parse(&wasm)?;
        let mut inst = Instance::instantiate(&m, 1_000_000, 16 * 1024 * 1024)?;
        inst.call_export("f", args.to_vec())
    }

    #[test]
    /// Duplicate standard sections, unknown IDs, and leftover payload are not accepted silently.
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
    /// Export, start, and reserved fields must match existing definitions.
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
    /// One-byte instructions cannot blow up into a large enum vector after decoding.
    fn decoded_instruction_count_is_bounded() {
        assert!(Module::parse(&nop_module(MAX_DECODED_INSTRUCTIONS - 1)).is_ok());
        assert!(Module::parse(&nop_module(MAX_DECODED_INSTRUCTIONS)).is_err());
    }

    #[test]
    /// Imports that cannot run are not loaded for compatibility's sake.
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
    /// The host value stack outside linear memory has a per-call cap too.
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
    /// The locals vector, copied on every recursive call, stays small per function.
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
    fn arithmetic_and_compare() {
        let wat = r#"(module (func (export "f") (param i32 i32) (result i32)
            (i32.add (local.get 0) (i32.mul (local.get 1) (i32.const 3)))))"#;
        assert_eq!(
            run_eval(wat, &[Value::I32(10), Value::I32(4)]).unwrap(),
            vec![Value::I32(22)]
        );
    }

    #[test]
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
    /// A loop keeps its branch arity apart from its result arity at end.
    fn loop_result_arity_is_checked_at_end() {
        let wat = r#"(module (func (export "f") (result i32)
            (loop (result i32) (i32.const 7))))"#;
        assert_eq!(run_eval(wat, &[]).unwrap(), vec![Value::I32(7)]);
    }

    #[test]
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
    fn fuel_exhaustion_traps() {
        let wat = r#"(module (func (export "f") (result i32)
            (loop $l (br $l)) (i32.const 1)))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let m = Module::parse(&wasm).unwrap();
        let mut inst = Instance::instantiate(&m, 10_000, 1024 * 1024).unwrap();
        assert!(inst.call_export("f", vec![]).is_err());
    }

    #[test]
    /// A panic here would let one query take down the server.
    fn load_at_overflowing_address_traps_not_panics() {
        let wat = r#"(module (memory 1) (func (export "f") (result i32)
            (i32.load (i32.const -1))))"#;
        assert!(run_eval(wat, &[]).is_err());
    }

    #[test]
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
    /// call_indirect does not run a function of another type that only has the same parameter
    /// count.
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
    /// The one overflow of signed division traps instead of returning a value.
    fn signed_division_overflow_traps() {
        let i32_wat = r#"(module (func (export "f") (result i32)
            (i32.div_s (i32.const -2147483648) (i32.const -1))))"#;
        let i64_wat = r#"(module (func (export "f") (result i64)
            (i64.div_s (i64.const -9223372036854775808) (i64.const -1))))"#;
        assert!(run_eval(i32_wat, &[]).is_err());
        assert!(run_eval(i64_wat, &[]).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        assert!(Module::parse(b"not wasm at all").is_err());
    }
}
