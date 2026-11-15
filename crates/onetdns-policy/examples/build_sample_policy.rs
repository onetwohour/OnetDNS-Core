const WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $p))
  (func (export "evaluate")
    (param $qptr i32) (param $qlen i32) (param $qtype i32) (param $cptr i32) (param $clen i32)
    (result i32)
    ;; qname 첫 글자 'x' → Block(2)
    (if (result i32)
        (i32.and (i32.gt_s (local.get $qlen) (i32.const 0))
                 (i32.eq (i32.load8_u (local.get $qptr)) (i32.const 120)))
      (then (i32.const 2))
      (else
        ;; qtype == HTTPS(65) → Refuse(3)
        (if (result i32) (i32.eq (local.get $qtype) (i32.const 65))
          (then (i32.const 3))
          (else (i32.const 0)))))))
"#;

/// Builds the sample policy plugin.
fn main() {
    let wasm = wat::parse_str(WAT).expect("WAT 컴파일");
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sample_policy.wasm".to_string());
    std::fs::write(&out, &wasm).expect("wasm 쓰기");
    eprintln!("wrote {out} ({} bytes)", wasm.len());
}
