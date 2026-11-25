;; lenprefix8: the reviewed library module that writes each input after its length in one
;; byte (len·a·len·b·…), the framing some login scripts build before they encrypt. An input
;; of more than 255 bytes traps. Entry: `run`.
;;
;; The file next to this one (lenprefix8.wasm) is this text compiled by the `wat` crate; a test
;; of the sandbox crate compiles the text again and checks that the bytes are the same.
(module
  (import "credentials" "input_count" (func $input_count (result i32)))
  (import "credentials" "input_len" (func $input_len (param i32) (result i32)))
  (import "credentials" "input_read" (func $input_read (param i32 i32)))
  (import "credentials" "output" (func $output (param i32 i32)))
  (memory (export "memory") 1)

  ;; Grows the memory so that `end` bytes fit; traps when it cannot.
  (func $reserve (param $end i32)
    (local $have i32)
    (local.set $have (i32.mul (memory.size) (i32.const 65536)))
    (if (i32.gt_u (local.get $end) (local.get $have))
      (then
        (if (i32.eq
              (memory.grow
                (i32.div_u
                  (i32.add (i32.sub (local.get $end) (local.get $have)) (i32.const 65535))
                  (i32.const 65536)))
              (i32.const -1))
          (then (unreachable))))))

  (func (export "run")
    (local $i i32)
    (local $n i32)
    (local $len i32)
    (local $at i32)
    (local.set $n (call $input_count))
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
        (local.set $len (call $input_len (local.get $i)))
        (if (i32.gt_u (local.get $len) (i32.const 255)) (then (unreachable)))
        (call $reserve (i32.add (i32.add (local.get $at) (i32.const 1)) (local.get $len)))
        (i32.store8 (local.get $at) (local.get $len))
        (call $input_read (local.get $i) (i32.add (local.get $at) (i32.const 1)))
        (local.set $at (i32.add (i32.add (local.get $at) (i32.const 1)) (local.get $len)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (call $output (i32.const 0) (local.get $at))))
