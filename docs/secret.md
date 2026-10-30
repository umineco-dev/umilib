# `umilib::secret`

Handling of secret values. Feature: `secret`.

| Item | Purpose |
| --- | --- |
| `Choice` | A secret boolean (`0` or `1`) combined with `&`, `\|`, `^`, `!` without branching. `into_bool` reveals it. |
| `ConstantTimeEq` | `ct_eq`/`ct_ne` in time that depends only on the lengths (lengths are public). |
| `ConditionallySelectable` | `select`, `conditional_assign`, `conditional_swap` without branching. |
| `Zeroize` | Overwrites memory with zeros in a way the compiler does not remove; `Vec<u8>` and `String` also zero their unused capacity. |
| `Secret<T>` | Owns a value, zeroizes it when dropped, prints as `Secret(..)`, and is only reached through `expose`/`expose_mut`. |
| `ConstantTimeTable<WORDS, BITS>` | A table of entries of 1 to 32 bits whose reads and writes take the same time for every index: each touches every word of the table. |
| `DataIndependentTiming` | A guard that keeps the processor in its data-independent timing mode for the current thread while it lives. |

```rust
use umilib::secret::{ConstantTimeEq, Secret};

let key = Secret::new([0x42u8; 32]);
let received = [0x42u8; 32];
if key.expose().ct_eq(&received).into_bool() {
    // authenticated
}
```

Rust does not guarantee constant-time code generation. umilib uses masks
instead of branches and passes every `Choice` through `core::hint::black_box`,
which prevents the known optimizations that reintroduce branches, but does not
make a formal guarantee. See `.docs/constant-time.md`.

Some processors take time that depends on the values they compute with even
without branches: Arm processors with FEAT_DIT, Apple silicon among them,
unless `PSTATE.DIT` is set (measured: a 256-bit division took from 218 to 673
µs depending on the values without it, and the same time with it), and Intel
processors unless the operating system sets DOITM. `DataIndependentTiming::enable()`
sets `PSTATE.DIT` until the guard is dropped, restoring the previous state,
so guards nest. It works on targets compiled with the `dit` target feature
(`DataIndependentTiming::AVAILABLE`), which the `aarch64-apple-*` targets
enable by default; elsewhere it does nothing, and so it does under Miri,
which cannot run the instructions. Setting the mode costs about
40 ns, so long constant-time operations (big integer division, modular
exponentiation and inversion) take a guard themselves, and code made of many
short ones should hold one guard around the whole computation:

```rust
use umilib::secret::DataIndependentTiming;

let _timing = DataIndependentTiming::enable();
// ... constant-time computation on secrets ...
```

`ConstantTimeTable::from_bytes(&SBOX)` (or `from_entries`) builds a table in
a constant, and a mismatch of its length or of an entry fails the
compilation; `get(index)` and `set(index, value)` take the index modulo the
number of entries, a power of two. The block ciphers defined by S-boxes use
it, so that no memory access depends on secret data; a lookup costs a mask
for each word of the table. The C ABI and Python export
`ConstantTimeTable<32, 8>` (256 bytes, the size of an S-box) as
`ConstantTimeTable32_8`.

The guard cannot move to another thread, because the mode belongs to the
thread. In C, release it with `umilib_secret_data_independent_timing_free` on
the thread that created it; in Python, use `with DataIndependentTiming():`.
