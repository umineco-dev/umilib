# The C ABI and bindings

## One source of truth

Every exported function is written once, in Rust, inside
`umilib::ffi_functions! { ... }`. The macro exports the function unmangled and
records its name, documentation, parameter types and return type in a constant
(`FUNCTIONS`, or a name given as `const NAME;`). Parameter types come from the
`ffi::Value` trait, so a description cannot disagree with the real signature.

Each module of `src/ffi` declares `pub const MODULE: Module` with its
definitions (opaque types, structures, callbacks) and functions; modules list
their children. `ffi::Manifest::ROOT` is the root. From it:

- `ffi::CHeader::generate` renders `include/`; `tests/ffi` fails when the
  committed headers differ (`UMILIB_BLESS=1` rewrites them, and removes stale
  headers when every feature is enabled);
- `ffi::Manifest::json` renders the JSON returned by `umilib_ffi_manifest`,
  which `port/python/umilib/ffi` uses to declare every function for ctypes.

Several `ffi_functions!` blocks in one module are combined with
`Function::concat`. Functions generated per integer type are written by small
`macro_rules!` that call `ffi_functions!`, because `macro_rules!` cannot
concatenate identifiers and umilib has no procedural macros.

When one function set is exported for many types, `umilib::ffi_exports!`
names each C symbol with an expression instead of the Rust identifier:
`#[unsafe(export_name = concat!(prefix, "_update"))]` is a documented form of
attribute (a key-value attribute whose value is a macro that expands to a
literal), so a macro can build the symbol and its manifest entry from one
prefix. The Rust functions then only need unique names in their module, so
each exported type has its own small module (`ffi::hash::sha::v2::sha256`).
`ffi_digest!`, `ffi_extendable_output!` and `ffi_xof_reader!` export the
functions every hash type shares with it.

Types generic over another type, such as `HMAC<H>`, are exported once: an
enum in `src/ffi` holds one variant per hash function, generated from the
registry `ffi_digest_algorithms!` (feature, variant, Rust path and C type
name per line, each variant behind the cfg of its feature), and C selects the
variant by the C type name of the hash type. A new hash function is added to
that registry once. The generic C ABI is gated on at least one hash function
being enabled, because the enum would otherwise have no variant.

Structures may have fixed-size array fields (`Type::Array`, from
`[T; N]: Value`), rendered as `uint8_t salt[16]` and as ctypes arrays in
Python; `tests/ffi` checks that arrays appear only as structure fields,
because C passes array parameters as pointers. A Rust structure passed to C
by value or through a pointer is `#[repr(C)]` (`BLAKE2bParameters`,
`DRBGConfig`).

## Naming

Functions are `umilib_<path>_<type>_<method>`; types are `umilib_<path>_<RustType>`.
Function names are lowercase and type names start with a capital after the
prefix, so they never collide (an earlier scheme named both in `snake_case`,
and `Bench::config` collided with `BenchConfig`; `tests/ffi` checks this now).

## Safety

`ffi::Pointer` converts C pointers to references, rejecting null and lengths
that do not fit in `isize`. It cannot check other validity, which is the C
caller's contract (documented in `docs/ffi.md`). Rules learned while building it:

- Check `out` pointers before mutating state, so that a null `out` never leaves
  an operation half done (a reader must not consume input it cannot return).
- Allocate handles only after checking `out` (`Pointer::write_handle`), so that
  a null `out` does not leak.
- `ffi::Buffer` frees its bytes when dropped, so a value that cannot be written
  to a null `out` is not leaked; writing into an `out` buffer never drops the
  previous contents, which are caller memory.
- Never create a `&mut` and a `&` (or two `&mut`) over memory the caller may
  pass twice. Writers copy input that lies in their own storage first
  (`WriterStorage`), because writing may reallocate or overwrite it; functions
  that take several pointers to memory they write accept identical or disjoint
  ranges and work through raw pointer reads and writes, rejecting partial
  overlaps.
- A function that reads caller memory and writes outputs in place starts with
  `Pointer::check_ranges(inputs, outputs)`, its ranges built by
  `Pointer::range(pointer, count)`, before it creates any reference over the
  inputs. Inputs are the byte and array ranges and the structures read
  through a pointer (a pointer array of `Pointer::strings` or
  `Pointer::slices` counts, the strings it points to do not); outputs are
  the integers, `bool`s, structures, `*const Status` and arrays the function
  writes or updates in place (an `InternetChecksum`, `IPv4Options`). Any shared
  byte fails with `InvalidArgument`, an identical pointer included, because
  two values in one place cannot both be the result. A function with two such
  outputs and no input checks them the same way (`Pointer::write_optional`
  does it for its pair). `Pointer::range` makes a null pointer an empty range,
  so that the conversion that follows still reports `NullPointer`.
- Left out of those ranges: `*mut Buffer` and handle outputs (`*mut *mut T`),
  written last from owned values once the inputs are no longer read, so an
  overlap neither changes what is read nor aliases a live reference; handles
  (`*const T`/`*mut T` of an opaque type), whose memory Rust allocated and
  the caller cannot place an input in without breaking the contract, and
  whose heap parts no range would cover; NUL-terminated strings, whose
  length is unknown until they are read; `void*` callback contexts.
- The protocol modules had no such check at first, although `docs/ffi.md`
  promised it; review of the mail protocols found it, and the
  check was added to every protocol function in one pass, from a list made
  by reading each signature (a pointer followed by a `usize` is a range of
  that many elements, a structure pointer one element, unless the body
  slices it by a count). Outputs of a fixed number of bytes (`out: *mut u8`
  of 4, 6 or 16) take that count by hand, which the list could not see. The
  shared helpers (`FFIHTTPConnection`) check for every HTTP version. Checking
  only where a reference is still alive at the write was not chosen: it
  depends on the body's order, which changes without anyone rereading the
  signature.
- Allocate with `try_reserve` where the size comes from the caller, so that an
  impossible request returns a status instead of aborting (a panic in an
  `extern "C"` function aborts the process).
- A C callback that fails is turned into a Rust panic only where the panic is
  caught (the fuzzer); `extern "C"` functions abort on panic.

## Generic types

A Rust type generic over a primitive is exported once, with an enum over its
instances behind the handle, chosen by the C type name of the parameter:

- `ffi_digest_algorithms!` and `ffi_block_ciphers!` are the registries: a
  callback macro receives one line per algorithm (`"feature" Variant =>
  path, "C name";`), each behind the cfg of its feature. `BlockCipher128`
  and `BlockCipher64` (with `BlockCipherChoice`) implement `BlockCipher` by
  delegation, so the modes are instantiated once per block size, not once
  per cipher. Types that need `KeyInit` of their cipher (GCM-SIV, CTR_DRBG)
  are enums over the concrete ciphers instead.
- `ffi_aead_enum!`, `ffi_mac_enum!` and `ffi_prf_enum!` build the enums over
  sizes (GCM tags, AEGIS degrees) or PRFs (HMAC of each hash, CMAC of each
  block size) and implement `AEADState`, `MACState` or the listed methods;
  `ffi_aead!`, `ffi_mac!` and `ffi_stream_cipher!` export the shared
  functions.
- An FFI module exists whenever its feature is enabled, even if its
  registry is empty (for example `ffi crypto-hmac` without a hash
  function): its constructors then fail with `InvalidArgument`. The macros
  carry `#[allow(unused_variables)]` for that case, and methods that consume
  or clone a state are written inside the macros (as `HMACState::verify`),
  because code after an expression of an empty enum type is unreachable and
  warns.
- Variant names cannot be concatenated in `macro_rules!`, and a repetition
  of the registry cannot be nested in a repetition of methods. `ffi_prf_enum!`
  passes the registry as one `{ ... }` token tree to an internal rule for
  each method, and passes `self` along, because each expansion has its own
  hygiene for it.

The public-key schemes are generic over curves, groups and hash functions
whose product is too large for enums, and their keys are byte encodings, so
they are exported through visitors instead:

- `KeyAgreementCall` and `SignatureSchemeCall` are traits with a generic
  `call<S>`; each operation is a struct implementing them (`KeyAgreementAgree`,
  `SignatureSchemeSign`, ...). A module defines `fn scheme<V>(names, call)`,
  which matches the C type names against its registries
  (`ffi_weierstrass_curves!`, `ffi_gost_curves!`, `ffi_standard_digests!`,
  `ffi_pairing_curves!`) and calls `call::<Scheme<C, H>>()`;
  `ffi_key_agreement!`, `ffi_signature_scheme!` and
  `ffi_identity_based_signature!` export the functions over it. The same
  shape serves the schemes that do not implement those traits (`RSACall`,
  `DSACall`, `ECCSICall`, `HPKECall` with `HPKESuite`, `SRPCall`).
- Stateful objects of a generic type (the contexts of HPKE, the peers of
  Dragonfly, the parties of SRP, the keys of the identity-based signatures)
  are `Box<dyn Trait>` behind the handle (`HPKESenderState`,
  `DragonflyState`, ...), implemented by the generic Rust type for every
  instance; `Value` is implemented for the box, which names the C type. The
  handle is a pointer to the box, freed by `Pointer::free`.
- Every function that writes through a pointer starts with
  `Pointer::check_ranges(inputs, outputs)`, listing every range it reads
  (names and generator type names included) and every range it writes, so
  that no `&mut [u8]` is created over memory a `&[u8]` or `&str` covers.
  Outputs that are `Buffer`s are written last and need no check.
- Each export keeps the symmetry of its trait: whatever Rust parses with
  validation (`private_key_from_bytes`, `verifying_key_from_bytes`,
  `deserialize_public_key`) has a `_check_*` function, so that bindings
  validate without computing more than Rust does, and whatever a binding
  needs to size its output by the parameters a Rust type takes has a sizes
  function of those parameters alone (`_sizes`, `_kms_sizes`); variable
  outputs are `Buffer`s instead.

Every function of a module must be listed in its `MODULE` (usually through
`Function::concat` of the constants that `ffi_functions!`, `ffi_exports!` and
the export macros define). A function that is exported but not listed is
missing from the headers and from Python, and the Rust tests do not notice:
`tools/check_ffi.py` compares the exported symbols with the manifest.

## Statuses

A status is a static `ffi::Status` with `domain` (the module path joined by
`.`, which is also the Python module), `name` (the Rust variant) and `message`.
Each module defines its statuses as constants of a `<Module>Status` type and
implements `ffi::ToStatus` for its error type. Variant fields are not carried,
so messages are static.

## Python

`umilib.ffi.Library` loads the library, reads the manifest and declares every
function with ctypes (all pointers as `c_void_p`, structures and callbacks
from the manifest definitions). Each Python module registers its exception
class for its domain with `Library.register_error`. `umilib.ffi.Handle` owns
an opaque handle and frees it with the type's `FREE` function.

Python mirrors every public Rust item with the same name. Logic always runs in
Rust through the C ABI; Python implements only data containers (such as
`Throughput` or `Corpus.inputs`) and conversions dictated by the language (see
`docs/python.md`). Another language is added as `port/<language>/` on the same
manifest.

## Contexts of Python callbacks

A Python binding keeps the ctypes objects of a callback alive in a
dictionary keyed by the context integer it gives C, until C calls the drop
callback. The keys come from one `itertools.count()` shared by every
handle that shares the dictionary (an executor and its clones, a pool and
its spawners). A counter per handle, or `key = next_key; next_key += 1`
(not atomic across threads), gave two tasks one key: the second entry
replaced the first, whose callbacks were then collected while C could
still call them, and the interpreter crashed
(`test_tasks_spawned_through_clones_keep_their_callbacks`).
