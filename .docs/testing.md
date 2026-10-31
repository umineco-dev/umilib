# Testing

## Rules for automated tests

- Tests check conformance to specifications (RFCs, FIPS, ...), not the current
  behaviour. When a test and the implementation disagree, the specification
  decides; a test is never changed to match the code without checking the
  specification. Expected values come from the specification's own test
  vectors or are derived from its definitions, never from running the code.
- Check every requirement, not only MUSTs: error cases, limits, encodings.
- Test vectors are stored in `tests/vectors/<module path>/` with their source.

## Suites

| Command | Checks |
| --- | --- |
| `cargo test --all-features` | integration tests (`tests/`), corpus replay and a deterministic fuzzing pass (`fuzz/`), doc tests |
| `python3 tools/check_features.py` | every feature compiles alone |
| `cargo +nightly miri test --all-features --test bytes --test secret --test ffi --test platform --test runtime -- --test-threads=1` (with `MIRIFLAGS=-Zmiri-disable-isolation`) | undefined behaviour and leaks in `unsafe` code. One test at a time: Miri runs every thread on one core, so tests run together take each other's time from the limits some check. `--test ffi` takes about an hour under Miri (the cryptography tests): run the part a change touches with a filter (`-- protocol::http::`, `-- codec::`). Tests too slow for Miri use fewer vectors under `cfg!(miri)`, or are ignored under it with the reason (`#[cfg_attr(miri, ignore = "...")]`), as are tests of system calls Miri does not emulate (`sendto`, `if_nametoindex`, some socket options, `SOCK_SEQPACKET` pairs, child processes, `ioctl` on files such as `/dev/net/tun`). Run the platform part for Linux, as CI does (`--target x86_64-unknown-linux-gnu`; Miri interprets the target): on macOS, Miri does not support some `fcntl` commands |
| `python3 tools/check_ffi.py` | the exported functions are exactly those of the manifest, the C headers compile and the C tests pass (clang, `-std=c99 -pedantic -Werror`), and the Python tests pass |
| `cargo test --release --all-features --test crypto -- --ignored` | the vectors that need minutes or a gibibyte (PBKDF2 with 2^24 iterations, scrypt with N = 2^20, Argon2 with 1 GiB) |
| `cargo bench --all-features -- --quick` | the benchmarks run |
| `python3 tools/fuzz.py <target> --sanitizer address` | libFuzzer with AddressSanitizer |
| `cargo build --no-default-features --features <non-platform features> --target thumbv7em-none-eabihf` | the `no_std` part builds for bare metal |
| `docker run --rm -v "$PWD":/work -w /work -e CARGO_TARGET_DIR=/work/target/docker-linux rust:1-bookworm cargo test --features "platform crypto-random" --test platform` (also with `--platform linux/amd64`, `linux/386`, `linux/arm/v7`) | the Linux layer (epoll, eventfd, `getrandom`, packet sockets) on Linux; see [platform.md](platform.md) |
| `cargo run --release --features platform-runtime --example echo -- server 127.0.0.1:7000 [--workers 4 --threads 2]` and `... -- client 127.0.0.1:7000 --connections 200 --messages 2000 --size 512` | manual load test of the platform runtime: the client (blocking std sockets on threads of its own) checks every byte echoed and reports round trips per second and latency percentiles; run it with large messages (`--size 65536`), many connections (`--connections 1000`), and `kill -9` of a worker under load (the supervisor starts it again), on macOS and in the Linux containers |
| `cargo check --features platform-native --target <target>` for the Windows and Android targets | the Windows and Android layers compile (they run in CI) |
| `docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD":/work -w /work -e CARGO_TARGET_DIR=/work/target/docker-linux rust:1-bookworm sh examples/tun.sh` | the IP, ICMP, UDP and TCP layers against the Linux kernel over a TUN interface: ping (IPv4, IPv6, at the MTU with DF), UDP echoes, TCP echoes of 1 MiB (one, eight at once, and over netem loss, delay and reordering), a refused connection, and a connection the example opens to the kernel; each check prints `ok` or `FAILED` |
| `OPENSSL=... CURL=... sh examples/http.sh` (a curl with HTTP/2 and HTTP/3, OpenSSL to convert the test certificates) | HTTP against other implementations: curl over HTTP/1.1, HTTP/2 (prior knowledge and ALPN) and HTTP/3, content of megabytes, gzip, keep-alive, parallel streams; Python's `http.client`, a WebSocket client of Python's standard library, Python's `http.server` as the server of umilib's client; umilib's client and server together over every version, WebSocket included. Then open `http://127.0.0.1:PORT/ws.html` of `http server PORT` in a browser: the page's WebSocket must echo and close with 1000 |
| `OPENSSL=... CURL=... sh examples/tls.sh` | TLS 1.3 and 1.2 against OpenSSL (`s_client`, `s_server`, ECH) and curl, both ways |
| `OPENSSL=... CURL=... sh examples/quic.sh` | QUIC v1 and v2 against itself, OpenSSL's QUIC client and curl's (ngtcp2): handshakes, streams, Retry, version negotiation |
| `DOCKER=... sh examples/dns.sh` | DNS against dig, BIND (dig, delv), Knot (kdig) and Unbound in Docker, over UDP, TCP, TLS, HTTPS and QUIC, with DNSSEC validation |
| `docker run --rm --privileged ... sh examples/dhcp.sh` (see the script) | DHCPv4 and DHCPv6 against ISC dhclient, BusyBox udhcpc and dnsmasq between two network namespaces |
| `DOCKER=... sh examples/coap.sh` | CoAP against libcoap's client and server in Docker, and itself |
| `DOCKER=... sh examples/mail.sh` | SMTP, POP3 and IMAP against themselves, curl, Python's smtplib, poplib and imaplib, and Postfix and Dovecot in Docker |
| `DOCKER=... sh examples/ftp.sh` | FTP against itself, curl, Python's ftplib and vsftpd in Docker |
| `DOCKER=... sh examples/integrated.sh` | OAuth integrated with HTTP and mail: an authorization server, an API and SMTP, IMAP and POP3 with OAUTHBEARER in two worker processes, against curl, Python's standard library (the code flow with PKCE, the mail clients) and this crate's client (device grant, DPoP, introspection); then this crate's client against Keycloak in Docker |
| `cargo +nightly miri test --target i686-unknown-linux-gnu --features "math ffi" --test math --test ffi` | the 32-bit limb code of `math` (Miri interprets the target; the tests use fewer iterations under `cfg!(miri)`) |
| `python3 tools/math_vectors.py` | regenerates `tests/vectors/math/python.txt`, results of Python integers used as an independent oracle |
| `python3 tools/xxhash_vectors.py path/to/xxhash.h` | regenerates `tests/vectors/hash/xxhash/xxhash.txt` by compiling the reference `xxhash.h` (BSD 2-Clause, not stored in the repository) with clang; the test files of the xxHash repository are GPL-2.0 and are not used |
| `python3 tools/dh_vectors.py` | regenerates `tests/vectors/crypto/dh/python.txt`, Diffie–Hellman exchanges in the groups of RFC 7919 and RFC 3526 computed with Python integers |
| `python3 tools/crc_catalogue.py` | regenerates `src/hash/crc/catalogue.rs` and the catalogue of the Python `CRCCatalogue` from `tests/vectors/hash/crc/catalogue.txt` |

Vectors taken from the text of a specification (RFC appendices, drafts,
PDFs of standards) are stored either in the `Key = Value` record format of
the CAVP files or as the text of the document itself, which the test parses
(RFC 6979, RFC 7748, RFC 8032, RFC 9180, ...), next to a `SOURCE` file that
names the document, its license and how the values are used, so that a
mistake in the extraction can be traced. A parser of a document skips its
page breaks and asserts the number of vectors it finds.
Tables of a specification (S-boxes, constants) are checked against it in the
tests as well, since a mistyped entry only changes some outputs.

Oracles must not share code with what they check: the math tests compare
against `u128`, against Python integers (in the Python tests and through the
generated vectors) and against the constants of specifications, never only
against other umilib functions.

The checks every elliptic curve must pass (group laws, the order of the
generator, SEC 1 and RFC 8032 encodings and their rejections) are in
`tests/common/ec.rs`, shared by the `math` and `crypto` test crates; the
curves of `math` are defined in the test from their specifications, those
of `crypto::curve` are the library's. Schemes without published test vectors
(Dragonfly of RFC 7664, the identity-based signatures of Hess and of Cha and
Cheon) are tested against the equations that define them and the
rejections they require. SM9 is tested against GM/T 0044.5-2016 annexes A
to D, stored as the text layer of the PDF, which loses the mathematical
symbols: `GMT` of `tests/common/vectors.rs` (and of `port/python/tests/vectors.py`)
finds each value by the English text before it, within a section of the
annex, and skips the page breaks of the extraction, whose page numbers are
hexadecimal digits. A value ends at a word that is not hexadecimal, so a
section must end before a word such as "b)" that is: cut it with `section`.
Annex B prints ID || hid with hid 02 in its steps A1 and B1 but computes
with 03, the identifier of its encryption keys (see
`tests/vectors/crypto/sm9/SOURCE`); the tests use 03.

The post-quantum schemes are tested against the ACVP vectors of NIST (the
`internalProjection.json` files of usnistgov/ACVP-Server, which hold the
expected results) and Project Wycheproof. The ACVP files of signature
generation and verification of ML-DSA and SLH-DSA are tens of megabytes;
the repository keeps subsets made by the scripts their `SOURCE` describes
(a few tests of every group, every interface and every reason of failure
kept), as the license of NIST asks a modified file to say. RFC 10024 gives
no vectors: its hybrids are tested against the sizes of its tables and
against ML-KEM and ECDH separately. SLH-DSA tests sign only with the fast
(`f`) parameter sets outside the ACVP vectors: the small ones take hundreds
of milliseconds per signature.

The C ABI of the public-key schemes is tested through the functions C calls
(`tests/ffi/crypto/`): every Wycheproof file of ECDH, ECDSA, EdDSA, DSA and
RSA, all of RFC 9180, RFC 6507 and RFC 5054, and the schemes whose test
vectors use curves outside the registries (GOST R 34.10 and SM2, whose
examples use test curves) against the Rust API, which signs
deterministically. The Python tests run one file of each family, because the
Python tests load the unoptimized library; they check the classes of
Python, not the algorithms again.

Integration tests are one crate per top-level module (`tests/<module>/main.rs`)
with submodules mirroring the module tree; `autotests` and `autobenches` are
disabled, so every target is declared in `Cargo.toml` with its
`required-features`.

## Manual testing

Each phase of work ends with a manual review in three steps:

1. look for as many problems as possible (read the code, run it on several
   platforms and in containers, fuzz it, compare it with other implementations);
2. write down every candidate problem with how it was found;
3. verify each candidate (read the code paths, reproduce it, read the
   specification) before fixing it.

Lessons so far:

- Miri: tests that pass a pointer to C and keep using the original reference,
  or call `as_mut_ptr` twice on one array, break the aliasing rules (take one
  raw pointer and reuse it); every `umilib_ffi_Buffer` written by a call must
  be freed before the variable is reused. An object that keeps a `&mut` to
  caller memory must never see a reference created from another pointer to
  that memory (see the writer functions in `src/ffi/bytes`).
- Miri found, once its CI job could finish: a test passing a one-byte output
  to a function that writes four (the C ABI tests, which then corrupted the
  test harness under qemu), a `syscall` given a `usize` where the prototype
  has `unsigned int` (a mismatched variadic argument), and a lost wakeup of
  the thread pool that its timing makes common. A Miri job that never ends
  hides all of this: when one test is slow, measure every test under Miri
  (each in its own process, with a time limit) rather than one at a time.
- Tests that check a time limit or an order of events in real time break
  under Miri, which is thousands of times slower: wait on the condition
  itself, with a deadline only to turn a hang into a failure.
- An independent review (a second reader who does not know the author's
  reasoning) found memory-safety bugs that every automated suite missed:
  self-aliasing inputs, allocation sizes from the caller, and Python views
  that outlive their owner. Review every phase this way.
- Exercise every mode of external tools: libFuzzer's `-merge` re-executes the
  program, which first failed because the harness did not support it.
