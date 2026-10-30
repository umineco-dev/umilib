# Continuous integration and releases

Workflows are in `.github/workflows/`.

| Workflow | Trigger | Does |
| --- | --- | --- |
| `test.yml` | every push; called by the others | formatting, clippy, docs, tests on Linux/macOS/Windows with stable and the minimum supported Rust (1.88), tests under qemu on i686/armv7/aarch64/riscv64/s390x (s390x is big-endian), builds for Android/iOS/Tier 3 targets, `no_std` builds, every feature alone, Miri, the C ABI and the Python tests |
| `pull_request.yml` | pull request opened, updated or reopened | after a member approves: `test.yml` and debug builds of the libraries, uploaded as artifacts |
| `release.yml` | a pushed tag `v<semver>` or a published release | version update, tests, builds, publication |
| `fuzz.yml` | weekly and on demand | libFuzzer with AddressSanitizer for every target |
| `bench.yml` | on demand | benchmarks on every platform |

## Approval of pull requests

The first job of `pull_request.yml` runs in the `pull-request` environment.
Create it in **Settings → Environments → New environment** with the name
`pull-request`, enable **Required reviewers** and add the members (or teams)
who may approve. Every pull request run then waits for one of them to approve
under **Review deployments**.

## Releases

Create a tag such as `v1.2.3` (or publish a release with a new tag). The release workflow then:

1. on the tagged commit, sets `version` in `Cargo.toml` to `1.2.3` and in
   `port/python/pyproject.toml` to its PEP 440 form (`1.2.3-rc.1` becomes
   `1.2.3rc1`; only `alpha.N`, `beta.N` and `rc.N` pre-releases are accepted),
   updates `Cargo.lock` and `port/python/uv.lock`, and commits the change with
   the date of the tagged commit, so that every run for the tag produces the
   same commit. The commit is pushed to the default branch if the tag is its
   head, and to the branch `release/<tag>` otherwise. The tag is not moved; the
   published packages are built from this commit, so they contain exactly the
   tagged code with the new version. If the default branch is protected, allow
   `github-actions[bot]` to push to it. When the release is already complete
   (both triggers fire for a release created with a new tag), the run stops here;
2. runs `test.yml` on that commit;
3. builds `umilib-<tag>-<arch>-<platform>.tar.xz` for:

   | platform | arch | Rust targets | notes |
   | --- | --- | --- | --- |
   | linux | x86, x86_64, aarch32, aarch64, riscv64 | `i686`, `x86_64`, `armv7` (gnueabihf), `aarch64`, `riscv64gc` `-unknown-linux-gnu` | |
   | linux | riscv32 | `riscv32gc-unknown-linux-gnu` (Tier 3) | static library only: no riscv32 glibc sysroot is available to link a shared library |
   | android | x86, x86_64, aarch32, aarch64 | `i686`, `x86_64`, `armv7`, `aarch64` Android | API level 24 |
   | android | riscv64 | `riscv64-linux-android` (Tier 3) | API level 35 |
   | darwin | x86_64 | `x86_64-apple-darwin`; `x86_64-apple-ios` in `lib/ios-simulator` | |
   | darwin | aarch64 | `aarch64-apple-darwin`; `aarch64-apple-ios` in `lib/ios`; `aarch64-apple-ios-sim` in `lib/ios-simulator` | |
   | windows | x86, x86_64, aarch64 | `i686`, `x86_64`, `aarch64` `-pc-windows-msvc` | |
   | windows | aarch32 | `thumbv7a-pc-windows-msvc` (Tier 3) | static library only: the Windows 11 SDKs of the CI runners no longer provide the 32-bit ARM libraries needed to link a DLL |

   Combinations without a Rust target (riscv on Darwin and Windows, riscv32 on
   Android) and obsolete ones (32-bit Darwin) are not built. Every archive
   contains `LICENSE`, `README.md`, `include/` and `lib/` (with
   `lib/pkgconfig/umilib.pc`, whose `Libs.private` lists the system libraries
   needed to link the static library), built with every feature. Python wheels
   are built for every target with a shared library and a Python platform tag
   (Linux, Android, macOS and Windows; not iOS, where PEP 730 requires binaries
   packaged as frameworks);
4. publishes to crates.io (`cargo publish`), to PyPI (`uv publish`, wheels and
   the source distribution) and attaches the archives and `SHA256SUMS` to the
   GitHub release. Versions already published are skipped, so a failed release
   can be re-run.

### Secrets

Create an environment named `release` and add these secrets to it:

| Secret | Value |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | a crates.io API token with the `publish-new` and `publish-update` scopes for `umilib` |
| `PYPI_API_TOKEN` | a PyPI API token (scoped to the `umilib` project after the first release) |

The package name `umilib` was unused on crates.io and PyPI when this project
was created (October 2026); the first release registers it.
