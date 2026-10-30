//! What Android's C library (bionic) gives besides the Linux kernel's
//! interfaces (`platform-linux`, which Android uses too): the system
//! properties ([`AndroidSystem`]). Compiled on Android only.

mod system;

pub use system::AndroidSystem;
