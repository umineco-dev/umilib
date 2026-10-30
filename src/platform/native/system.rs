/// The operating system umilib is compiled for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct System;

impl System {
    /// `"linux"`, `"android"`, `"darwin"`, `"windows"`, or `"other"` (where no native layer exists).
    pub const NAME: &'static str = if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_vendor = "apple") {
        "darwin"
    } else if cfg!(windows) {
        "windows"
    } else {
        "other"
    };

    /// Whether the system has a native layer.
    pub const SUPPORTED: bool = !matches!(System::NAME.as_bytes(), b"other");
}
