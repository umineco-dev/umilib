/// Code under test. It fails by panicking.
pub trait FuzzTarget: Sync {
    /// The name, used for corpus and crash directories; conventionally the
    /// feature path of the tested module followed by what is tested, such as `bytes-reader`.
    fn name(&self) -> &str;

    /// Runs the code under test on `data`.
    fn run(&self, data: &[u8]);
}
