use super::FuzzTarget;

/// A [`FuzzTarget`] made of a name and a function.
pub struct FuzzFunction<F: Fn(&[u8]) + Sync> {
    name: &'static str,
    function: F,
}

impl<F: Fn(&[u8]) + Sync> FuzzFunction<F> {
    /// Creates a target named `name` that calls `function`.
    pub const fn new(name: &'static str, function: F) -> FuzzFunction<F> {
        FuzzFunction { name, function }
    }
}

impl<F: Fn(&[u8]) + Sync> FuzzTarget for FuzzFunction<F> {
    fn name(&self) -> &str {
        self.name
    }

    fn run(&self, data: &[u8]) {
        (self.function)(data)
    }
}
