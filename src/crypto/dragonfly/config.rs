/// The parameters of a Dragonfly exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct DragonflyConfig {
    /// The rounds k of hunting and pecking that are always run (section 3.2):
    /// a round finds a point with a probability of about 1/2, so 40 rounds
    /// leave a probability of 2^-40 that more are needed and their number shows.
    pub iterations: u32,
}

impl Default for DragonflyConfig {
    fn default() -> DragonflyConfig {
        DragonflyConfig { iterations: 40 }
    }
}
