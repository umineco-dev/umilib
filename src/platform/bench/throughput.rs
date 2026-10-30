/// The amount of work done by one iteration of a routine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Throughput {
    /// The routine processes this many bytes.
    Bytes(u64),
    /// The routine processes this many elements (packets, keys, messages...).
    Elements(u64),
}

impl Throughput {
    /// The amount of work, regardless of its unit.
    pub const fn amount(&self) -> u64 {
        match self {
            Throughput::Bytes(amount) | Throughput::Elements(amount) => *amount,
        }
    }

    /// The unit of work: `bytes` or `elements`.
    pub const fn unit(&self) -> &'static str {
        match self {
            Throughput::Bytes(_) => "bytes",
            Throughput::Elements(_) => "elements",
        }
    }
}
