//! Cyclic redundancy checks of any width up to 128 bits, described by the
//! parameters of the Rocksoft model (Williams, "A Painless Guide to CRC
//! Error Detection Algorithms"), with every algorithm of the RevEng
//! "Catalogue of parametrised CRC algorithms" as a preset.

mod catalogue;
mod parameters;
mod register;
mod state;
mod table;

pub use catalogue::CRCCatalogue;
pub use parameters::CRCParameters;
pub use register::CRCRegister;
pub use state::CRC;
pub use table::CRCTable;
