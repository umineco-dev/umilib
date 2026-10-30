//! Tests of `umilib::bytes`: integers are encoded as defined for network byte
//! order (big-endian, most significant byte first) and little-endian (least
//! significant byte first), and failed operations leave the cursor unchanged.

mod bits;
mod buffer;
mod reader;
mod slice_writer;
