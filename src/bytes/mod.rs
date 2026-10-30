//! Reading and writing integers and byte sequences.
//!
//! [`Reader`] parses a borrowed slice without copying. [`Writer`] is implemented
//! by [`Buffer`], which grows up to an optional limit, by [`SliceWriter`],
//! which fills a caller-provided slice, and by [`ByteCounter`], which only
//! counts. [`BitReader`] and [`BitWriter`] read and write bits, least
//! significant first, as the compressed formats pack them; [`BitQueue`]
//! holds the bits a streaming decoder takes from successive inputs, in
//! either [`BitOrder`]. [`LineBuffer`] holds received bytes and reads them
//! as CRLF-ended lines or counted bytes, as line protocols do.

mod bit_order;
mod bit_queue;
mod bit_reader;
mod bit_writer;
mod buffer;
mod byte_counter;
mod error;
mod integer;
mod line_buffer;
mod reader;
mod slice_writer;
mod writer;

pub use bit_order::BitOrder;
pub use bit_queue::BitQueue;
pub use bit_reader::BitReader;
pub use bit_writer::BitWriter;
pub use buffer::Buffer;
pub use byte_counter::ByteCounter;
pub use error::BytesError;
pub use integer::Integer;
pub use line_buffer::LineBuffer;
pub use reader::Reader;
pub use slice_writer::SliceWriter;
pub use writer::Writer;
