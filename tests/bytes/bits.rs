//! Bit I/O: the packing of RFC 1951 section 3.1.1 (least significant bit
//! first) and its mirror (most significant bit first), and the backward
//! bitstreams of RFC 8878 section 4.1.

use umilib::bytes::{BackwardBitReader, BackwardBitWriter, BitOrder, BitQueue, BitReader, BitWriter};

#[test]
fn bit_readers_and_writers_pack_least_significant_bits_first() {
    // RFC 1951 section 3.1.1: data elements are packed starting with the least significant bit.
    let mut writer = BitWriter::new();
    writer.write(0b1, 1);
    writer.write(0b10, 2);
    writer.write(0b11001, 5);
    writer.write(0x1234, 16);
    writer.write(0b101, 3);
    assert_eq!(writer.bit_length(), 27);
    let bytes = writer.finish();
    assert_eq!(bytes, [0b1100_1101, 0x34, 0x12, 0b101]);
    let mut reader = BitReader::new(&bytes);
    assert_eq!(reader.read(1), Some(1));
    assert_eq!(reader.read(2), Some(0b10));
    assert_eq!(reader.read(5), Some(0b11001));
    assert_eq!(reader.read(16), Some(0x1234));
    assert_eq!(reader.peek(9), None);
    assert_eq!(reader.peek_padded(9), 0b101);
    assert_eq!(reader.read(8), Some(0b101));
    assert_eq!(reader.remaining(), 0);
    assert_eq!(reader.read(1), None);
}

#[test]
fn bit_writers_align_and_hand_over_bytes() {
    let mut writer = BitWriter::new();
    writer.write(0b111, 3);
    writer.write_bytes(&[0xAB]);
    writer.write(1, 1);
    assert_eq!(writer.completed(), [0b111, 0xAB]);
    let completed = writer.completed().to_vec();
    writer.clear_completed();
    assert!(writer.completed().is_empty());
    writer.write(0, 7);
    assert_eq!(completed.len() + writer.completed().len(), 3);
    assert_eq!(writer.finish(), [1]);
    let mut reader = BitReader::new(&[0b0000_0101, 0xCD]);
    assert_eq!(reader.read(3), Some(0b101));
    assert_eq!(reader.read_bytes(1), None);
    assert_eq!(reader.align(), 0);
    // A length whose number of bits does not fit a usize is refused, not wrapped.
    assert_eq!(reader.read_bytes(usize::MAX / 8 + 1), None);
    assert_eq!(reader.read_bytes(1), Some(&[0xCD][..]));
}

#[test]
fn bit_queues_read_in_both_orders() {
    let data = [0b1010_0110u8, 0b0011_1100];
    let mut least = BitQueue::new();
    let mut input = &data[..];
    assert_eq!(least.read_from(3, &mut input), Some(0b110));
    assert_eq!(input.len(), 1, "one byte is enough for three bits");
    assert_eq!(least.read_from(7, &mut input), Some(0b001_0100));
    assert_eq!(least.count(), 6);
    assert_eq!(least.align(), 0b001111);
    let mut most = BitQueue::with_order(BitOrder::MostSignificantFirst);
    let mut input = &data[..];
    assert_eq!(most.read_from(3, &mut input), Some(0b101));
    assert_eq!(most.read_from(7, &mut input), Some(0b001_1000));
    assert_eq!(most.peek(7), None);
    assert_eq!(most.peek_padded(7), 0b111_1000);
    assert_eq!(most.align(), 0b111100);
    assert_eq!(most.count(), 0);
}

#[test]
fn bit_queues_take_no_byte_they_do_not_need() {
    let data = [0xFFu8, 0x00, 0x55];
    let mut queue = BitQueue::new();
    let mut input = &data[..];
    assert!(queue.fill(9, &mut input));
    assert_eq!((queue.count(), input.len()), (16, 1));
    assert!(queue.fill(16, &mut input));
    assert_eq!(input.len(), 1);
    assert_eq!(queue.read(16), Some(0x00FF));
    let mut empty: &[u8] = &[];
    assert_eq!(queue.read_from(1, &mut empty), None);
    assert_eq!(queue.read_from(8, &mut input), Some(0x55));
    // A partial fill keeps the bytes it took.
    let mut queue = BitQueue::new();
    let mut short = &data[..1];
    assert!(!queue.fill(12, &mut short));
    assert_eq!(queue.count(), 8);
    queue.clear();
    assert_eq!(queue.count(), 0);
}

#[test]
fn bit_writers_of_the_most_significant_bit_first() {
    // The mirror of RFC 1951 section 3.1.1, as HPACK (RFC 7541 §5.2) and
    // Zstandard's backward streams pack bits: the first bit is the most
    // significant of its byte, and a value's most significant bit goes first.
    let mut writer = BitWriter::with_order(BitOrder::MostSignificantFirst);
    writer.write(0b1, 1);
    writer.write(0b10, 2);
    writer.write(0b11001, 5);
    writer.write(0x1234, 16);
    writer.write(0b101, 3);
    assert_eq!(writer.bit_length(), 27);
    let bytes = writer.finish();
    assert_eq!(bytes, [0b1101_1001, 0x12, 0x34, 0b1010_0000]);
    let mut queue = BitQueue::with_order(BitOrder::MostSignificantFirst);
    let mut input = &bytes[..];
    for (count, value) in [(1, 0b1), (2, 0b10), (5, 0b11001), (16, 0x1234), (3, 0b101)] {
        assert_eq!(queue.read_from(count, &mut input), Some(value));
    }
}

#[test]
fn backward_bit_readers_start_after_the_final_bit() {
    // RFC 8878 section 4.1 (and 3.1.1.3.1.6, 4.2.2): the last byte ends with a 1 bit followed by
    // zero padding, the bits before it are read from the end, the first read the most significant.
    // 0x05 = 00000101: 5 padding zeros and the 1 bit leave its 2 lowest bits, 0 then 1.
    let bytes = [0b1011_0110, 0b0000_0101];
    let mut reader = BackwardBitReader::new(&bytes).unwrap();
    assert_eq!(reader.remaining(), 10);
    assert_eq!(reader.peek(3), 0b011);
    assert_eq!(reader.read(3), 0b011);
    assert_eq!(reader.read(4), 0b0110);
    assert_eq!(reader.read(0), 0);
    assert_eq!(reader.read(3), 0b110);
    assert!(reader.is_finished() && !reader.overflowed());
    // A stream of only the final bit holds no bits; one without it is not a stream.
    assert!(BackwardBitReader::new(&[0x01]).unwrap().is_finished());
    assert!(BackwardBitReader::new(&[0x80]).unwrap().remaining() == 7);
    assert_eq!(BackwardBitReader::new(&[0xFF, 0x00]), None);
    assert_eq!(BackwardBitReader::new(&[]), None);
}

#[test]
fn backward_bit_readers_give_zeros_past_the_start_and_say_so() {
    // Bits below the start of the stream are zeros at the bottom of a value; the reader stays at
    // the start and reports the overflow, so a stream shorter than its symbols is detected.
    let bytes = [0b0000_1101];
    let mut reader = BackwardBitReader::new(&bytes).unwrap();
    assert_eq!(reader.remaining(), 3);
    assert_eq!(reader.peek(5), 0b10100);
    assert_eq!(reader.read(5), 0b10100);
    assert!(reader.overflowed() && !reader.is_finished());
    assert_eq!(reader.remaining(), 0);
    assert_eq!(reader.read(32), 0);
    assert_eq!(reader.peek(1), 0);
    assert!(reader.overflowed());
    // A read of exactly the remaining bits does not overflow.
    let mut reader = BackwardBitReader::new(&bytes).unwrap();
    assert_eq!(reader.read(3), 0b101);
    assert!(reader.is_finished());
}

#[test]
fn backward_bit_writers_write_what_readers_read() {
    // The reverse of the order of reading: 0b110, then 0b0110, then 0b011 give the stream above.
    let mut writer = BackwardBitWriter::new();
    writer.write(0b110, 3);
    writer.write(0xFFFF_FFF6, 4);
    writer.write(0b011, 3);
    assert_eq!(writer.bit_length(), 10);
    assert_eq!(writer.finish(), [0b1011_0110, 0b0000_0101]);
    assert_eq!(BackwardBitWriter::new().finish(), [0x01]);
    // Values of every width, 32 bits included, in random order.
    let mut state = 0x2545_F491u32;
    let mut values = Vec::new();
    let mut writer = BackwardBitWriter::new();
    for _ in 0..1000 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let count = state % 33;
        let value = if count == 32 { state } else { state & ((1 << count) - 1) };
        writer.write(value, count);
        values.push((value, count));
    }
    let stream = writer.finish();
    let mut reader = BackwardBitReader::new(&stream).unwrap();
    for (value, count) in values.iter().rev() {
        assert_eq!(reader.read(*count), *value);
    }
    assert!(reader.is_finished());
}
