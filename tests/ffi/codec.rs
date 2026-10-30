use std::ptr;

use umilib::codec::base::BitEncoding;
use umilib::codec::base::base64::Base64;
use umilib::codec::base::base85::Base85;
use umilib::ffi::Buffer;
use umilib::ffi::codec::base::base64::*;
use umilib::ffi::codec::base::base85::*;
use umilib::ffi::codec::base::*;

use super::Check;

#[test]
fn base64_encodes_and_decodes_through_the_c_abi() {
    let mut encoding: *mut Base64 = ptr::null_mut();
    unsafe {
        Check::ok(umilib_codec_base_base64_base64_standard(&mut encoding));
        let mut text = Buffer::EMPTY;
        Check::ok(umilib_codec_base_base64_base64_encode(encoding, b"foobar".as_ptr(), 6, &mut text));
        assert_eq!(text.as_slice(), b"Zm9vYmFy");
        let mut bytes = Buffer::EMPTY;
        Check::ok(umilib_codec_base_base64_base64_decode(
            encoding,
            text.as_slice().as_ptr(),
            text.as_slice().len(),
            &mut bytes,
        ));
        assert_eq!(bytes.as_slice(), b"foobar");
        umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
        Check::fails(
            umilib_codec_base_base64_base64_decode(encoding, b"Zh==".as_ptr(), 4, &mut bytes),
            "codec.base",
            "NonCanonical",
        );
        Check::fails(
            umilib_codec_base_base64_base64_decode(encoding, b"Zg=".as_ptr(), 3, &mut bytes),
            "codec.base",
            "InvalidLength",
        );

        let (mut has, mut length) = (false, 0usize);
        Check::ok(umilib_codec_base_base64_base64_maximum_encoded_length(encoding, 4, &mut has, &mut length));
        assert_eq!((has, length), (true, 8));
        Check::ok(umilib_codec_base_base64_base64_maximum_encoded_length(encoding, usize::MAX, &mut has, &mut length));
        assert!(!has);

        let mut output = [0u8; 8];
        let mut written = 0usize;
        Check::ok(umilib_codec_base_base64_base64_encode_to_slice(
            encoding,
            b"fo".as_ptr(),
            2,
            output.as_mut_ptr(),
            8,
            &mut written,
        ));
        assert_eq!(&output[..written], b"Zm8=");
        Check::fails(
            umilib_codec_base_base64_base64_encode_to_slice(
                encoding,
                b"foo".as_ptr(),
                3,
                output.as_mut_ptr(),
                3,
                &mut written,
            ),
            "codec.base",
            "OutputTooSmall",
        );
        // Encoding into its own input is rejected rather than reading changed data.
        let base = output.as_mut_ptr();
        Check::fails(
            umilib_codec_base_base64_base64_encode_to_slice(encoding, base, 2, base, 8, &mut written),
            "ffi",
            "InvalidArgument",
        );

        let mut bit: *mut BitEncoding = ptr::null_mut();
        Check::ok(umilib_codec_base_base64_base64_encoding(encoding, &mut bit));
        let mut group = 0usize;
        Check::ok(umilib_codec_base_bit_encoding_group_characters(bit, &mut group));
        assert_eq!(group, 4);
        umilib_codec_base_bit_encoding_free(bit);

        let mut custom: *mut Base64 = ptr::null_mut();
        Check::ok(umilib_codec_base_base64_base64_new(
            umilib_codec_base_base64_base64_url_safe_alphabet(),
            1,
            &mut custom,
        ));
        // An output buffer is overwritten without being freed: free it before reuse.
        umilib::ffi::umilib_ffi_buffer_free(&mut text);
        Check::ok(umilib_codec_base_base64_base64_encode(custom, [0xFB, 0xFF].as_ptr(), 2, &mut text));
        assert_eq!(text.as_slice(), b"-_8");
        umilib::ffi::umilib_ffi_buffer_free(&mut text);
        Check::fails(
            umilib_codec_base_base64_base64_new(umilib_codec_base_base64_base64_url_safe_alphabet(), 9, &mut custom),
            "ffi",
            "InvalidArgument",
        );
        umilib_codec_base_base64_base64_free(custom);
        umilib_codec_base_base64_base64_free(encoding);
    }
}

#[test]
fn alphabets_are_static_and_queryable() {
    unsafe {
        let alphabet = umilib_codec_base_base64_base64_standard_alphabet();
        assert_eq!(alphabet, umilib_codec_base_base64_base64_standard_alphabet());
        let mut size = 0usize;
        Check::ok(umilib_codec_base_alphabet_size(alphabet, &mut size));
        assert_eq!(size, 64);
        let mut character = 0u8;
        Check::ok(umilib_codec_base_alphabet_encode(alphabet, 63, &mut character));
        assert_eq!(character, b'/');
        Check::fails(umilib_codec_base_alphabet_encode(alphabet, 64, &mut character), "ffi", "InvalidArgument");
        let (mut valid, mut value) = (false, 0u8);
        Check::ok(umilib_codec_base_alphabet_decode(alphabet, b'a', &mut valid, &mut value));
        assert_eq!((valid, value), (true, 26));
        Check::ok(umilib_codec_base_alphabet_decode(alphabet, b'-', &mut valid, &mut value));
        assert!(!valid);
        assert_eq!(umilib_codec_base_alphabet_mask_in(5, 3, 4), 0xFF);
        assert_eq!(umilib_codec_base_alphabet_mask_in(7, 3, 4), 0);
    }
}

#[test]
fn base85_groups_through_the_c_abi() {
    let mut encoding: *mut Base85 = ptr::null_mut();
    unsafe {
        Check::ok(umilib_codec_base_base85_base85_z85(&mut encoding));
        let mut digits = [0u8; 5];
        Check::ok(umilib_codec_base_base85_base85_encode_group(encoding, 0x864F_D26F, digits.as_mut_ptr()));
        assert_eq!(&digits, b"Hello");
        let mut text = Buffer::EMPTY;
        Check::fails(
            umilib_codec_base_base85_base85_encode(encoding, [1u8].as_ptr(), 1, &mut text),
            "codec.base",
            "InvalidLength",
        );
        umilib_codec_base_base85_base85_free(encoding);
    }
}

#[test]
fn json_values_through_the_c_abi() {
    use umilib::codec::json::{JSONNumber, JSONValue};
    use umilib::ffi::codec::json::*;

    unsafe {
        let text = br#"{"a": [1, "x"], "b": true}"#;
        let mut value: *mut JSONValue = ptr::null_mut();
        Check::ok(umilib_codec_json_json_value_decode(text.as_ptr(), text.len(), ptr::null(), &mut value));
        let mut kind = 9u8;
        Check::ok(umilib_codec_json_json_value_kind(value, &mut kind));
        assert_eq!(kind, JSONValueKind::OBJECT);
        let (mut found, mut member): (bool, *mut JSONValue) = (false, ptr::null_mut());
        Check::ok(umilib_codec_json_json_value_get(value, b"a".as_ptr(), 1, &mut found, &mut member));
        assert!(found);
        let mut length = 0usize;
        Check::ok(umilib_codec_json_json_value_len(member, &mut length));
        assert_eq!(length, 2);
        let mut element: *mut JSONValue = ptr::null_mut();
        Check::ok(umilib_codec_json_json_value_index(member, 1, &mut element));
        let mut string = Buffer::EMPTY;
        Check::ok(umilib_codec_json_json_value_as_str(element, &mut string));
        assert_eq!(string.as_slice(), b"x");
        umilib::ffi::umilib_ffi_buffer_free(&mut string);
        let mut flag = false;
        Check::fails(umilib_codec_json_json_value_as_bool(element, &mut flag), "codec.json", "WrongKind");
        // Pushing a value into itself copies it first.
        Check::ok(umilib_codec_json_json_value_push(member, member));
        Check::ok(umilib_codec_json_json_value_len(member, &mut length));
        assert_eq!(length, 3);
        Check::ok(umilib_codec_json_json_value_insert(value, b"a".as_ptr(), 1, member));
        let mut encoded = Buffer::EMPTY;
        Check::ok(umilib_codec_json_json_value_encode(value, &mut encoded));
        assert_eq!(encoded.as_slice(), br#"{"a":[1,"x",[1,"x"]],"b":true}"#);
        umilib::ffi::umilib_ffi_buffer_free(&mut encoded);
        let mut missing: *mut JSONValue = ptr::null_mut();
        Check::ok(umilib_codec_json_json_value_get(value, b"zz".as_ptr(), 2, &mut found, &mut missing));
        assert!(!found && missing.is_null());
        umilib_codec_json_json_value_free(element);
        umilib_codec_json_json_value_free(member);
        umilib_codec_json_json_value_free(value);

        Check::fails(
            umilib_codec_json_json_value_decode(b"[1,]".as_ptr(), 4, ptr::null(), &mut value),
            "codec.json",
            "UnexpectedCharacter",
        );
        let mut number: *mut JSONNumber = ptr::null_mut();
        Check::ok(umilib_codec_json_json_number_new(b"-12".as_ptr(), 3, &mut number));
        let mut integer = 0i64;
        Check::ok(umilib_codec_json_json_number_as_i64(number, &mut integer));
        assert_eq!(integer, -12);
        let mut unsigned = 0u64;
        Check::fails(umilib_codec_json_json_number_as_u64(number, &mut unsigned), "codec.json", "OutOfRange");
        umilib_codec_json_json_number_free(number);
        Check::fails(umilib_codec_json_json_number_from_f64(f64::NAN, &mut number), "codec.json", "OutOfRange");
        Check::fails(umilib_codec_json_json_number_new(b"01".as_ptr(), 2, &mut number), "codec.json", "InvalidNumber");
    }
}

#[test]
fn json_reader_and_strings_through_the_c_abi() {
    use umilib::codec::json::JSONReader;
    use umilib::ffi::codec::json::*;

    let text = br#"["a\nb", 2, true]"#;
    let mut reader: *mut JSONReader<'static> = ptr::null_mut();
    let mut kinds = Vec::new();
    unsafe {
        Check::ok(umilib_codec_json_json_reader_new(text.as_ptr(), text.len(), ptr::null(), &mut reader));
        loop {
            let (mut has, mut kind, mut data, mut length, mut escaped) = (false, 0u8, ptr::null(), 0usize, false);
            Check::ok(umilib_codec_json_json_reader_next_event(
                reader,
                &mut has,
                &mut kind,
                &mut data,
                &mut length,
                &mut escaped,
            ));
            if !has {
                break;
            }
            if kind == JSONEventKind::STRING {
                assert!(escaped);
                let mut decoded = Buffer::EMPTY;
                Check::ok(umilib_codec_json_json_string_decode(data, length, &mut decoded));
                assert_eq!(decoded.as_slice(), b"a\nb");
                umilib::ffi::umilib_ffi_buffer_free(&mut decoded);
            }
            if kind == JSONEventKind::BOOL {
                assert!(escaped, "booleans carry their value in out_escaped");
            }
            kinds.push(kind);
        }
        umilib_codec_json_json_reader_free(reader);
        let mut decoded = Buffer::EMPTY;
        Check::fails(
            umilib_codec_json_json_string_decode(b"\\x".as_ptr(), 2, &mut decoded),
            "codec.json",
            "InvalidEscape",
        );
        Check::fails(
            umilib_codec_json_json_string_decode(b"a\"b".as_ptr(), 3, &mut decoded),
            "codec.json",
            "UnexpectedCharacter",
        );
    }
    assert_eq!(
        kinds,
        [
            JSONEventKind::BEGIN_ARRAY,
            JSONEventKind::STRING,
            JSONEventKind::NUMBER,
            JSONEventKind::BOOL,
            JSONEventKind::END_ARRAY
        ]
    );
}

#[test]
fn der_reading_and_writing_through_the_c_abi() {
    use umilib::codec::asn1::ObjectIdentifier;
    use umilib::codec::asn1::der::{DERReader, DERWriter};
    use umilib::ffi::codec::asn1::der::*;
    use umilib::ffi::codec::asn1::*;

    unsafe {
        let mut writer: *mut DERWriter = ptr::null_mut();
        let mut inner: *mut DERWriter = ptr::null_mut();
        Check::ok(umilib_codec_asn1_der_der_writer_new(&mut writer));
        Check::ok(umilib_codec_asn1_der_der_writer_new(&mut inner));
        Check::ok(umilib_codec_asn1_der_der_writer_write_ia5_string(inner, b"Smith".as_ptr(), 5));
        Check::ok(umilib_codec_asn1_der_der_writer_write_boolean(inner, true));
        Check::ok(umilib_codec_asn1_der_der_writer_write_sequence(writer, inner));
        Check::fails(umilib_codec_asn1_der_der_writer_write_sequence(writer, writer), "ffi", "InvalidArgument");
        Check::fails(
            umilib_codec_asn1_der_der_writer_write_printable_string(writer, b"a@b".as_ptr(), 3),
            "codec.asn1",
            "InvalidContent",
        );
        let mut bytes = Buffer::EMPTY;
        Check::ok(umilib_codec_asn1_der_der_writer_into_bytes(writer, &mut bytes));
        umilib_codec_asn1_der_der_writer_free(inner);
        assert_eq!(bytes.as_slice(), [0x30, 0x0A, 0x16, 0x05, b'S', b'm', b'i', b't', b'h', 0x01, 0x01, 0xFF]);

        let mut reader: *mut DERReader<'static> = ptr::null_mut();
        Check::ok(umilib_codec_asn1_der_der_reader_new(bytes.as_slice().as_ptr(), bytes.as_slice().len(), &mut reader));
        let mut sequence: *mut DERReader<'static> = ptr::null_mut();
        Check::ok(umilib_codec_asn1_der_der_reader_read_sequence(reader, &mut sequence));
        let (mut data, mut length): (*const u8, usize) = (ptr::null(), 0);
        Check::ok(umilib_codec_asn1_der_der_reader_read_ia5_string(sequence, &mut data, &mut length));
        assert_eq!(std::slice::from_raw_parts(data, length), b"Smith");
        let mut element = CDERElement {
            tag: CTag { tag_class: 0, constructed: false, number: 0 },
            content: ptr::null(),
            content_length: 0,
            encoding: ptr::null(),
            encoding_length: 0,
            position: 0,
        };
        Check::ok(umilib_codec_asn1_der_der_reader_read_element(sequence, &mut element));
        assert_eq!((element.tag, element.position), (CTag { tag_class: 0, constructed: false, number: 1 }, 9));
        let mut value = false;
        Check::ok(umilib_codec_asn1_der_der_element_as_boolean(&element, &mut value));
        assert!(value);
        Check::ok(umilib_codec_asn1_der_der_reader_finish(sequence));
        Check::fails(
            umilib_codec_asn1_der_der_reader_read_element(sequence, &mut element),
            "codec.asn1",
            "UnexpectedEnd",
        );
        umilib_codec_asn1_der_der_reader_free(sequence);
        umilib_codec_asn1_der_der_reader_free(reader);
        Check::fails(
            umilib_codec_asn1_der_der_reader_validate([0x01, 0x01, 0x01].as_ptr(), 3, 64),
            "codec.asn1",
            "NonCanonical",
        );
        Check::fails(
            umilib_codec_asn1_der_der_reader_read_expected(
                ptr::null_mut(),
                CTag { tag_class: 9, constructed: false, number: 1 },
                &mut element,
            ),
            "ffi",
            "InvalidArgument",
        );
        umilib::ffi::umilib_ffi_buffer_free(&mut bytes);

        let mut identifier: *mut ObjectIdentifier<'static> = ptr::null_mut();
        Check::ok(umilib_codec_asn1_object_identifier_parse(b"2.999.3".as_ptr(), 7, &mut identifier));
        let (mut content, mut content_length): (*const u8, usize) = (ptr::null(), 0);
        Check::ok(umilib_codec_asn1_object_identifier_as_bytes(identifier, &mut content, &mut content_length));
        assert_eq!(std::slice::from_raw_parts(content, content_length), [0x88, 0x37, 0x03]);
        let mut arc = umilib::ffi::U128::default();
        Check::ok(umilib_codec_asn1_object_identifier_arcs(identifier, 1, &mut arc));
        assert_eq!(u128::from(arc), 999);
        umilib_codec_asn1_object_identifier_free(identifier);

        let mut der = Buffer::EMPTY;
        let ber = [0x24u8, 0x80, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42, 0x00, 0x00];
        Check::ok(umilib::ffi::codec::asn1::ber::umilib_codec_asn1_ber_ber_reader_to_der(
            ber.as_ptr(),
            ber.len(),
            64,
            &mut der,
        ));
        assert_eq!(der.as_slice(), [0x04, 0x02, 0x41, 0x42]);
        umilib::ffi::umilib_ffi_buffer_free(&mut der);

        let mut time = umilib::codec::asn1::ASN1Time::new(1970, 1, 1, 0, 0, 0, 0).unwrap();
        Check::ok(umilib_codec_asn1_asn1_time_decode_generalized_time(b"19851106210627.3Z".as_ptr(), 17, &mut time));
        assert_eq!((time.year, time.nanosecond), (1985, 300_000_000));
        Check::fails(
            umilib_codec_asn1_asn1_time_new(2023, 2, 29, 0, 0, 0, 0, &mut time),
            "codec.asn1",
            "InvalidContent",
        );
    }
}

#[test]
fn der_writers_reject_their_own_bytes_as_input() {
    use umilib::codec::asn1::der::DERWriter;
    use umilib::ffi::codec::asn1::CTag;
    use umilib::ffi::codec::asn1::der::*;

    unsafe {
        let mut writer: *mut DERWriter = ptr::null_mut();
        Check::ok(umilib_codec_asn1_der_der_writer_new(&mut writer));
        Check::ok(umilib_codec_asn1_der_der_writer_write_octet_string(writer, [7u8; 100].as_ptr(), 100));
        let (mut data, mut length) = (ptr::null(), 0usize);
        Check::ok(umilib_codec_asn1_der_der_writer_as_bytes(writer, &mut data, &mut length));
        // Appending reallocates the bytes the input would point into.
        let tag = CTag { tag_class: 0, constructed: false, number: 4 };
        Check::fails(
            umilib_codec_asn1_der_der_writer_write_element(writer, tag, data, length),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(umilib_codec_asn1_der_der_writer_write_raw(writer, data.add(1), 2), "ffi", "InvalidArgument");
        Check::fails(
            umilib_codec_asn1_der_der_writer_write_utf8_string(writer, data.add(10), 5),
            "ffi",
            "InvalidArgument",
        );
        let copy = std::slice::from_raw_parts(data, length).to_vec();
        Check::ok(umilib_codec_asn1_der_der_writer_write_raw(writer, copy.as_ptr(), copy.len()));
        Check::ok(umilib_codec_asn1_der_der_writer_as_bytes(writer, &mut data, &mut length));
        assert_eq!(length, 2 * copy.len());
        umilib_codec_asn1_der_der_writer_free(writer);
    }
}

#[test]
fn bit_encodings_check_their_parameters() {
    unsafe {
        let alphabet = umilib_codec_base_base64_base64_standard_alphabet();
        let mut encoding: *mut BitEncoding = ptr::null_mut();
        Check::fails(umilib_codec_base_bit_encoding_new(alphabet, 6, 0, b'A', &mut encoding), "ffi", "InvalidArgument");
        Check::fails(umilib_codec_base_bit_encoding_new(alphabet, 5, 0, b'=', &mut encoding), "ffi", "InvalidArgument");
        assert!(encoding.is_null());
        Check::ok(umilib_codec_base_bit_encoding_new(alphabet, 6, 0, b'=', &mut encoding));
        let mut valid = false;
        Check::ok(umilib_codec_base_bit_encoding_is_valid(encoding, &mut valid));
        assert!(valid);
        umilib_codec_base_bit_encoding_free(encoding);
    }
}

#[test]
fn huffman_codecs_stream_through_the_c_abi() {
    use umilib::codec::Progress;
    use umilib::codec::huffman::adaptive::{AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor};
    use umilib::codec::huffman::canonical::{HuffmanCode, HuffmanTable};
    use umilib::ffi::codec::huffman::adaptive;
    use umilib::ffi::codec::huffman::adaptive::*;
    use umilib::ffi::codec::huffman::canonical::*;

    let data = b"abracadabra abracadabra abracadabra".repeat(20);
    unsafe {
        // The code of RFC 1951 section 3.2.2 and its table.
        let mut code: *mut HuffmanCode = ptr::null_mut();
        Check::ok(umilib_codec_huffman_canonical_huffman_code_from_lengths(
            [3u8, 3, 3, 3, 3, 2, 4, 4].as_ptr(),
            8,
            &mut code,
        ));
        let mut value = 0u32;
        Check::ok(umilib_codec_huffman_canonical_huffman_code_code(code, 6, &mut value));
        assert_eq!(value, 0b1110);
        Check::fails(umilib_codec_huffman_canonical_huffman_code_code(code, 8, &mut value), "ffi", "InvalidArgument");
        let mut table: *mut HuffmanTable = ptr::null_mut();
        Check::ok(umilib_codec_huffman_canonical_huffman_table_new(code, 1, &mut table));
        let (mut symbol, mut length) = (0u16, 0u32);
        Check::ok(umilib_codec_huffman_canonical_huffman_table_decode(table, 0b0001, &mut symbol, &mut length));
        assert_eq!((symbol, length), (5, 2));
        umilib_codec_huffman_canonical_huffman_table_free(table);
        umilib_codec_huffman_canonical_huffman_code_free(code);
        Check::fails(
            umilib_codec_huffman_canonical_huffman_code_from_lengths([1u8, 1, 1].as_ptr(), 3, &mut code),
            "codec.huffman",
            "InvalidLengths",
        );
        let mut lengths = Buffer::EMPTY;
        Check::ok(umilib_codec_huffman_canonical_huffman_code_lengths_from_frequencies(
            [1u32, 1, 2].as_ptr(),
            3,
            15,
            &mut lengths,
        ));
        assert_eq!(lengths.as_slice(), [2, 2, 1]);
        umilib::ffi::umilib_ffi_buffer_free(&mut lengths);

        // Adaptive: compress in one call, decompress in pieces.
        let mut compressor: *mut AdaptiveHuffmanCompressor = ptr::null_mut();
        Check::ok(umilib_codec_huffman_adaptive_adaptive_huffman_compressor_new(&mut compressor));
        let mut stream = Buffer::EMPTY;
        Check::ok(adaptive::compressor::compress_to_vec(compressor, data.as_ptr(), data.len(), &mut stream));
        let mut decompressor: *mut AdaptiveHuffmanDecompressor = ptr::null_mut();
        Check::ok(umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_new(&mut decompressor));
        let mut out = vec![0u8; data.len()];
        let mut progress = Progress::default();
        Check::ok(adaptive::decompressor::decompress(
            decompressor,
            stream.as_slice().as_ptr(),
            stream.as_slice().len(),
            out.as_mut_ptr(),
            out.len(),
            &mut progress,
        ));
        assert_eq!(
            (progress.consumed, progress.produced, progress.finished),
            (stream.as_slice().len(), data.len(), true)
        );
        assert_eq!(out, data);
        // An unknown flush is rejected.
        Check::fails(
            adaptive::compressor::compress(compressor, ptr::null(), 0, out.as_mut_ptr(), out.len(), 3, &mut progress),
            "ffi",
            "InvalidArgument",
        );
        // Corrupt data fail with the statuses of CompressionError.
        Check::ok(adaptive::decompressor::reset(decompressor));
        let mut whole = Buffer::EMPTY;
        Check::fails(
            adaptive::decompressor::decompress_to_vec(
                decompressor,
                stream.as_slice().as_ptr(),
                3,
                usize::MAX,
                &mut whole,
            ),
            "codec",
            "UnexpectedEnd",
        );
        umilib::ffi::umilib_ffi_buffer_free(&mut stream);
        adaptive::compressor::free(compressor);
        adaptive::decompressor::free(decompressor);
    }
}

#[test]
fn lz_codecs_stream_through_the_c_abi() {
    use umilib::codec::Progress;
    use umilib::codec::lzss::{LZSSCompressor, LZSSDecompressor};
    use umilib::codec::rle::PackBitsDecompressor;
    use umilib::ffi::codec::{lzss, rle};

    let data = b"abracadabra abracadabra abracadabra".repeat(20);
    unsafe {
        let mut compressor: *mut LZSSCompressor = ptr::null_mut();
        Check::ok(lzss::umilib_codec_lzss_lzss_compressor_new(11, 4, &mut compressor));
        let mut stream = Buffer::EMPTY;
        Check::ok(lzss::compressor::compress_to_vec(compressor, data.as_ptr(), data.len(), &mut stream));
        let mut decompressor: *mut LZSSDecompressor = ptr::null_mut();
        Check::ok(lzss::umilib_codec_lzss_lzss_decompressor_new(11, 4, &mut decompressor));
        let mut out = Buffer::EMPTY;
        Check::ok(lzss::decompressor::decompress_to_vec(
            decompressor,
            stream.as_slice().as_ptr(),
            stream.as_slice().len(),
            data.len(),
            &mut out,
        ));
        assert_eq!(out.as_slice(), data);
        Check::fails(
            lzss::umilib_codec_lzss_lzss_decompressor_new(4, 2, &mut decompressor),
            "codec",
            "InvalidParameter",
        );
        let mut progress = Progress::default();
        let mut room = [0u8; 8];
        Check::fails(
            lzss::compressor::compress(compressor, data.as_ptr(), 4, room.as_mut_ptr(), 8, 1, &mut progress),
            "codec",
            "InvalidParameter",
        );
        umilib::ffi::umilib_ffi_buffer_free(&mut stream);
        umilib::ffi::umilib_ffi_buffer_free(&mut out);
        lzss::compressor::free(compressor);
        lzss::decompressor::free(decompressor);

        // PackBits ends with its input: finish accepts the end between runs only.
        let mut packbits: *mut PackBitsDecompressor = ptr::null_mut();
        Check::ok(rle::umilib_codec_rle_pack_bits_decompressor_new(&mut packbits));
        Check::ok(rle::decompressor::decompress(
            packbits,
            [0xFE, 0xAA, 0x02].as_ptr(),
            3,
            room.as_mut_ptr(),
            8,
            &mut progress,
        ));
        assert_eq!((progress.consumed, progress.produced, progress.finished), (3, 3, false));
        Check::fails(rle::decompressor::finish(packbits), "codec", "UnexpectedEnd");
        Check::ok(rle::decompressor::reset(packbits));
        Check::ok(rle::decompressor::finish(packbits));
        rle::decompressor::free(packbits);
    }
}

#[test]
fn deflate_codecs_stream_through_the_c_abi() {
    use umilib::codec::gzip::{GzipCompressor, GzipDecompressor};
    use umilib::codec::zlib::{ZlibCompressor, ZlibDecompressor};
    use umilib::ffi::codec::{gzip, zlib};

    let data = b"abracadabra abracadabra abracadabra".repeat(20);
    unsafe {
        // zlib with a dictionary: the decompressor without it fails with MissingDictionary.
        let mut compressor: *mut ZlibCompressor = ptr::null_mut();
        Check::ok(zlib::umilib_codec_zlib_zlib_compressor_new(9, 15, b"abra".as_ptr(), 4, &mut compressor));
        let mut stream = Buffer::EMPTY;
        Check::ok(zlib::compressor::compress_to_vec(compressor, data.as_ptr(), data.len(), &mut stream));
        let mut decompressor: *mut ZlibDecompressor = ptr::null_mut();
        Check::ok(zlib::umilib_codec_zlib_zlib_decompressor_new(15, ptr::null(), 0, &mut decompressor));
        let mut out = Buffer::EMPTY;
        let (input, length) = (stream.as_slice().as_ptr(), stream.as_slice().len());
        Check::fails(
            zlib::decompressor::decompress_to_vec(decompressor, input, length, data.len(), &mut out),
            "codec",
            "MissingDictionary",
        );
        zlib::decompressor::free(decompressor);
        Check::ok(zlib::umilib_codec_zlib_zlib_decompressor_new(15, b"abra".as_ptr(), 4, &mut decompressor));
        Check::ok(zlib::decompressor::decompress_to_vec(decompressor, input, length, data.len(), &mut out));
        assert_eq!(out.as_slice(), data);
        umilib::ffi::umilib_ffi_buffer_free(&mut out);
        umilib::ffi::umilib_ffi_buffer_free(&mut stream);
        zlib::compressor::free(compressor);
        zlib::decompressor::free(decompressor);

        // gzip with a name; the decompressor gives it back.
        let mut compressor: *mut GzipCompressor = ptr::null_mut();
        let name = b"data.txt";
        Check::ok(gzip::umilib_codec_gzip_gzip_compressor_new(
            6,
            7,
            3,
            false,
            true,
            ptr::null(),
            0,
            name.as_ptr(),
            name.len(),
            ptr::null(),
            0,
            &mut compressor,
        ));
        Check::ok(gzip::compressor::compress_to_vec(compressor, data.as_ptr(), data.len(), &mut stream));
        let mut decompressor: *mut GzipDecompressor = ptr::null_mut();
        Check::ok(gzip::umilib_codec_gzip_gzip_decompressor_new(true, 1 << 16, &mut decompressor));
        Check::ok(gzip::decompressor::decompress_to_vec(
            decompressor,
            stream.as_slice().as_ptr(),
            stream.as_slice().len(),
            data.len(),
            &mut out,
        ));
        assert_eq!(out.as_slice(), data);
        let (mut has, mut field) = (false, Buffer::EMPTY);
        Check::ok(gzip::umilib_codec_gzip_gzip_decompressor_header_field(decompressor, 1, &mut has, &mut field));
        assert!(has && field.as_slice() == name);
        // The buffer the call above wrote, released once.
        field.release();
        Check::ok(gzip::umilib_codec_gzip_gzip_decompressor_header_field(decompressor, 2, &mut has, &mut field));
        assert!(!has);
        Check::fails(
            gzip::umilib_codec_gzip_gzip_decompressor_header_field(decompressor, 3, &mut has, &mut field),
            "ffi",
            "InvalidArgument",
        );
        let (mut text, mut time, mut flags, mut system, mut checksum, mut members) =
            (true, 0u32, 0u8, 0u8, false, 0usize);
        Check::ok(gzip::umilib_codec_gzip_gzip_decompressor_header(
            decompressor,
            &mut text,
            &mut time,
            &mut flags,
            &mut system,
            &mut checksum,
            &mut members,
        ));
        assert_eq!((text, time, system, checksum, members), (false, 7, 3, true, 1));
        umilib::ffi::umilib_ffi_buffer_free(&mut out);
        umilib::ffi::umilib_ffi_buffer_free(&mut stream);
        umilib::ffi::umilib_ffi_buffer_free(&mut field);
        gzip::compressor::free(compressor);
        gzip::decompressor::free(decompressor);
    }
}

#[test]
fn brotli_codecs_stream_through_the_c_abi() {
    use umilib::codec::Progress;
    use umilib::codec::brotli::{BrotliCompressor, BrotliDecompressor};
    use umilib::ffi::codec::brotli;

    let data = b"abracadabra abracadabra abracadabra".repeat(20);
    unsafe {
        let (mut level, mut window_bits, mut maximum_window_bits) = (0u32, 0u32, 0u32);
        Check::ok(brotli::umilib_codec_brotli_brotli_config_defaults(
            &mut level,
            &mut window_bits,
            &mut maximum_window_bits,
        ));
        assert_eq!((level, window_bits, maximum_window_bits), (6, 22, 24));
        let mut compressor: *mut BrotliCompressor = ptr::null_mut();
        Check::ok(brotli::umilib_codec_brotli_brotli_compressor_new(9, 16, &mut compressor));
        let mut stream = Buffer::EMPTY;
        Check::ok(brotli::compressor::compress_to_vec(compressor, data.as_ptr(), data.len(), &mut stream));
        // A decompressor limited to WBITS 15 rejects the stream of WBITS 16; one of 16 reads it.
        let mut decompressor: *mut BrotliDecompressor = ptr::null_mut();
        Check::ok(brotli::umilib_codec_brotli_brotli_decompressor_new(15, &mut decompressor));
        let mut out = Buffer::EMPTY;
        let (input, length) = (stream.as_slice().as_ptr(), stream.as_slice().len());
        Check::fails(
            brotli::decompressor::decompress_to_vec(decompressor, input, length, data.len(), &mut out),
            "codec",
            "LimitExceeded",
        );
        brotli::decompressor::free(decompressor);
        Check::ok(brotli::umilib_codec_brotli_brotli_decompressor_new(16, &mut decompressor));
        Check::ok(brotli::decompressor::decompress_to_vec(decompressor, input, length, data.len(), &mut out));
        assert_eq!(out.as_slice(), data);
        // Streaming: the stream ends with its last meta-block, before the bytes after it.
        Check::ok(brotli::decompressor::reset(decompressor));
        let mut extended = stream.as_slice().to_vec();
        extended.extend_from_slice(b"after");
        let mut room = vec![0u8; data.len()];
        let mut progress = Progress::default();
        Check::ok(brotli::decompressor::decompress(
            decompressor,
            extended.as_ptr(),
            extended.len(),
            room.as_mut_ptr(),
            room.len(),
            &mut progress,
        ));
        assert_eq!((progress.consumed, progress.produced, progress.finished), (length, data.len(), true));
        assert_eq!(room, data);
        Check::ok(brotli::decompressor::finish(decompressor));
        Check::fails(
            brotli::umilib_codec_brotli_brotli_compressor_new(12, 22, &mut compressor),
            "codec",
            "InvalidParameter",
        );
        Check::fails(
            brotli::umilib_codec_brotli_brotli_decompressor_new(9, &mut decompressor),
            "codec",
            "InvalidParameter",
        );
        umilib::ffi::umilib_ffi_buffer_free(&mut out);
        umilib::ffi::umilib_ffi_buffer_free(&mut stream);
        brotli::compressor::free(compressor);
        brotli::decompressor::free(decompressor);
    }
}

#[test]
fn xz_codecs_and_filters_stream_through_the_c_abi() {
    use umilib::codec::filter::bcj::BCJFilter;
    use umilib::codec::filter::delta::DeltaFilter;
    use umilib::codec::xz::{XZCompressor, XZDecompressor};
    use umilib::ffi::codec::filter::{bcj, delta};
    use umilib::ffi::codec::xz::{self, XZFilterFlags};

    let data = b"abracadabra \xE8\x00\x00\x00\x00 abracadabra".repeat(30);
    unsafe {
        let (mut level, mut check, mut maximum, mut multiple) = (0u32, 0u8, 0u64, false);
        Check::ok(xz::umilib_codec_xz_xz_config_defaults(&mut level, &mut check, &mut maximum, &mut multiple));
        assert_eq!((level, check, maximum, multiple), (6, 4, 1 << 26, true));
        // Delta (distance 2) and x86 before LZMA2, SHA-256, Blocks of 500 bytes.
        let filters = [XZFilterFlags { id: 0x03, value: 2 }, XZFilterFlags { id: 0x04, value: 0 }];
        let mut compressor: *mut XZCompressor = ptr::null_mut();
        Check::ok(xz::umilib_codec_xz_xz_compressor_new(1, 0, 0x0A, 500, filters.as_ptr(), 2, &mut compressor));
        let mut stream = Buffer::EMPTY;
        Check::ok(xz::compressor::compress_to_vec(compressor, data.as_ptr(), data.len(), &mut stream));
        let mut decompressor: *mut XZDecompressor = ptr::null_mut();
        Check::ok(xz::umilib_codec_xz_xz_decompressor_new(1 << 26, true, &mut decompressor));
        let mut out = Buffer::EMPTY;
        let (input, length) = (stream.as_slice().as_ptr(), stream.as_slice().len());
        Check::ok(xz::decompressor::decompress_to_vec(decompressor, input, length, data.len(), &mut out));
        assert_eq!(out.as_slice(), data);
        let (mut streams, mut stream_check) = (0u64, 0u8);
        Check::ok(xz::umilib_codec_xz_xz_decompressor_streams(decompressor, &mut streams, &mut stream_check));
        assert_eq!((streams, stream_check), (1, 0x0A));
        // A reserved Check, an unknown filter, LZMA2 among the filters before LZMA2.
        Check::fails(
            xz::umilib_codec_xz_xz_compressor_new(6, 0, 0x02, 0, ptr::null(), 0, &mut compressor),
            "ffi",
            "InvalidArgument",
        );
        let unknown = [XZFilterFlags { id: 0x7F, value: 0 }];
        Check::fails(
            xz::umilib_codec_xz_xz_compressor_new(6, 0, 4, 0, unknown.as_ptr(), 1, &mut compressor),
            "ffi",
            "InvalidArgument",
        );
        let lzma2 = [XZFilterFlags { id: 0x21, value: 1 << 20 }];
        Check::fails(
            xz::umilib_codec_xz_xz_compressor_new(6, 0, 4, 0, lzma2.as_ptr(), 1, &mut compressor),
            "codec",
            "InvalidParameter",
        );
        umilib::ffi::umilib_ffi_buffer_free(&mut out);
        umilib::ffi::umilib_ffi_buffer_free(&mut stream);
        xz::compressor::free(compressor);
        xz::decompressor::free(decompressor);

        // The filters on their own, in place.
        let mut x86: *mut BCJFilter = ptr::null_mut();
        Check::ok(bcj::umilib_codec_filter_bcj_bcj_filter_new(0, 0, &mut x86));
        let mut bytes = [0xE8, 0, 0, 0, 0, 0x90];
        let mut converted = 0usize;
        Check::ok(bcj::filter::encode(x86, bytes.as_mut_ptr(), bytes.len(), &mut converted));
        assert_eq!(bytes[..5], [0xE8, 5, 0, 0, 0]);
        let mut lookahead = 0usize;
        Check::ok(bcj::filter::lookahead(x86, &mut lookahead));
        assert!(bytes.len() - converted <= lookahead);
        Check::ok(bcj::filter::reset(x86));
        Check::ok(bcj::filter::decode(x86, bytes.as_mut_ptr(), bytes.len(), &mut converted));
        assert_eq!(bytes, [0xE8, 0, 0, 0, 0, 0x90]);
        let (mut architecture, mut start) = (9u8, 9u32);
        Check::ok(bcj::umilib_codec_filter_bcj_bcj_filter_parameters(x86, &mut architecture, &mut start));
        assert_eq!((architecture, start), (0, 0));
        let mut alignment = 0u32;
        Check::ok(bcj::umilib_codec_filter_bcj_bcj_architecture_alignment(2, &mut alignment));
        assert_eq!(alignment, 16);
        Check::fails(bcj::umilib_codec_filter_bcj_bcj_filter_new(8, 0, &mut x86), "ffi", "InvalidArgument");
        Check::fails(bcj::umilib_codec_filter_bcj_bcj_filter_new(3, 2, &mut x86), "codec", "InvalidParameter");
        bcj::filter::free(x86);
        let mut delta_filter: *mut DeltaFilter = ptr::null_mut();
        Check::ok(delta::umilib_codec_filter_delta_delta_filter_new(1, &mut delta_filter));
        let mut bytes = [5u8, 7, 7, 1];
        Check::ok(delta::filter::encode(delta_filter, bytes.as_mut_ptr(), 4, &mut converted));
        assert_eq!((bytes, converted), ([5, 2, 0, 0xFA], 4));
        Check::fails(
            delta::umilib_codec_filter_delta_delta_filter_new(257, &mut delta_filter),
            "codec",
            "InvalidParameter",
        );
        delta::filter::free(delta_filter);
    }
}

#[test]
fn mail_messages_through_the_c_abi() {
    use umilib::codec::mail::{MailConfig, MailDate};
    use umilib::ffi::codec::mail::*;

    let message = b"From: \"Joe Q. Public\" <john.q.public@example.com>\r\n\
To: A Group:Ed Jones <c@a.test>,joe@where.test;\r\n\
Date: Tue, 1 Jul 2003 10:52:37 +0200\r\n\
Subject: =?ISO-8859-1?Q?Caf=E9?=\r\n\
Content-Type: multipart/mixed; boundary=b\r\n\
\r\n\
--b\r\n\
\r\n\
one\r\n\
--b\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"../x.bin\"\r\n\
\r\n\
aGVsbG8=\r\n\
--b--\r\n";
    unsafe {
        let mut config = MailConfig {
            maximum_length: 0,
            maximum_field_length: 0,
            maximum_fields: 0,
            maximum_parts: 0,
            maximum_depth: 0,
            utf8: false,
        };
        Check::ok(umilib_codec_mail_mail_config_default(&mut config));
        assert_eq!(config, MailConfig::default());
        // The message: its fields, its validity, written back.
        let mut fields: *mut umilib::codec::mail::MailFields = ptr::null_mut();
        let mut body = Buffer::EMPTY;
        Check::ok(umilib_codec_mail_mail_message_decode(
            message.as_ptr(),
            message.len(),
            config,
            &mut fields,
            &mut body,
        ));
        let mut count = 0;
        Check::ok(umilib_codec_mail_mail_fields_count(fields, &mut count));
        assert_eq!(count, 5);
        let (mut name, mut value) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_codec_mail_mail_fields_get(fields, 3, &mut name, &mut value));
        assert_eq!(name.as_slice(), b"Subject");
        let mut subject = Buffer::EMPTY;
        Check::ok(umilib_codec_mail_mime_encoded_word_decode_text(
            value.as_slice().as_ptr(),
            value.as_slice().len(),
            &mut subject,
        ));
        assert_eq!(subject.as_slice(), "Caf\u{e9}".as_bytes());
        Check::fails(umilib_codec_mail_mail_fields_get(fields, 5, &mut name, &mut value), "codec.mail", "NoSuchEntry");
        Check::ok(umilib_codec_mail_mail_message_validate(fields, body.as_slice().as_ptr(), body.as_slice().len()));
        Check::fails(
            umilib_codec_mail_mail_fields_push(fields, b"Bad Name".as_ptr(), 8, b"x".as_ptr(), 1),
            "codec.mail",
            "Syntax",
        );
        let mut written = Buffer::EMPTY;
        Check::ok(umilib_codec_mail_mail_message_encode(
            fields,
            body.as_slice().as_ptr(),
            body.as_slice().len(),
            &mut written,
        ));
        assert_eq!(written.as_slice(), message);
        for buffer in [&mut name, &mut value, &mut subject, &mut body, &mut written] {
            umilib::ffi::umilib_ffi_buffer_free(buffer);
        }
        umilib_codec_mail_mail_fields_free(fields);

        // The address list: a group of two.
        let to = b"A Group:Ed Jones <c@a.test>,joe@where.test;";
        let mut addresses: *mut Vec<umilib::codec::mail::MailAddress> = ptr::null_mut();
        Check::ok(umilib_codec_mail_mail_address_parse_list(to.as_ptr(), to.len(), false, &mut addresses));
        let (mut group, mut has_name, mut members) = (false, false, 0);
        let mut group_name = Buffer::EMPTY;
        Check::ok(umilib_codec_mail_mail_addresses_get(
            addresses,
            0,
            &mut group,
            &mut has_name,
            &mut group_name,
            &mut members,
        ));
        assert!(group && has_name && members == 2);
        assert_eq!(group_name.as_slice(), b"A Group");
        let (mut mailbox_name, mut local, mut domain) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_codec_mail_mail_addresses_mailbox(
            addresses,
            0,
            0,
            &mut has_name,
            &mut mailbox_name,
            &mut local,
            &mut domain,
        ));
        assert_eq!(
            (mailbox_name.as_slice(), local.as_slice(), domain.as_slice()),
            (&b"Ed Jones"[..], &b"c"[..], &b"a.test"[..])
        );
        let mut empty: *mut Vec<umilib::codec::mail::MailAddress> = ptr::null_mut();
        Check::ok(umilib_codec_mail_mail_addresses_new(&mut empty));
        Check::fails(
            umilib_codec_mail_mail_addresses_push_member(empty, ptr::null(), 0, b"x".as_ptr(), 1, b"y".as_ptr(), 1),
            "codec.mail",
            "NotAGroup",
        );
        umilib_codec_mail_mail_addresses_free(empty);
        let mut formatted = Buffer::EMPTY;
        Check::ok(umilib_codec_mail_mail_addresses_format(addresses, &mut formatted));
        assert_eq!(formatted.as_slice(), b"A Group: Ed Jones <c@a.test>, joe@where.test;");
        for buffer in [&mut group_name, &mut mailbox_name, &mut local, &mut domain, &mut formatted] {
            umilib::ffi::umilib_ffi_buffer_free(buffer);
        }
        umilib_codec_mail_mail_addresses_free(addresses);

        // A date.
        let mut date = MailDate::new(0, 0);
        Check::ok(umilib_codec_mail_mail_date_parse(b"Tue, 1 Jul 2003 10:52:37 +0200".as_ptr(), 30, &mut date));
        assert_eq!(date, MailDate::new(1057049557, 120));

        // The entity: two parts, the second Base64 with a disposition.
        let mut entity: *mut umilib::codec::mail::MIMEEntity = ptr::null_mut();
        Check::ok(umilib_codec_mail_mime_entity_decode(message.as_ptr(), message.len(), config, &mut entity));
        let mut parts = 0;
        Check::ok(umilib_codec_mail_mime_entity_part_count(entity, &mut parts));
        assert_eq!(parts, 2);
        let mut part: *mut umilib::codec::mail::MIMEEntity = ptr::null_mut();
        Check::ok(umilib_codec_mail_mime_entity_part(entity, 1, &mut part));
        let mut data = Buffer::EMPTY;
        Check::ok(umilib_codec_mail_mime_entity_data(part, message.as_ptr(), message.len(), &mut data));
        assert_eq!(data.as_slice(), b"hello");
        let mut has_disposition = false;
        let mut disposition: *mut umilib::codec::mail::MIMEDisposition = ptr::null_mut();
        Check::ok(umilib_codec_mail_mime_entity_disposition(part, &mut has_disposition, &mut disposition));
        assert!(has_disposition);
        let (mut has_filename, mut filename) = (false, Buffer::EMPTY);
        Check::ok(umilib_codec_mail_mime_disposition_filename(disposition, &mut has_filename, &mut filename));
        assert!(has_filename);
        assert_eq!(filename.as_slice(), b"x.bin");
        let mut has_message = true;
        let mut encapsulated: *mut umilib::codec::mail::MIMEEntity = ptr::null_mut();
        Check::ok(umilib_codec_mail_mime_entity_message(part, &mut has_message, &mut encapsulated));
        assert!(!has_message && encapsulated.is_null());
        let mut content_type: *mut umilib::codec::mail::MIMEContentType = ptr::null_mut();
        Check::ok(umilib_codec_mail_mime_entity_content_type(entity, &mut content_type));
        let (mut has_boundary, mut boundary) = (false, Buffer::EMPTY);
        Check::ok(umilib_codec_mail_mime_content_type_boundary(content_type, &mut has_boundary, &mut boundary));
        assert!(has_boundary);
        assert_eq!(boundary.as_slice(), b"b");
        for buffer in [&mut data, &mut filename, &mut boundary] {
            umilib::ffi::umilib_ffi_buffer_free(buffer);
        }
        umilib_codec_mail_mime_content_type_free(content_type);
        umilib_codec_mail_mime_disposition_free(disposition);
        umilib_codec_mail_mime_entity_free(part);
        umilib_codec_mail_mime_entity_free(entity);

        // Character sets by number; an unknown number is refused.
        let mut text = Buffer::EMPTY;
        Check::ok(umilib_codec_mail_mime_charset_decode(2, b"\xe9".as_ptr(), 1, &mut text));
        assert_eq!(text.as_slice(), "\u{e9}".as_bytes());
        umilib::ffi::umilib_ffi_buffer_free(&mut text);
        Check::fails(
            umilib_codec_mail_mime_charset_decode(9, b"x".as_ptr(), 1, &mut text),
            "codec.mail",
            "UnknownValue",
        );
    }
}

#[test]
fn uri_references_and_forms_through_the_c_abi() {
    use umilib::codec::uri::URIReference;
    use umilib::ffi::codec::uri::*;

    fn take(buffer: &mut Buffer) -> String {
        let text = String::from_utf8(buffer.as_slice().to_vec()).unwrap();
        unsafe { umilib::ffi::umilib_ffi_buffer_free(buffer) };
        text
    }

    unsafe {
        // A reference read, its components, and its target against the base of RFC 3986 §5.4.
        let text = "../g;x?y#s";
        let mut reference: *mut URIReference = ptr::null_mut();
        Check::ok(umilib_codec_uri_uri_reference_parse(text.as_ptr(), text.len(), &mut reference));
        let base_text = "http://a/b/c/d;p?q";
        let mut base: *mut URIReference = ptr::null_mut();
        Check::ok(umilib_codec_uri_uri_reference_parse(base_text.as_ptr(), base_text.len(), &mut base));
        let mut target: *mut URIReference = ptr::null_mut();
        Check::ok(umilib_codec_uri_uri_reference_resolve(reference, base, &mut target));
        let mut written = Buffer::EMPTY;
        Check::ok(umilib_codec_uri_uri_reference_format(target, &mut written));
        assert_eq!(take(&mut written), "http://a/b/g;x?y#s");
        Check::fails(umilib_codec_uri_uri_reference_resolve(base, reference, &mut target), "codec.uri", "NotAbsolute");

        let (mut has, mut has_userinfo, mut has_port) = (false, true, true);
        let (mut userinfo, mut host, mut port) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_codec_uri_uri_reference_authority(
            target,
            &mut has,
            &mut has_userinfo,
            &mut userinfo,
            &mut host,
            &mut has_port,
            &mut port,
        ));
        assert!(has && !has_userinfo && !has_port);
        assert_eq!(
            (take(&mut userinfo), take(&mut host), take(&mut port)),
            (String::new(), "a".to_string(), String::new())
        );
        let mut query = Buffer::EMPTY;
        Check::ok(umilib_codec_uri_uri_reference_query(target, &mut has, &mut query));
        assert!(has);
        assert_eq!(take(&mut query), "y");
        // One output given twice is refused before anything is written.
        let mut same = false;
        Check::fails(
            umilib_codec_uri_uri_reference_authority(
                target,
                &mut same,
                &mut same,
                &mut userinfo,
                &mut host,
                &mut has_port,
                &mut port,
            ),
            "ffi",
            "InvalidArgument",
        );

        // Built component by component, then checked and normalized (§6.2.2).
        let mut built: *mut URIReference = ptr::null_mut();
        Check::ok(umilib_codec_uri_uri_reference_new(&mut built));
        Check::ok(umilib_codec_uri_uri_reference_set_scheme(built, b"HTTP".as_ptr(), 4));
        Check::ok(umilib_codec_uri_uri_reference_set_authority(
            built,
            true,
            ptr::null(),
            0,
            b"EXAMPLE.com".as_ptr(),
            11,
            b"".as_ptr(),
            0,
        ));
        Check::ok(umilib_codec_uri_uri_reference_set_path(built, b"/a/./%7e".as_ptr(), 8));
        Check::ok(umilib_codec_uri_uri_reference_check(built));
        let mut normalized: *mut URIReference = ptr::null_mut();
        Check::ok(umilib_codec_uri_uri_reference_normalize(built, &mut normalized));
        Check::ok(umilib_codec_uri_uri_reference_format(normalized, &mut written));
        assert_eq!(take(&mut written), "http://example.com/a/~");
        Check::ok(umilib_codec_uri_uri_reference_set_path(built, b"a".as_ptr(), 1));
        Check::fails(umilib_codec_uri_uri_reference_check(built), "codec.uri", "Syntax");
        let mut absolute = false;
        Check::ok(umilib_codec_uri_uri_reference_is_absolute(built, &mut absolute));
        assert!(absolute);
        Check::ok(umilib_codec_uri_uri_reference_set_scheme(built, ptr::null(), 0));
        Check::ok(umilib_codec_uri_uri_reference_is_relative(built, &mut absolute));
        assert!(absolute);
        assert_eq!((*built).scheme, None);
        Check::fails(
            umilib_codec_uri_uri_reference_parse(b"http://a b".as_ptr(), 10, &mut built),
            "codec.uri",
            "Syntax",
        );
        Check::ok(umilib_codec_uri_uri_reference_remove_dot_segments(b"/a/b/c/./../../g".as_ptr(), 16, &mut written));
        assert_eq!(take(&mut written), "/a/g");
        for handle in [reference, base, target, built, normalized] {
            umilib_codec_uri_uri_reference_free(handle);
        }

        let mut kind = 9;
        Check::ok(umilib_codec_uri_uri_authority_host_kind(b"[v1.x]".as_ptr(), 6, &mut kind));
        assert_eq!(kind, URIHostKindValue::IPVFUTURE);
        Check::ok(umilib_codec_uri_uri_authority_parse(
            b"u@[::1]:8".as_ptr(),
            9,
            &mut has_userinfo,
            &mut userinfo,
            &mut host,
            &mut has_port,
            &mut port,
        ));
        assert!(has_userinfo && has_port);
        assert_eq!(
            (take(&mut userinfo), take(&mut host), take(&mut port)),
            ("u".to_string(), "[::1]".to_string(), "8".to_string())
        );

        // Percent-encoding with the kept octets passed as a list.
        Check::ok(umilib_codec_uri_uri_percent_encode(b"a/b c".as_ptr(), 5, b"/".as_ptr(), 1, &mut written));
        assert_eq!(take(&mut written), "%61/%62%20%63");
        Check::fails(umilib_codec_uri_uri_percent_decode(b"%4".as_ptr(), 2, &mut written), "codec.uri", "Percent");
        Check::fails(umilib_codec_uri_uri_percent_decode_text(b"%FF".as_ptr(), 3, &mut written), "codec.uri", "UTF8");
        let (mut found, mut digit) = (false, 0);
        Check::ok(umilib_codec_uri_uri_percent_digit(b'e', &mut found, &mut digit));
        assert!(found && digit == 14);

        // The pairs of a form, and the pairs written.
        let body = b"grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
        let mut pairs: *mut Vec<(String, String)> = ptr::null_mut();
        Check::ok(umilib_codec_uri_uri_form_parse(body.as_ptr(), body.len(), &mut pairs));
        let mut count = 0;
        Check::ok(umilib_codec_uri_uri_form_pairs_count(pairs, &mut count));
        assert_eq!(count, 2);
        let (mut name, mut value) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_codec_uri_uri_form_pairs_get(pairs, 1, &mut name, &mut value));
        assert_eq!(
            (take(&mut name), take(&mut value)),
            ("redirect_uri".to_string(), "https://client.example.com/cb".to_string())
        );
        Check::fails(umilib_codec_uri_uri_form_pairs_get(pairs, 2, &mut name, &mut value), "codec.uri", "NoSuchPair");
        Check::ok(umilib_codec_uri_uri_form_pairs_push(pairs, "é".as_ptr(), 2, b"a b".as_ptr(), 3));
        Check::ok(umilib_codec_uri_uri_form_encode(pairs, &mut written));
        assert_eq!(
            take(&mut written),
            "grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&%C3%A9=a+b"
        );
        umilib_codec_uri_uri_form_pairs_free(pairs);
        Check::fails(umilib_codec_uri_uri_form_parse(b"a=%FF".as_ptr(), 5, &mut pairs), "codec.uri", "UTF8");
    }
}
