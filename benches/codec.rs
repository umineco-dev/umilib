//! Benchmarks of `umilib::codec`.

use std::hint::black_box;

use umilib::platform::bench::Bench;
#[cfg(umilib_feature = "codec-base")]
use umilib::{codec::base::Encoding, platform::bench::Throughput};

pub struct Benchmarks;

impl Benchmarks {
    /// Text-like data of `length` bytes: words of a small vocabulary with repeats.
    pub fn text(length: usize) -> Vec<u8> {
        const WORDS: [&str; 10] =
            ["the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog ", "compression ", "\n"];
        let mut state = 0x2545_F491u32;
        let mut out = Vec::with_capacity(length + 16);
        while out.len() < length {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.extend_from_slice(WORDS[state as usize % WORDS.len()].as_bytes());
        }
        out.truncate(length);
        out
    }

    /// Benchmarks compressing and decompressing `data` with a pair of a compressed format.
    #[cfg(any(
        umilib_feature = "codec-brotli",
        umilib_feature = "codec-deflate",
        umilib_feature = "codec-huffman",
        umilib_feature = "codec-lz4",
        umilib_feature = "codec-lz77",
        umilib_feature = "codec-lz78",
        umilib_feature = "codec-lzma",
        umilib_feature = "codec-lzss",
        umilib_feature = "codec-rle",
        umilib_feature = "codec-xz",
        umilib_feature = "codec-zstandard"
    ))]
    pub fn compression(
        bench: &mut Bench,
        name: &str,
        compressor: &mut dyn umilib::codec::Compressor,
        decompressor: &mut dyn umilib::codec::Decompressor,
        data: &[u8],
    ) {
        let throughput = umilib::platform::bench::Throughput::Bytes(data.len() as u64);
        bench.run(&format!("codec-{name}-compress-{}", data.len()), Some(throughput), || {
            compressor.reset();
            black_box(compressor.compress_to_vec(black_box(data)).unwrap());
        });
        compressor.reset();
        let stream = compressor.compress_to_vec(data).unwrap();
        bench.run(&format!("codec-{name}-decompress-{}", data.len()), Some(throughput), || {
            decompressor.reset();
            black_box(decompressor.decompress_to_vec(black_box(&stream), data.len()).unwrap());
        });
    }

    pub fn run(bench: &mut Bench) {
        #[cfg(umilib_feature = "codec-base")]
        {
            let data: Vec<u8> = (0..4096u32).map(|index| (index * 31) as u8).collect();
            let encodings: &[(&str, &dyn Encoding)] = &[
                #[cfg(umilib_feature = "codec-base-base16")]
                ("base16", &umilib::codec::base::base16::Base16::LOWER),
                #[cfg(umilib_feature = "codec-base-base32")]
                ("base32", &umilib::codec::base::base32::Base32::STANDARD),
                #[cfg(umilib_feature = "codec-base-base64")]
                ("base64", &umilib::codec::base::base64::Base64::STANDARD),
                #[cfg(umilib_feature = "codec-base-base85")]
                ("base85", &umilib::codec::base::base85::Base85::Z85),
            ];
            for &(name, encoding) in encodings {
                let mut output = vec![0u8; encoding.maximum_encoded_length(data.len()).unwrap()];
                bench.run(&format!("codec-base-{name}-encode-4096"), Some(Throughput::Bytes(4096)), || {
                    black_box(encoding.encode_to_slice(black_box(&data), &mut output).unwrap());
                });
                let text = encoding.encode(&data);
                let mut decoded = vec![0u8; encoding.maximum_decoded_length(text.len())];
                bench.run(&format!("codec-base-{name}-decode-4096"), Some(Throughput::Bytes(4096)), || {
                    black_box(encoding.decode_to_slice(black_box(text.as_bytes()), &mut decoded).unwrap());
                });
            }
            #[cfg(umilib_feature = "codec-base-base58")]
            {
                let address = [0x5Au8; 25];
                bench.run("codec-base-base58-encode-25", Some(Throughput::Bytes(25)), || {
                    black_box(umilib::codec::base::base58::Base58::BITCOIN.encode(black_box(&address)));
                });
            }
        }
        #[cfg(umilib_feature = "codec-stringprep")]
        {
            use umilib::codec::stringprep::{
                LDAPMatching, LDAPPrep, LDAPString, NormalizationForm, StringPrepProfile, Unassigned,
            };
            use umilib::platform::bench::Throughput;
            // Latin with combining marks, Hangul, compatibility characters and spaces.
            let text = "Caf\u{e9} e\u{301}\u{327} \u{d55c}\u{ad6d}\u{c5b4} \u{fb01}\u{2168} \u{a0}  ".repeat(16);
            let length = text.len() as u64;
            for (name, form) in [("nfc", NormalizationForm::NFC), ("nfkc", NormalizationForm::NFKC)] {
                bench.run(&format!("codec-stringprep-{name}"), Some(Throughput::Bytes(length)), || {
                    black_box(form.normalize(black_box(&text)));
                });
            }
            bench.run("codec-stringprep-saslprep", Some(Throughput::Bytes(length)), || {
                black_box(StringPrepProfile::SASLPREP.prepare(black_box(&text), Unassigned::Allowed).unwrap());
            });
            bench.run("codec-stringprep-ldapprep-case-ignore", Some(Throughput::Bytes(length)), || {
                black_box(LDAPPrep::prepare(black_box(&text), LDAPMatching::CaseIgnore, LDAPString::Value).unwrap());
            });
        }
        #[cfg(umilib_feature = "codec-json")]
        {
            use umilib::codec::json::{JSONConfig, JSONReader, JSONValue};
            let mut text = String::from("[");
            for index in 0..200 {
                if index > 0 {
                    text.push(',');
                }
                text.push_str(&format!(
                    r#"{{"id":{index},"name":"item \u00e9 {index}","price":{index}.25,"tags":["a","b"],"ok":true}}"#
                ));
            }
            text.push(']');
            let length = text.len() as u64;
            bench.run("codec-json-reader-validate", Some(umilib::platform::bench::Throughput::Bytes(length)), || {
                JSONReader::new(black_box(text.as_bytes()), JSONConfig::default()).unwrap().validate().unwrap();
            });
            bench.run("codec-json-value-decode", Some(umilib::platform::bench::Throughput::Bytes(length)), || {
                black_box(JSONValue::decode(black_box(text.as_bytes()), JSONConfig::default()).unwrap());
            });
            let value = JSONValue::parse(&text).unwrap();
            bench.run("codec-json-value-encode", Some(umilib::platform::bench::Throughput::Bytes(length)), || {
                black_box(black_box(&value).encode());
            });
        }
        #[cfg(all(umilib_feature = "codec-asn1", umilib_feature = "codec-pem"))]
        {
            use umilib::codec::asn1::ber::BERReader;
            use umilib::codec::asn1::der::DERReader;
            use umilib::codec::pem::{PEMConfig, PEMDocument};
            let text =
                std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/codec/pem/rfc7468.txt")).unwrap();
            let documents = PEMDocument::decode_all(&text, PEMConfig::default()).unwrap();
            let certificate = documents[0].data().to_vec();
            let length = certificate.len() as u64;
            bench.run(
                "codec-pem-decode-all-rfc7468",
                Some(umilib::platform::bench::Throughput::Bytes(text.len() as u64)),
                || {
                    black_box(PEMDocument::decode_all(black_box(&text), PEMConfig::default()).unwrap());
                },
            );
            bench.run(
                "codec-asn1-der-validate-certificate",
                Some(umilib::platform::bench::Throughput::Bytes(length)),
                || {
                    DERReader::validate(black_box(&certificate), 64).unwrap();
                },
            );
            bench.run(
                "codec-asn1-ber-to-der-certificate",
                Some(umilib::platform::bench::Throughput::Bytes(length)),
                || {
                    black_box(BERReader::to_der(black_box(&certificate), 64).unwrap());
                },
            );
        }
        #[cfg(umilib_feature = "codec-hpack")]
        {
            use umilib::codec::hpack::{
                HPACKDecoder, HPACKDecoderConfig, HPACKEncoder, HPACKEncoderConfig, HPACKField, HPACKHuffman,
            };
            use umilib::platform::bench::Throughput;
            // The fields of a browser's request (RFC 7541 C.4 and common headers), on a warm table.
            let fields: Vec<HPACKField> = [
                (&b":method"[..], &b"GET"[..]),
                (b":scheme", b"https"),
                (b":authority", b"www.example.com"),
                (b":path", b"/index.html?query=1"),
                (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0"),
                (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                (b"accept-language", b"en-US,en;q=0.5"),
                (b"accept-encoding", b"gzip, deflate, br, zstd"),
                (b"cookie", b"session=0123456789abcdef0123456789abcdef"),
            ]
            .iter()
            .map(|(name, value)| HPACKField::new(name, value))
            .collect();
            let mut encoder = HPACKEncoder::new(HPACKEncoderConfig::default(), 4096);
            let mut block = Vec::new();
            encoder.encode(&fields, &mut block);
            bench.run("codec-hpack-encode-request", Some(Throughput::Elements(1)), || {
                block.clear();
                encoder.encode(black_box(&fields), &mut block);
            });
            let mut cold = Vec::new();
            HPACKEncoder::new(HPACKEncoderConfig::default(), 4096).encode(&fields, &mut cold);
            bench.run("codec-hpack-decode-request-cold", Some(Throughput::Elements(1)), || {
                black_box(HPACKDecoder::new(HPACKDecoderConfig::default()).decode(black_box(&cold)).unwrap());
            });
            let huffman = HPACKHuffman::new();
            let text = Benchmarks::text(4096);
            let mut coded = Vec::new();
            huffman.encode(&text, &mut coded);
            let mut out = Vec::new();
            bench.run("codec-hpack-huffman-encode-4096", Some(Throughput::Bytes(4096)), || {
                out.clear();
                huffman.encode(black_box(&text), &mut out);
            });
            bench.run("codec-hpack-huffman-decode-4096", Some(Throughput::Bytes(4096)), || {
                out.clear();
                huffman.decode(black_box(&coded), &mut out, 4096).unwrap();
            });
        }
        #[cfg(umilib_feature = "codec-qpack")]
        {
            use umilib::codec::hpack::HPACKField;
            use umilib::codec::qpack::{QPACKDecoder, QPACKDecoderConfig, QPACKEncoder, QPACKEncoderConfig};
            use umilib::platform::bench::Throughput;
            let fields: Vec<HPACKField> = [
                (&b":method"[..], &b"GET"[..]),
                (b":scheme", b"https"),
                (b":authority", b"www.example.com"),
                (b":path", b"/index.html"),
                (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0"),
                (b"cookie", b"session=0123456789abcdef0123456789abcdef"),
            ]
            .iter()
            .map(|(name, value)| HPACKField::new(name, value))
            .collect();
            let mut encoder = QPACKEncoder::new(QPACKEncoderConfig::default());
            let mut decoder = QPACKDecoder::new(QPACKDecoderConfig::default());
            encoder.set_peer_settings(4096, 16);
            let mut stream = 0;
            bench.run("codec-qpack-encode-decode-request", Some(Throughput::Elements(1)), || {
                let section = encoder.encode(stream, black_box(&fields));
                decoder.receive_encoder_stream(&encoder.take_instructions()).unwrap();
                black_box(decoder.decode(stream, &section).unwrap());
                encoder.receive_decoder_stream(&decoder.take_instructions()).unwrap();
                stream += 4;
            });
        }
        #[cfg(umilib_feature = "codec-uri")]
        {
            use umilib::codec::uri::{URIForm, URIReference};
            use umilib::platform::bench::Throughput;
            let text = "https://user@auth.example.com:8443/oauth/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb#top";
            bench.run("codec-uri-reference-parse", Some(Throughput::Bytes(text.len() as u64)), || {
                black_box(URIReference::parse(black_box(text)).unwrap());
            });
            let base = URIReference::parse("http://a/b/c/d;p?q").unwrap();
            let reference = URIReference::parse("../../g;x=1/./y?q#s").unwrap();
            bench.run("codec-uri-reference-resolve", None, || {
                black_box(black_box(&reference).resolve(&base).unwrap());
            });
            let messy = URIReference::parse("HTTP://Example.COM/a/./b/../c/%7e%41%2f?%5f#%2d").unwrap();
            bench.run("codec-uri-reference-normalize", None, || {
                black_box(black_box(&messy).normalize());
            });
            let pairs: Vec<(String, String)> =
                (0..64).map(|index| (format!("name{index}"), format!("value {index} & ü/é"))).collect();
            let body = URIForm::encode(&pairs);
            bench.run("codec-uri-form-parse-64", Some(Throughput::Bytes(body.len() as u64)), || {
                black_box(URIForm::parse(black_box(body.as_bytes())).unwrap());
            });
            bench.run("codec-uri-form-encode-64", Some(Throughput::Bytes(body.len() as u64)), || {
                black_box(URIForm::encode(black_box(&pairs)));
            });
        }
        #[cfg(umilib_feature = "codec-mail")]
        {
            use umilib::codec::mail::{MIMEEntity, MIMEQuotedPrintable, MailAddress, MailConfig, MailMessage};
            use umilib::platform::bench::Throughput;
            let config = MailConfig::default();
            let body = Benchmarks::text(64 * 1024);
            let mut message = b"From: John Doe <jdoe@machine.example>\r\nTo: Mary Smith <mary@example.net>, A Group:Ed Jones <c@a.test>,joe@where.test;\r\nSubject: Saying Hello\r\nDate: Fri, 21 Nov 1997 09:55:06 -0600\r\nMessage-ID: <1234@local.machine.example>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n".to_vec();
            message.extend_from_slice(&body);
            message.extend_from_slice(b"\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAwQFBgcICQ==\r\n--b--\r\n");
            let length = message.len() as u64;
            bench.run("codec-mail-message-decode-64k", Some(Throughput::Bytes(length)), || {
                black_box(MailMessage::decode(black_box(&message), &config).unwrap());
            });
            bench.run("codec-mail-entity-decode-64k", Some(Throughput::Bytes(length)), || {
                black_box(MIMEEntity::decode(black_box(&message), &config).unwrap());
            });
            let list = b"Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>, <boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>";
            bench.run("codec-mail-address-list-parse", Some(Throughput::Bytes(list.len() as u64)), || {
                black_box(MailAddress::parse_list(black_box(list), true).unwrap());
            });
            let binary: Vec<u8> = (0..64 * 1024u32).map(|index| (index * 7) as u8).collect();
            let quoted = MIMEQuotedPrintable::new(true);
            let mut encoded = Vec::new();
            quoted.encode(&binary, &mut encoded);
            bench.run("codec-mail-quoted-printable-encode-64k", Some(Throughput::Bytes(binary.len() as u64)), || {
                let mut out = Vec::with_capacity(encoded.len());
                quoted.encode(black_box(&binary), &mut out);
                black_box(out);
            });
            bench.run("codec-mail-quoted-printable-decode-64k", Some(Throughput::Bytes(binary.len() as u64)), || {
                black_box(quoted.decode(black_box(&encoded)));
            });
        }
        #[cfg(umilib_feature = "codec-huffman")]
        {
            use umilib::codec::huffman::adaptive::{AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor};
            use umilib::codec::huffman::canonical::{
                CanonicalHuffmanCompressor, CanonicalHuffmanConfig, CanonicalHuffmanDecompressor,
            };
            let data = Benchmarks::text(1 << 16);
            let mut canonical = CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig::default()).unwrap();
            Benchmarks::compression(
                bench,
                "huffman-canonical",
                &mut canonical,
                &mut CanonicalHuffmanDecompressor::new(),
                &data,
            );
            Benchmarks::compression(
                bench,
                "huffman-adaptive",
                &mut AdaptiveHuffmanCompressor::new(),
                &mut AdaptiveHuffmanDecompressor::new(),
                &data,
            );
        }
        let data = Benchmarks::text(1 << 16);
        #[cfg(umilib_feature = "codec-deflate")]
        {
            use umilib::codec::deflate::{DeflateCompressor, DeflateConfig, DeflateDecompressor};
            for level in [1, 6, 9] {
                let mut compressor = DeflateCompressor::new(DeflateConfig { level, window_bits: 15 }).unwrap();
                Benchmarks::compression(
                    bench,
                    &format!("deflate-level{level}"),
                    &mut compressor,
                    &mut DeflateDecompressor::default(),
                    &data,
                );
            }
        }
        #[cfg(umilib_feature = "codec-zlib")]
        {
            use umilib::codec::deflate::DeflateConfig;
            use umilib::codec::zlib::{ZlibCompressor, ZlibDecompressor};
            let mut compressor = ZlibCompressor::new(DeflateConfig::default()).unwrap();
            Benchmarks::compression(bench, "zlib", &mut compressor, &mut ZlibDecompressor::default(), &data);
        }
        #[cfg(umilib_feature = "codec-gzip")]
        {
            use umilib::codec::gzip::{GzipCompressor, GzipConfig, GzipDecompressor};
            let mut compressor = GzipCompressor::new(GzipConfig::default()).unwrap();
            Benchmarks::compression(bench, "gzip", &mut compressor, &mut GzipDecompressor::default(), &data);
        }
        #[cfg(umilib_feature = "codec-lz4")]
        {
            use umilib::codec::lz4::{LZ4Compressor, LZ4Config, LZ4Decompressor};
            for level in [1, 9] {
                let mut compressor = LZ4Compressor::new(LZ4Config { level, ..LZ4Config::default() }).unwrap();
                Benchmarks::compression(
                    bench,
                    &format!("lz4-level{level}"),
                    &mut compressor,
                    &mut LZ4Decompressor::default(),
                    &data,
                );
            }
        }
        #[cfg(umilib_feature = "codec-lzma")]
        {
            use umilib::codec::lzma::{
                LZMA2Compressor, LZMA2Decompressor, LZMA2DecompressorConfig, LZMACompressor, LZMAConfig,
                LZMADecompressor,
            };
            for level in [1, 6] {
                let config = LZMAConfig { level, ..LZMAConfig::default() };
                let mut compressor = LZMACompressor::new(config).unwrap();
                Benchmarks::compression(
                    bench,
                    &format!("lzma-level{level}"),
                    &mut compressor,
                    &mut LZMADecompressor::default(),
                    &data,
                );
            }
            let mut compressor = LZMA2Compressor::new(LZMAConfig::default()).unwrap();
            let config = LZMA2DecompressorConfig { dictionary_size: compressor.dictionary_size() };
            Benchmarks::compression(
                bench,
                "lzma2",
                &mut compressor,
                &mut LZMA2Decompressor::new(config).unwrap(),
                &data,
            );
        }
        #[cfg(umilib_feature = "codec-brotli")]
        {
            use umilib::codec::brotli::{BrotliCompressor, BrotliConfig, BrotliDecompressor};
            for level in [1, 6, 11] {
                let mut compressor = BrotliCompressor::new(BrotliConfig { level, ..BrotliConfig::default() }).unwrap();
                Benchmarks::compression(
                    bench,
                    &format!("brotli-level{level}"),
                    &mut compressor,
                    &mut BrotliDecompressor::default(),
                    &data,
                );
            }
        }
        #[cfg(umilib_feature = "codec-xz")]
        {
            use umilib::codec::filter::bcj::BCJArchitecture;
            use umilib::codec::lzma::LZMAConfig;
            use umilib::codec::xz::{XZCompressor, XZConfig, XZDecompressor, XZFilter};
            for level in [1, 6] {
                let config = XZConfig { lzma: LZMAConfig { level, ..LZMAConfig::default() }, ..XZConfig::default() };
                let mut compressor = XZCompressor::new(config).unwrap();
                Benchmarks::compression(
                    bench,
                    &format!("xz-level{level}"),
                    &mut compressor,
                    &mut XZDecompressor::default(),
                    &data,
                );
            }
            let filters = vec![XZFilter::BCJ { architecture: BCJArchitecture::X86, start_offset: 0 }];
            let mut compressor = XZCompressor::new(XZConfig { filters, ..XZConfig::default() }).unwrap();
            Benchmarks::compression(bench, "xz-x86", &mut compressor, &mut XZDecompressor::default(), &data);
        }
        #[cfg(umilib_feature = "codec-filter")]
        {
            use umilib::codec::filter::Filter;
            let throughput = umilib::platform::bench::Throughput::Bytes(data.len() as u64);
            let mut buffer = data.clone();
            #[cfg(umilib_feature = "codec-filter-bcj")]
            for architecture in umilib::codec::filter::bcj::BCJArchitecture::ALL {
                let mut filter = umilib::codec::filter::bcj::BCJFilter::new(architecture, 0).unwrap();
                bench.run(&format!("codec-filter-bcj-{architecture:?}-{}", data.len()), Some(throughput), || {
                    filter.reset();
                    black_box(filter.encode(black_box(&mut buffer)));
                });
            }
            #[cfg(umilib_feature = "codec-filter-delta")]
            {
                let mut filter = umilib::codec::filter::delta::DeltaFilter::new(4).unwrap();
                bench.run(&format!("codec-filter-delta-{}", data.len()), Some(throughput), || {
                    black_box(filter.encode(black_box(&mut buffer)));
                });
            }
        }
        #[cfg(umilib_feature = "codec-zstandard")]
        {
            use umilib::codec::zstandard::{ZstandardCompressor, ZstandardConfig, ZstandardDecompressor};
            for level in [1, 3, 19] {
                let mut compressor =
                    ZstandardCompressor::new(ZstandardConfig { level, ..ZstandardConfig::default() }).unwrap();
                Benchmarks::compression(
                    bench,
                    &format!("zstandard-level{level}"),
                    &mut compressor,
                    &mut ZstandardDecompressor::default(),
                    &data,
                );
            }
        }
        #[cfg(umilib_feature = "codec-lz77")]
        {
            use umilib::codec::lz77::{LZ77Compressor, LZ77Config, LZ77Decompressor};
            let mut compressor = LZ77Compressor::new(LZ77Config::default()).unwrap();
            Benchmarks::compression(bench, "lz77", &mut compressor, &mut LZ77Decompressor::new(), &data);
        }
        #[cfg(umilib_feature = "codec-lz78")]
        {
            use umilib::codec::lz78::{LZ78Compressor, LZ78Config, LZ78Decompressor};
            let mut compressor = LZ78Compressor::new(LZ78Config::default()).unwrap();
            Benchmarks::compression(bench, "lz78", &mut compressor, &mut LZ78Decompressor::default(), &data);
        }
        #[cfg(umilib_feature = "codec-lzss")]
        {
            use umilib::codec::lzss::{LZSSCompressor, LZSSConfig, LZSSDecompressor};
            let mut compressor = LZSSCompressor::new(LZSSConfig::default()).unwrap();
            Benchmarks::compression(
                bench,
                "lzss",
                &mut compressor,
                &mut LZSSDecompressor::new(LZSSConfig::default()).unwrap(),
                &data,
            );
        }
        #[cfg(umilib_feature = "codec-rle")]
        {
            use umilib::codec::rle::{PackBitsCompressor, PackBitsDecompressor};
            Benchmarks::compression(
                bench,
                "packbits",
                &mut PackBitsCompressor::new(),
                &mut PackBitsDecompressor::new(),
                &data,
            );
        }
        let _ = black_box((&bench, &data));
    }
}
