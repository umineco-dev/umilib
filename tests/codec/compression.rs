//! Data and streaming drivers shared by the tests of the compressed formats.

use umilib::codec::{CompressionError, Compressor, Decompressor, Flush};

/// A deterministic generator of test data (xorshift64*).
pub struct Samples {
    state: u64,
}

impl Samples {
    pub fn new(seed: u64) -> Samples {
        Samples { state: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1 }
    }

    pub fn next(&mut self) -> u64 {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in [0, bound).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    /// `length` uniformly random bytes.
    pub fn random(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next() as u8).collect()
    }

    /// `length` bytes of words drawn from a small vocabulary, like text.
    pub fn text(&mut self, length: usize) -> Vec<u8> {
        const WORDS: [&str; 12] = [
            "the ",
            "quick ",
            "brown ",
            "fox ",
            "jumps ",
            "over ",
            "lazy ",
            "dog ",
            "and ",
            "a ",
            "compression ",
            "\n",
        ];
        let mut out = Vec::with_capacity(length + 16);
        while out.len() < length {
            out.extend_from_slice(WORDS[self.below(WORDS.len() as u64) as usize].as_bytes());
        }
        out.truncate(length);
        out
    }

    /// `length` bytes with runs and repeated sequences at various distances.
    pub fn repetitive(&mut self, length: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(length);
        while out.len() < length {
            match self.below(3) {
                0 => {
                    let byte = self.next() as u8;
                    out.extend(core::iter::repeat_n(byte, 1 + self.below(300) as usize));
                }
                1 if !out.is_empty() => {
                    let distance = 1 + self.below(out.len().min(40000) as u64) as usize;
                    for _ in 0..3 + self.below(200) as usize {
                        out.push(out[out.len() - distance]);
                    }
                }
                _ => {
                    let length = 1 + self.below(20) as usize;
                    out.extend(self.random(length));
                }
            }
        }
        out.truncate(length);
        out
    }

    /// The data sets every format is tested with.
    pub fn sets() -> Vec<(&'static str, Vec<u8>)> {
        let mut samples = Samples::new(1);
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x41]),
            ("zeros", vec![0; 100_000]),
            ("all bytes", (0..=255u8).cycle().take(3000).collect()),
            ("text", samples.text(70_000)),
            ("random", samples.random(20_000)),
            ("repetitive", samples.repetitive(150_000)),
        ]
    }
}

/// How the streams of a format end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// The stream marks its end; bytes after it are not consumed.
    Marked,
    /// The stream ends with its input ([`Decompressor::finish`]).
    Input,
}

/// Streaming drivers of a compressor and a decompressor.
pub struct Streaming;

impl Streaming {
    /// Compresses `data` in pieces of the given sizes (cycled), with the
    /// output given in pieces of `output_size`, asking for a sync flush
    /// after every `sync_every` pieces (0 for none).
    pub fn compress(
        compressor: &mut dyn Compressor,
        data: &[u8],
        pieces: &[usize],
        output_size: usize,
        sync_every: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buffer = vec![0u8; output_size];
        let (mut position, mut piece) = (0, 0);
        loop {
            let end = (position + pieces[piece % pieces.len()]).min(data.len());
            piece += 1;
            let flush = if end == data.len() {
                Flush::Finish
            } else if sync_every > 0 && piece % sync_every == 0 {
                Flush::Sync
            } else {
                Flush::None
            };
            let mut input = &data[position..end];
            loop {
                let progress = compressor.compress(input, &mut buffer, flush).expect("compression succeeds");
                input = &input[progress.consumed..];
                out.extend_from_slice(&buffer[..progress.produced]);
                if progress.finished {
                    assert!(input.is_empty() && flush == Flush::Finish);
                    return out;
                }
                // Sync and None return once the input is taken and the output delivered.
                if input.is_empty() && flush != Flush::Finish && progress.produced < buffer.len() {
                    break;
                }
            }
            position = end;
        }
    }

    /// Decompresses `stream` in input pieces of the given sizes (cycled),
    /// with outputs of `output_size` bytes; returns the data and the bytes consumed.
    pub fn decompress(
        decompressor: &mut dyn Decompressor,
        stream: &[u8],
        pieces: &[usize],
        output_size: usize,
    ) -> Result<(Vec<u8>, usize), CompressionError> {
        let mut out = Vec::new();
        let mut buffer = vec![0u8; output_size];
        let (mut position, mut piece) = (0, 0);
        let mut available = 0usize;
        loop {
            if available == position {
                available = available.saturating_add(pieces[piece % pieces.len()]).min(stream.len());
                piece += 1;
            }
            let progress = decompressor.decompress(&stream[position..available], &mut buffer)?;
            position += progress.consumed;
            out.extend_from_slice(&buffer[..progress.produced]);
            if progress.finished {
                return Ok((out, position));
            }
            if progress.consumed == 0 && progress.produced == 0 {
                if available == stream.len() {
                    decompressor.finish()?;
                    return Ok((out, position));
                }
                available = available.saturating_add(pieces[piece % pieces.len()]).min(stream.len());
                piece += 1;
            }
        }
    }

    /// Checks that `decompressor` recovers `data` from `stream` fed and
    /// drained in many piece sizes, stopping right at its end.
    pub fn check(decompressor: &mut dyn Decompressor, stream: &[u8], data: &[u8], ending: Ending) {
        let mut extended = stream.to_vec();
        if ending == Ending::Marked {
            extended.extend_from_slice(b"TRAILER");
        }
        for (pieces, output_size) in
            [(&[usize::MAX][..], 1 << 16), (&[1][..], 1), (&[7, 1, 300][..], 13), (&[4096][..], 100_000)]
        {
            decompressor.reset();
            let (out, consumed) =
                Streaming::decompress(decompressor, &extended, pieces, output_size).expect("the stream decompresses");
            assert!(out == data, "decompressed data differ (pieces {pieces:?}, output {output_size})");
            assert_eq!(consumed, stream.len(), "the decompressor stops at the end of the stream");
        }
        // An output of exactly the size of the data is enough to reach the end of the stream.
        decompressor.reset();
        let mut exact = vec![0u8; data.len()];
        let (mut position, mut produced) = (0, 0);
        loop {
            let progress =
                decompressor.decompress(&stream[position..], &mut exact[produced..]).expect("the stream decompresses");
            position += progress.consumed;
            produced += progress.produced;
            if progress.finished {
                break;
            }
            if ending == Ending::Input && position == stream.len() && progress.consumed + progress.produced == 0 {
                decompressor.finish().expect("the stream ends with its input");
                break;
            }
            assert!(progress.consumed + progress.produced > 0, "the stream ends without room past its data");
        }
        assert!(exact == data && position == stream.len());
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(stream, data.len()).as_deref(), Ok(data));
        if !data.is_empty() {
            decompressor.reset();
            assert_eq!(
                decompressor.decompress_to_vec(stream, data.len() - 1),
                Err(CompressionError::LimitExceeded { limit: data.len() as u64 - 1 })
            );
        }
        if !stream.is_empty() {
            decompressor.reset();
            let truncated = decompressor.decompress_to_vec(&stream[..stream.len() - 1], usize::MAX);
            match ending {
                Ending::Marked => assert_eq!(truncated, Err(CompressionError::UnexpectedEnd)),
                // A stream that ends with its input may end at an earlier unit, with part of the data.
                Ending::Input => match truncated {
                    Ok(prefix) => assert!(prefix.len() < data.len() && data.starts_with(&prefix)),
                    Err(error) => assert_eq!(error, CompressionError::UnexpectedEnd),
                },
            }
        }
    }

    /// Checks that after a sync flush the output so far decompresses to all
    /// the input so far, without ending the stream.
    pub fn check_sync(compressor: &mut dyn Compressor, decompressor: &mut dyn Decompressor, data: &[u8]) {
        compressor.reset();
        let prefix = Streaming::compress_sync(compressor, data);
        decompressor.reset();
        let mut out = vec![0u8; data.len() + 1];
        let mut input = &prefix[..];
        let mut produced = 0;
        loop {
            let progress = decompressor.decompress(input, &mut out[produced..]).expect("the prefix decompresses");
            input = &input[progress.consumed..];
            produced += progress.produced;
            assert!(!progress.finished, "a sync flush does not end the stream");
            if progress.consumed == 0 && progress.produced == 0 {
                break;
            }
        }
        assert!(out[..produced] == *data, "the output of a sync flush holds all the input so far");
    }

    /// The output of compressing `data` then flushing with [`Flush::Sync`].
    pub fn compress_sync(compressor: &mut dyn Compressor, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buffer = [0u8; 1000];
        let mut input = data;
        loop {
            let progress = compressor.compress(input, &mut buffer, Flush::Sync).expect("compression succeeds");
            input = &input[progress.consumed..];
            out.extend_from_slice(&buffer[..progress.produced]);
            if input.is_empty() && progress.produced < buffer.len() {
                return out;
            }
        }
    }

    /// Round trips every sample set through the pair, whole and in pieces
    /// with sync flushes (if the format `syncs`; otherwise a sync flush must
    /// fail with `InvalidParameter`).
    pub fn round_trip(
        compressor: &mut dyn Compressor,
        decompressor: &mut dyn Decompressor,
        ending: Ending,
        syncs: bool,
    ) {
        if !syncs {
            compressor.reset();
            assert_eq!(
                compressor.compress(b"data", &mut [0u8; 64], Flush::Sync),
                Err(CompressionError::InvalidParameter)
            );
        }
        for (name, data) in Samples::sets() {
            compressor.reset();
            let stream = compressor.compress_to_vec(&data).expect("compression succeeds");
            decompressor.reset();
            assert_eq!(decompressor.decompress_to_vec(&stream, data.len()).as_deref(), Ok(&data[..]), "{name}");
            Streaming::check(decompressor, &stream, &data, ending);
            if syncs {
                Streaming::check_sync(compressor, decompressor, &data);
            }
            for (pieces, output_size, sync_every) in
                [(&[1][..], 1, 0), (&[1000, 3, 77][..], 50, 2), (&[5000][..], 7, 1)]
            {
                let sync_every = if syncs { sync_every } else { 0 };
                compressor.reset();
                let stream = Streaming::compress(compressor, &data, pieces, output_size, sync_every);
                decompressor.reset();
                assert_eq!(
                    decompressor.decompress_to_vec(&stream, data.len()).as_deref(),
                    Ok(&data[..]),
                    "{name} in pieces {pieces:?}"
                );
            }
        }
    }
}
