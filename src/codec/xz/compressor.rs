use alloc::vec;
use alloc::vec::Vec;

use super::{XZBlockHeader, XZChecksum, XZConfig, XZFilter, XZFilterCoder, XZFormat, XZIndex};
use crate::codec::filter::FilterChain;
use crate::codec::lzma::LZMA2Compressor;
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into a .xz Stream: a Stream Header, Blocks (one, or one per
/// [`XZConfig::block_size`] bytes) of the configured filters and LZMA2,
/// each with its Check, the Index and the Stream Footer. Block Headers do
/// not record sizes (as xz without threads), which the Index does.
///
/// [`Flush::Sync`] makes the data so far decodable: without filters by an
/// LZMA2 flush within the Block; with filters, which may hold back the last
/// bytes, by ending the Block.
#[derive(Clone, Debug)]
pub struct XZCompressor {
    config: XZConfig,
    lzma2: LZMA2Compressor,
    chain: FilterChain<XZFilterCoder>,
    checksum: XZChecksum,
    index: XZIndex,
    pending: PendingOutput,
    scratch: Vec<u8>,
    /// The open Block: its header size and its sizes so far.
    block_open: bool,
    header_size: u64,
    compressed: u64,
    uncompressed: u64,
    /// Whether nothing was taken since the last sync flush.
    synced: bool,
    started: bool,
    finished: bool,
}

impl XZCompressor {
    /// The most input taken at once.
    pub const PIECE: usize = 1 << 16;

    /// A compressor of the parameters `config`; fails with `InvalidParameter`
    /// for more than 3 filters, LZMA2 among them, invalid filter or LZMA
    /// parameters, or a Block size of 0.
    pub fn new(config: XZConfig) -> Result<XZCompressor, CompressionError> {
        let filters_valid = config.filters.len() < XZFormat::MAXIMUM_FILTERS
            && config.filters.iter().all(|filter| !matches!(filter, XZFilter::LZMA2 { .. }) && filter.check().is_ok());
        if !filters_valid || config.block_size == Some(0) {
            return Err(CompressionError::InvalidParameter);
        }
        let lzma2 = LZMA2Compressor::new(config.lzma)?;
        let chain = FilterChain::new(config.filters.iter().filter_map(XZFilter::coder).collect());
        Ok(XZCompressor {
            checksum: XZChecksum::new(config.check),
            config,
            lzma2,
            chain,
            index: XZIndex::new(),
            pending: PendingOutput::new(),
            scratch: vec![0; 1 << 12],
            block_open: false,
            header_size: 0,
            compressed: 0,
            uncompressed: 0,
            synced: true,
            started: false,
            finished: false,
        })
    }

    pub fn config(&self) -> &XZConfig {
        &self.config
    }

    /// The filter chain of the Blocks: the configured filters, then LZMA2.
    pub fn filters(&self) -> Vec<XZFilter> {
        let mut filters = self.config.filters.clone();
        filters.push(XZFilter::LZMA2 { dictionary_size: self.lzma2.dictionary_size() as u64 });
        filters
    }

    /// The Stream Header.
    pub fn stream_header(&self) -> Vec<u8> {
        let flags = [0, self.config.check.id()];
        let mut header = XZFormat::HEADER_MAGIC.to_vec();
        header.extend(flags);
        header.extend(XZFormat::crc32(&flags).to_le_bytes());
        header
    }

    /// The Index and the Stream Footer.
    pub fn stream_end(&self) -> Vec<u8> {
        let mut end = self.index.encode();
        let backward = (end.len() / 4 - 1) as u32;
        let mut fields = backward.to_le_bytes().to_vec();
        fields.extend([0, self.config.check.id()]);
        end.extend(XZFormat::crc32(&fields).to_le_bytes());
        end.extend(fields);
        end.extend(XZFormat::FOOTER_MAGIC);
        end
    }

    /// Starts a Block: its header, a fresh LZMA2 stream, filters and Check.
    pub fn open_block(&mut self) {
        let header = XZBlockHeader { compressed_size: None, uncompressed_size: None, filters: self.filters() }.encode();
        self.header_size = header.len() as u64;
        self.pending.extend(&header);
        self.lzma2.reset();
        self.chain.reset();
        self.checksum = XZChecksum::new(self.config.check);
        (self.compressed, self.uncompressed) = (0, 0);
        self.block_open = true;
    }

    /// Gives `data` to the LZMA2 compressor with `flush`, collecting its output.
    pub fn feed(&mut self, data: &[u8], flush: Flush) -> Result<(), CompressionError> {
        let mut data = data;
        loop {
            let progress = self.lzma2.compress(data, &mut self.scratch, flush)?;
            self.pending.extend(&self.scratch[..progress.produced]);
            self.compressed += progress.produced as u64;
            data = &data[progress.consumed..];
            if progress.finished
                || (flush != Flush::Finish && data.is_empty() && progress.produced < self.scratch.len())
            {
                return Ok(());
            }
        }
    }

    /// Passes the bytes the filters converted to LZMA2.
    pub fn feed_ready(&mut self) -> Result<(), CompressionError> {
        let chain = core::mem::replace(&mut self.chain, FilterChain::new(Vec::new()));
        let result = self.feed(chain.ready(), Flush::None);
        self.chain = chain;
        let ready = self.chain.ready().len();
        self.chain.consume(ready);
        result
    }

    /// Ends the open Block: the rest of its data, the end of its LZMA2
    /// stream, its padding and Check; records it.
    pub fn close_block(&mut self) -> Result<(), CompressionError> {
        self.chain.encode(true);
        self.feed_ready()?;
        self.feed(&[], Flush::Finish)?;
        let padding = (4 - (self.compressed % 4) as usize) % 4;
        self.pending.extend(&[0; 3][..padding]);
        let (check, size) = self.checksum.finish();
        self.pending.extend(&check[..size]);
        let unpadded = self.header_size + self.compressed + size as u64;
        self.index.records.push((unpadded, self.uncompressed));
        self.block_open = false;
        Ok(())
    }
}

impl Default for XZCompressor {
    fn default() -> XZCompressor {
        XZCompressor::new(XZConfig::default()).expect("the default parameters are valid")
    }
}

impl Compressor for XZCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if !self.started {
            let header = self.stream_header();
            self.pending.extend(&header);
            self.started = true;
        }
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            if consumed < input.len() {
                if !self.block_open {
                    self.open_block();
                }
                let room = self.config.block_size.map_or(u64::MAX, |size| size - self.uncompressed);
                let take = (input.len() - consumed).min(XZCompressor::PIECE).min(room.min(usize::MAX as u64) as usize);
                let piece = &input[consumed..consumed + take];
                self.checksum.update(piece);
                self.uncompressed += take as u64;
                consumed += take;
                self.synced = false;
                if self.chain.filters().is_empty() {
                    self.feed(piece, Flush::None)?;
                } else {
                    self.chain.extend(piece);
                    self.chain.encode(false);
                    self.feed_ready()?;
                }
                if self.config.block_size == Some(self.uncompressed) {
                    self.close_block()?;
                }
                continue;
            }
            match flush {
                Flush::None => break,
                Flush::Sync => {
                    if self.synced {
                        break;
                    }
                    if self.block_open {
                        if self.chain.filters().is_empty() {
                            self.feed(&[], Flush::Sync)?;
                        } else {
                            self.close_block()?;
                        }
                    }
                    self.synced = true;
                }
                Flush::Finish => {
                    if self.block_open {
                        self.close_block()?;
                    }
                    let end = self.stream_end();
                    self.pending.extend(&end);
                    self.finished = true;
                }
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.lzma2.reset();
        self.chain.reset();
        self.checksum = XZChecksum::new(self.config.check);
        self.index = XZIndex::new();
        self.pending.clear();
        self.block_open = false;
        (self.header_size, self.compressed, self.uncompressed) = (0, 0, 0);
        self.synced = true;
        self.started = false;
        self.finished = false;
    }
}
