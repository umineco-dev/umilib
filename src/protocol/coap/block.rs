use alloc::vec::Vec;

use super::{CoAPBlock, CoAPError, CoAPMessage, CoAPOptionNumber, CoAPOptions};

/// The block-wise transfer of a body (RFC 7959): what a server gives of a
/// body block by block, and what a receiver puts together.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoAPBlockwise {
    /// The body received so far: the next block is at its end, of any size
    /// (a receiver may ask for smaller blocks as it goes, §2.4).
    pub body: Vec<u8>,
    /// The ETag of the first block, which every block must have (§2.4).
    pub etag: Option<Vec<u8>>,
    /// The largest body taken.
    pub maximum: usize,
}

impl CoAPBlockwise {
    pub fn new(maximum: usize) -> CoAPBlockwise {
        CoAPBlockwise { body: Vec::new(), etag: None, maximum }
    }

    /// Sets the block of `body` that `request` asks for in its Block2 (its
    /// number, at most the size `size`), or the first, as `response`'s
    /// payload with its Block2 option, if the body is larger than a block
    /// or a block was asked for (§2.4); and Size2 if the request has it
    /// (§4). Fails for a block past the end, which is 4.02 (§2.4).
    pub fn respond(
        request: &CoAPMessage,
        body: &[u8],
        size: usize,
        response: &mut CoAPMessage,
    ) -> Result<(), CoAPError> {
        let asked = request.options.block(CoAPOptionNumber::BLOCK2).transpose()?;
        let size = asked.map_or(size, |block| block.size().min(size));
        let first = CoAPBlock::new(0, false, size)?;
        if asked.is_none() && body.len() <= size {
            response.payload = body.to_vec();
            return Ok(());
        }
        // A smaller size than asked keeps the same offset (§2.4).
        let number = asked.map_or(0, |block| (block.offset() / first.size()) as u32);
        let block = CoAPBlock { number, ..first };
        let (payload, more) = block.slice(body).ok_or(CoAPError::Option("a block past the end of the body"))?;
        response.payload = payload.to_vec();
        response.options.set(CoAPOptionNumber::BLOCK2, CoAPBlock { more, ..block }.encode());
        if request.options.contains(CoAPOptionNumber::SIZE2) {
            response.options.set_uint(CoAPOptionNumber::SIZE2, body.len() as u32);
        }
        Ok(())
    }

    /// Takes the block `block` of `payload`, of the message's ETag: in
    /// order (at the end of the body so far), each but the last of the full
    /// size and of the same ETag (§2.4, §2.5). Whether the body is whole.
    pub fn receive(&mut self, block: CoAPBlock, payload: &[u8], etag: Option<&[u8]>) -> Result<bool, CoAPError> {
        if block.offset() != self.body.len() {
            return Err(CoAPError::State);
        }
        if block.more && payload.len() != block.size() {
            return Err(CoAPError::Malformed("a block not of its size before the last"));
        }
        if self.body.is_empty() {
            self.etag = etag.map(<[u8]>::to_vec);
        } else if self.etag.as_deref() != etag {
            return Err(CoAPError::State);
        }
        if self.body.len() + payload.len() > self.maximum {
            return Err(CoAPError::TooLarge);
        }
        self.body.extend_from_slice(payload);
        Ok(!block.more)
    }

    /// The options of the request for the next block, of `size`: `options`
    /// with Block2 of the number at the end of the body so far (§2.4); fails
    /// for a size that the body so far is not a multiple of, as a larger one
    /// than the blocks received may be.
    pub fn next_request(&self, options: &CoAPOptions, size: usize) -> Result<CoAPOptions, CoAPError> {
        let first = CoAPBlock::new(0, false, size)?;
        if !self.body.len().is_multiple_of(first.size()) {
            return Err(CoAPError::Option("a block size the body so far is not a multiple of"));
        }
        let number = u32::try_from(self.body.len() / first.size()).map_err(|_| CoAPError::TooLarge)?;
        let mut options = options.clone();
        options.set(CoAPOptionNumber::BLOCK2, CoAPBlock::new(number, false, size)?.encode());
        options.remove(CoAPOptionNumber::OBSERVE);
        Ok(options)
    }
}
