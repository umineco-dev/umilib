use alloc::collections::{BTreeMap, VecDeque};

use super::{
    QUICError, QUICErrorCode, QUICEvent, QUICFrameType, QUICReceiveBuffer, QUICReceiveCredit, QUICRole, QUICSendBuffer,
    QUICSendCredit, QUICStreamID, QUICTransportParameters,
};

/// The states of a stream's sending half (RFC 9000 §3.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum QUICSendState {
    #[default]
    Ready,
    Send,
    DataSent,
    DataReceived,
    ResetSent,
    ResetReceived,
}

/// The states of a stream's receiving half (RFC 9000 §3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum QUICReceiveState {
    #[default]
    Receive,
    SizeKnown,
    DataReceived,
    DataRead,
    ResetReceived,
    ResetRead,
}

/// The sending half of a stream: its data, its flow control credit, and a
/// reset if one was asked for.
#[derive(Clone, Debug, Default)]
pub struct QUICSendStream {
    pub state: QUICSendState,
    pub buffer: QUICSendBuffer,
    pub credit: QUICSendCredit,
    /// The error of RESET_STREAM, once this end resets the stream.
    pub reset: Option<u64>,
    /// Whether RESET_STREAM must be sent (again).
    pub reset_pending: bool,
    /// Whether STREAM_DATA_BLOCKED must be sent.
    pub blocked_pending: bool,
}

impl QUICSendStream {
    pub fn new(credit: u64) -> QUICSendStream {
        QUICSendStream { credit: QUICSendCredit::new(credit), ..QUICSendStream::default() }
    }

    /// Whether the half is done: all data acknowledged, or the reset (RFC 9000 §3.1).
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, QUICSendState::DataReceived | QUICSendState::ResetReceived)
    }

    /// Resets the half with `error` (RFC 9000 §3.1): what is held is dropped,
    /// and RESET_STREAM carries the final size. Does nothing once terminal
    /// or reset already.
    pub fn reset(&mut self, error: u64) {
        if self.reset.is_some() || self.is_terminal() {
            return;
        }
        self.reset = Some(error);
        self.reset_pending = true;
        self.state = QUICSendState::ResetSent;
        self.buffer.discard();
    }

    /// The final size a RESET_STREAM carries: the data sent so far (RFC 9000 §4.5).
    pub fn final_size(&self) -> u64 {
        self.buffer.sent
    }
}

/// The receiving half of a stream: its data, the credit given for it, and
/// what the peer or this end asked to stop.
#[derive(Clone, Debug, Default)]
pub struct QUICReceiveStream {
    pub state: QUICReceiveState,
    pub buffer: QUICReceiveBuffer,
    pub credit: QUICReceiveCredit,
    /// The peer's error of RESET_STREAM.
    pub reset: Option<u64>,
    /// The error of STOP_SENDING, once this end asks the peer to stop.
    pub stop: Option<u64>,
    pub stop_pending: bool,
    /// Whether MAX_STREAM_DATA must be sent with the credit's limit.
    pub limit_pending: bool,
}

impl QUICReceiveStream {
    pub fn new(window: u64) -> QUICReceiveStream {
        QUICReceiveStream { credit: QUICReceiveCredit::new(window), ..QUICReceiveStream::default() }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, QUICReceiveState::DataRead | QUICReceiveState::ResetRead)
    }

    /// STREAM data at `offset` (RFC 9000 §3.2, §4.5): counted against the
    /// stream's credit for the offsets past the highest received, which
    /// returns how many. Data after a reset or once all was received is
    /// checked against the final size and dropped.
    pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<u64, QUICError> {
        let before = self.buffer.highest;
        if matches!(self.state, QUICReceiveState::ResetReceived | QUICReceiveState::ResetRead) {
            let end = offset + data.len() as u64;
            let size = self.buffer.final_size.unwrap_or(0);
            if end > size || (fin && end != size) {
                return Err(QUICError::transport(QUICErrorCode::FINAL_SIZE_ERROR, "data past a reset's final size"));
            }
            return Ok(0);
        }
        self.buffer.insert(offset, data, fin)?;
        let new = self.buffer.highest - before;
        self.credit.receive(new)?;
        if self.buffer.final_size.is_some() && self.state == QUICReceiveState::Receive {
            self.state = QUICReceiveState::SizeKnown;
        }
        if self.state == QUICReceiveState::SizeKnown
            && self.buffer.final_size.is_some_and(|size| self.buffer.read + self.buffer.readable() as u64 == size)
        {
            self.state = QUICReceiveState::DataReceived;
        }
        Ok(new)
    }

    /// RESET_STREAM with `final_size` (RFC 9000 §3.2, §4.5): the size must
    /// agree with what was received; returns the new bytes it counts for
    /// flow control, or `None` if the reset changes nothing: all data was
    /// received already, or the stream was reset before.
    pub fn receive_reset(&mut self, error: u64, final_size: u64) -> Result<Option<u64>, QUICError> {
        let mismatch = QUICError::transport(QUICErrorCode::FINAL_SIZE_ERROR, "reset with another final size");
        match self.buffer.final_size {
            Some(size) if size != final_size => return Err(mismatch),
            None if final_size < self.buffer.highest => return Err(mismatch),
            _ => {}
        }
        if matches!(self.state, QUICReceiveState::DataReceived | QUICReceiveState::DataRead) || self.reset.is_some() {
            return Ok(None);
        }
        let new = final_size - self.buffer.highest;
        self.credit.receive(new)?;
        self.buffer.highest = final_size;
        self.buffer.final_size = Some(final_size);
        self.buffer.discard();
        self.reset = Some(error);
        self.state = QUICReceiveState::ResetReceived;
        Ok(Some(new))
    }

    /// Drops what arrived for a reader that stopped reading (RFC 9000 §3.5):
    /// the bytes received count as read, and the half ends once its final
    /// size is known. Returns the bytes newly counted as read.
    pub fn absorb(&mut self) -> u64 {
        let taken = self.buffer.highest - self.buffer.read;
        self.buffer.read = self.buffer.highest;
        self.buffer.discard();
        self.credit.consume(taken);
        if self.buffer.final_size.is_some() {
            self.state = if self.reset.is_some() { QUICReceiveState::ResetRead } else { QUICReceiveState::DataRead };
        }
        taken
    }
}

/// A stream: the halves its direction gives it (RFC 9000 §2.1).
#[derive(Clone, Debug)]
pub struct QUICStream {
    pub id: QUICStreamID,
    pub send: Option<QUICSendStream>,
    pub receive: Option<QUICReceiveStream>,
}

impl QUICStream {
    /// Whether both halves are done, so that the stream can be forgotten.
    pub fn is_closed(&self) -> bool {
        self.send.as_ref().is_none_or(QUICSendStream::is_terminal)
            && self.receive.as_ref().is_none_or(QUICReceiveStream::is_terminal)
    }
}

/// The flow control windows of streams that one end's transport
/// parameters give (RFC 9000 §18.2), by who opens the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct QUICStreamWindows {
    pub bidi_local: u64,
    pub bidi_remote: u64,
    pub uni: u64,
}

impl QUICStreamWindows {
    pub fn of(parameters: &QUICTransportParameters) -> QUICStreamWindows {
        QUICStreamWindows {
            bidi_local: parameters.initial_max_stream_data_bidi_local,
            bidi_remote: parameters.initial_max_stream_data_bidi_remote,
            uni: parameters.initial_max_stream_data_uni,
        }
    }
}

/// The streams of a connection (RFC 9000 §2–§4): those open, the limits on
/// opening more each way, and the windows of new ones.
#[derive(Clone, Debug)]
pub struct QUICStreams {
    pub role: QUICRole,
    pub streams: BTreeMap<QUICStreamID, QUICStream>,
    /// The streams this end opened of each kind (bidirectional first), and
    /// how many the peer allows (its MAX_STREAMS).
    pub opened: [u64; 2],
    pub peer_limit: [u64; 2],
    /// The streams the peer opened of each kind, how many it may (this
    /// end's MAX_STREAMS), how many of them closed, and the count kept open.
    pub peer_opened: [u64; 2],
    pub limit: [u64; 2],
    pub peer_closed: [u64; 2],
    pub window: [u64; 2],
    /// Whether MAX_STREAMS or STREAMS_BLOCKED of a kind must be sent.
    pub limit_pending: [bool; 2],
    pub blocked_pending: [bool; 2],
    /// The windows this end gives and the peer gives.
    pub local_windows: QUICStreamWindows,
    pub peer_windows: QUICStreamWindows,
    /// The streams with data or frames to send, in turn.
    pub ready: VecDeque<QUICStreamID>,
}

impl QUICStreams {
    pub fn new(role: QUICRole, local: &QUICTransportParameters) -> QUICStreams {
        let window = [local.initial_max_streams_bidi, local.initial_max_streams_uni];
        QUICStreams {
            role,
            streams: BTreeMap::new(),
            opened: [0; 2],
            peer_limit: [0; 2],
            peer_opened: [0; 2],
            limit: window,
            peer_closed: [0; 2],
            window,
            limit_pending: [false; 2],
            blocked_pending: [false; 2],
            local_windows: QUICStreamWindows::of(local),
            peer_windows: QUICStreamWindows::default(),
            ready: VecDeque::new(),
        }
    }

    pub const fn kind(bidirectional: bool) -> usize {
        if bidirectional { 0 } else { 1 }
    }

    /// The peer's transport parameters: its limits on streams this end
    /// opens, and the windows of new streams (RFC 9000 §4.6, §7.4).
    pub fn apply(&mut self, peer: &QUICTransportParameters) {
        self.peer_limit[0] = self.peer_limit[0].max(peer.initial_max_streams_bidi);
        self.peer_limit[1] = self.peer_limit[1].max(peer.initial_max_streams_uni);
        self.peer_windows = QUICStreamWindows::of(peer);
        // Streams opened before (in 0-RTT) get the windows now known.
        for stream in self.streams.values_mut() {
            let credit = QUICStreams::send_window(self.role, &self.peer_windows, stream.id);
            if let Some(send) = &mut stream.send {
                send.credit.raise(credit);
            }
        }
    }

    /// The credit the peer gives a stream to receive on, by its windows.
    pub fn send_window(role: QUICRole, peer: &QUICStreamWindows, id: QUICStreamID) -> u64 {
        match (id.is_bidirectional(), id.initiator() == role) {
            (true, true) => peer.bidi_remote,
            (true, false) => peer.bidi_local,
            (false, _) => peer.uni,
        }
    }

    /// The window this end gives a stream.
    pub fn receive_window(role: QUICRole, local: &QUICStreamWindows, id: QUICStreamID) -> u64 {
        match (id.is_bidirectional(), id.initiator() == role) {
            (true, true) => local.bidi_local,
            (true, false) => local.bidi_remote,
            (false, _) => local.uni,
        }
    }

    /// A new stream of `id`, with the halves its direction gives it.
    pub fn create(&self, id: QUICStreamID) -> QUICStream {
        let local = id.initiator() == self.role;
        let sends = id.is_bidirectional() || local;
        let receives = id.is_bidirectional() || !local;
        QUICStream {
            id,
            send: sends.then(|| QUICSendStream::new(QUICStreams::send_window(self.role, &self.peer_windows, id))),
            receive: receives
                .then(|| QUICReceiveStream::new(QUICStreams::receive_window(self.role, &self.local_windows, id))),
        }
    }

    /// Opens a stream; fails with [`QUICError::State`] at the peer's limit,
    /// after queueing STREAMS_BLOCKED (RFC 9000 §4.6).
    pub fn open(&mut self, bidirectional: bool) -> Result<QUICStreamID, QUICError> {
        let kind = QUICStreams::kind(bidirectional);
        if self.opened[kind] >= self.peer_limit[kind] {
            self.blocked_pending[kind] = true;
            return Err(QUICError::State);
        }
        let id = QUICStreamID::new(self.role, bidirectional, self.opened[kind]);
        self.opened[kind] += 1;
        let stream = self.create(id);
        self.streams.insert(id, stream);
        Ok(id)
    }

    /// The stream a frame of `frame_type` names (RFC 9000 §2.1, §3, §4.6):
    /// one of the peer's is opened with those before it, and fails with
    /// STREAM_LIMIT_ERROR past this end's limit; one of this end's that was
    /// never opened fails with STREAM_STATE_ERROR, as does a frame for a
    /// half the stream does not have (`sending` says whether the frame is
    /// about the peer's sending half). `None` for a stream closed and forgotten.
    pub fn frame(
        &mut self,
        id: QUICStreamID,
        frame_type: QUICFrameType,
        sending: bool,
        events: &mut VecDeque<QUICEvent>,
    ) -> Result<Option<&mut QUICStream>, QUICError> {
        if id.0 > QUICStreamID::MAXIMUM {
            return Err(QUICError::frame_encoding(frame_type, "stream ID past 2^62 - 1"));
        }
        let state = QUICError::transport(QUICErrorCode::STREAM_STATE_ERROR, "a frame for a half that is not there")
            .in_frame(frame_type);
        let local = id.initiator() == self.role;
        // The peer sends on its own streams and bidirectional ones; it receives on bidirectional ones and this end's.
        let half_exists = if sending { id.is_bidirectional() || !local } else { id.is_bidirectional() || local };
        if !half_exists {
            return Err(state);
        }
        let kind = QUICStreams::kind(id.is_bidirectional());
        if local {
            if id.index() >= self.opened[kind] {
                return Err(state);
            }
        } else if id.index() >= self.peer_opened[kind] {
            if id.index() >= self.limit[kind] {
                return Err(QUICError::transport(QUICErrorCode::STREAM_LIMIT_ERROR, "a stream past the limit")
                    .in_frame(frame_type));
            }
            for index in self.peer_opened[kind]..=id.index() {
                let opened = QUICStreamID::new(self.role.peer(), id.is_bidirectional(), index);
                let stream = self.create(opened);
                self.streams.insert(opened, stream);
                events.push_back(QUICEvent::StreamOpened { stream: opened });
            }
            self.peer_opened[kind] = id.index() + 1;
        }
        Ok(self.streams.get_mut(&id))
    }

    /// Forgets the streams whose halves are done; for the peer's, more may
    /// be opened (RFC 9000 §4.6): MAX_STREAMS is due once half the window closed.
    pub fn collect(&mut self) {
        let closed: alloc::vec::Vec<QUICStreamID> =
            self.streams.values().filter(|stream| stream.is_closed()).map(|stream| stream.id).collect();
        for id in closed {
            self.streams.remove(&id);
            if id.initiator() != self.role {
                let kind = QUICStreams::kind(id.is_bidirectional());
                self.peer_closed[kind] += 1;
                let next = (self.peer_closed[kind] + self.window[kind]).min(QUICStreamID::MAXIMUM_COUNT);
                if next >= self.limit[kind] + self.window[kind] / 2 && next > self.limit[kind] {
                    self.limit[kind] = next;
                    self.limit_pending[kind] = true;
                }
            }
        }
    }

    /// A MAX_STREAMS of the peer: only an increase counts (RFC 9000 §19.11).
    pub fn raise_limit(&mut self, bidirectional: bool, maximum: u64, events: &mut VecDeque<QUICEvent>) {
        let kind = QUICStreams::kind(bidirectional);
        if maximum > self.peer_limit[kind] {
            let was_blocked = self.opened[kind] >= self.peer_limit[kind];
            self.peer_limit[kind] = maximum;
            if was_blocked {
                events.push_back(QUICEvent::StreamsAvailable { bidirectional });
            }
        }
    }

    /// Queues `id` to send, once.
    pub fn schedule(&mut self, id: QUICStreamID) {
        if !self.ready.contains(&id) {
            self.ready.push_back(id);
        }
    }
}
