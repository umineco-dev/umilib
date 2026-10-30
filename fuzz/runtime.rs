//! Fuzz targets of `umilib::runtime`.

use std::collections::{BTreeMap, VecDeque};

use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};
use umilib::runtime::{Channel, ChannelError, Instant, TimerQueue};

/// Runs operations read from the input on a bounded channel and on a timer
/// queue, checking each against a plain model.
pub const OPERATIONS: FuzzFunction<fn(&[u8])> = FuzzFunction::new("runtime-operations", |data| {
    let capacity = 1 + data.first().map_or(0, |byte| *byte as usize % 8);
    let (sender, mut receiver) = Channel::bounded::<u8>(capacity);
    let mut senders = vec![sender];
    let mut model: VecDeque<u8> = VecDeque::new();
    let mut closed = false;
    let mut queue = TimerQueue::new();
    let mut timers: BTreeMap<u64, u64> = BTreeMap::new();
    for pair in data.chunks(2) {
        let (operation, value) = (pair[0], pair.get(1).copied().unwrap_or(0));
        match operation % 8 {
            0 if !senders.is_empty() => {
                let result = senders[0].try_send(value);
                if closed {
                    assert_eq!(result.map_err(|error| error.error), Err(ChannelError::Closed));
                } else if model.len() == capacity {
                    assert_eq!(result.map_err(|error| error.error), Err(ChannelError::Full));
                } else {
                    assert_eq!(result, Ok(()));
                    model.push_back(value);
                }
            }
            1 => {
                let expected = match model.pop_front() {
                    Some(value) => Ok(value),
                    None if senders.is_empty() => Err(ChannelError::Closed),
                    None => Err(ChannelError::Empty),
                };
                assert_eq!(receiver.try_receive(), expected);
            }
            2 if !senders.is_empty() && senders.len() < 8 => senders.push(senders[0].clone()),
            3 => {
                senders.pop();
            }
            4 => {
                receiver.close();
                closed = true;
            }
            5 => {
                let deadline = value as u64;
                let key = queue.insert(Instant::from_nanos(deadline), None);
                timers.insert(key.value(), deadline);
            }
            6 => {
                let key = timers.keys().nth(value as usize % timers.len().max(1)).copied();
                if let Some(key) = key {
                    timers.remove(&key);
                    assert!(queue.remove(umilib::runtime::TimerKey::from_value(key)));
                }
            }
            _ => {
                let now = value as u64;
                let expired = timers.values().filter(|deadline| **deadline <= now).count();
                timers.retain(|_, deadline| *deadline > now);
                assert_eq!(queue.fire(Instant::from_nanos(now)), expired);
                assert_eq!(queue.next_deadline().map(Instant::as_nanos), timers.values().min().copied());
            }
        }
        assert_eq!(receiver.len(), model.len());
        assert_eq!(queue.len(), timers.len());
    }
});

pub const TARGETS: &[&dyn FuzzTarget] = &[&OPERATIONS];
